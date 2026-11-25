#!/usr/bin/env python3
"""Collector `host`: host/endpoint hardening, READ-ONLY, through an exec adapter + an OS profile.

Instance config `hosts: [{name, exec: <exec adapter cfg>|null, profile: linux|macos|windows|termux|busybox, gap?,
probe_timeout?, slow_probe_timeout?, script_timeout?}]`.
A profile is a script printing key=value lines; the checks below only read those keys, so new OSes are
new profiles, not new checks. Password prompts are impossible (exec adapters are non-interactive).

Every probe in a profile has its own time limit (profiles/probe.sh, probe.ps1): a probe that does not finish prints
`probe.timeout=<key>` instead of a value. The checks that read that key become a NARROW coverage gap
(`host:<name>/<part>`, carrying the checks it stands for) - "could not check", never a pass - while every other check
reports normally. The whole-script limit stays as a backstop; when it fires, the lines printed so far are still used
and the probes that never ran become gaps the same way.
"""
import fnmatch
import os
import re
import sys
import time

HERE = os.path.dirname(__file__)
ROOT = os.path.join(HERE, "..", "..")
sys.path[:0] = [os.path.join(ROOT, "sdk"), ROOT]
import spsdk  # noqa: E402
from adapters import exec as ex  # noqa: E402

VERSION = open(os.path.join(HERE, "VERSION")).read().strip()
DB_PORTS = {5432, 55432, 3306, 6379, 27017, 9200, 2379}
PROBE_TIMEOUT, SLOW_PROBE_TIMEOUT = 20, 90   # seconds per probe; slow = network-dependent (update servers), run last
END = "probe.end"                            # printed after the profile: its absence = the script did not finish

# The checks each probe key feeds: (part, key patterns, check patterns). A key that could not be read makes
# `host:<name>/<part>` a gap for exactly these checks; keys outside this table feed no check (informational only).
PARTS = [
    ("ssh", ["sshd", "sshd.*"], ["ssh.password_auth_enabled", "ssh.root_login_password", "ssh.x11_forwarding"]),
    ("package-updates", ["pkg.upgradable", "pkg.security_upgradable"], ["patch.security_pending", "patch.pending"]),
    ("package-metadata", ["pkg.cache_mtime"], ["patch.metadata_stale"]),
    ("reboot", ["reboot_required"], ["patch.reboot_required"]),
    ("auto-updates", ["pkg.auto_updates"], ["patch.auto_updates_off"]),
    ("firewall", ["fw.ufw", "fw.nft_input_policy", "fw.iptables_input_policy"], ["fw.host_firewall_off"]),
    ("disk-encryption", ["disk.filevault"], ["macos.disk_filevault_off"]),
    ("app-firewall", ["fw.app_firewall"], ["macos.fw_app_firewall_off"]),
    ("firewall-stealth", ["fw.stealth"], ["macos.fw_stealth_off"]),
    ("sip", ["sip"], ["macos.sip_off"]),
    ("gatekeeper", ["gatekeeper"], ["macos.gatekeeper_off"]),
    ("os-updates", ["pkg.os_updates_pending"], ["patch.os_updates_pending"]),
    ("brew", ["pkg.brew_outdated"], ["patch.brew_outdated"]),
    ("windows-firewall", ["fw.profile", "fw.profile_*"], ["win.fw_profile_*"]),
    ("antivirus", ["av", "av.*"], ["win.av_realtime_off", "win.av_signatures_stale"]),
    ("disk-encryption", ["disk.bitlocker"], ["win.disk_unencrypted"]),
    ("smb1", ["smb.v1"], ["win.smb1_enabled"]),
    ("windows-updates", ["pkg.last_hotfix"], ["patch.windows_stale"]),
    ("android-patch", ["os.security_patch"], ["patch.android_security_patch_old"]),
    ("process-arguments", ["proc.secret_in_argv_suspects"], ["secret.in_process_argv"]),
    ("telnet", ["telnetd"], ["telnet.daemon_running"]),
    ("listeners", ["listen"], ["listen.db_wildcard.*"]),
]


def limits(h):
    t = int(h.get("probe_timeout", PROBE_TIMEOUT))
    slow = int(h.get("slow_probe_timeout", SLOW_PROBE_TIMEOUT))
    return t, slow, int(h.get("script_timeout", max(300, 2 * slow + 120)))


def script_for(h):
    """The profile with its probe helper in front, the limits from the instance config and the end marker."""
    prof = h["profile"]
    win = prof == "windows"
    body = open(os.path.join(HERE, "profiles", prof + (".ps1" if win else ".sh"))).read()
    helper = open(os.path.join(HERE, "profiles", "probe" + (".ps1" if win else ".sh"))).read()
    t, slow, _ = limits(h)
    if win:
        return f"$SpProbeTimeout = {t}\n$SpProbeSlowTimeout = {slow}\n{helper}\n{body}\n'{END}=1'\n"
    return f"SP_PROBE_TIMEOUT={t}\nSP_PROBE_SLOW_TIMEOUT={slow}\n{helper}\n{body}\necho {END}=1\n"


def planned(script):
    """Probe keys the script would print, in order (to tell which probes a stopped script never reached)."""
    return re.findall(r"^\s*(?:sp_probe|sp_lines|Probe)\s+([A-Za-z0-9_.-]+)\s", script, re.M)


def collect(h):
    script = script_for(h)
    e = ex.executor(h["exec"])
    _, _, total = limits(h)
    if h["profile"] == "windows":   # through stdin: a script of any length (cmd.exe caps command lines at 8191)
        return (*ex.powershell(e, script, timeout=total, partial=True), script)
    return (*e.run(["sh", "-s"], stdin=script, timeout=total, partial=True), script)


def parse(out):
    """-> kv, listen lines, timed-out probe keys."""
    kv, listen, timeouts = {}, [], []
    for line in out.splitlines():
        line = line.strip()
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        if k == "listen":
            listen.append(v)
        elif k == "probe.timeout":
            timeouts.append(v.strip())
        else:
            kv[k] = v.strip()
    return kv, listen, timeouts


def unread(kv, listen, timeouts, script, rc):
    """{probe key: reason} for every probe whose value is unknown: it timed out, or the whole script was stopped
    before reaching it."""
    miss = {k: "did not finish within its time limit" for k in timeouts}
    if END not in kv:
        seen = set(kv) | ({"listen"} if listen else set())
        for k in planned(script):
            if k not in miss and not any(s == k or s.startswith(k + ".") or s.startswith(k + "_") for s in seen):
                miss[k] = f"not reached: the script was stopped (rc={rc})"
    return miss


def narrow_gaps(miss):
    """[(part, reason, checks)] for the parts whose checks read a key in `miss`."""
    out = {}
    for k, why in miss.items():
        for part, keys, chks in PARTS:
            if any(fnmatch.fnmatchcase(k, p) for p in keys):
                g = out.setdefault(part, [[], set()])
                g[0].append(f"{k}: {why}")
                g[1].update(chks)
    return [(part, "; ".join(w), sorted(c)) for part, (w, c) in sorted(out.items())]


def num(v, default=0):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return default


def checks(c, name, kv, listen, ev, skip_metric=False):
    a = f"host:{name}"
    F = c.finding
    pa = kv.get("sshd.passwordauthentication", "")
    if pa.startswith("yes"):
        F("identity", a, "ssh.password_auth_enabled", "SSH password authentication is enabled", "high", ev,
          "PasswordAuthentication no (keys only)")
    if kv.get("sshd.permitrootlogin") == "yes":
        F("identity", a, "ssh.root_login_password", "SSH root login with password allowed", "high", ev,
          "PermitRootLogin prohibit-password/no")
    if kv.get("sshd.x11forwarding") == "yes":
        F("host", a, "ssh.x11_forwarding", "SSH X11Forwarding enabled", "low", ev, "X11Forwarding no")
    sec, up = num(kv.get("pkg.security_upgradable")), num(kv.get("pkg.upgradable"))
    if sec:
        F("host", a, "patch.security_pending", f"{sec} security updates pending", "medium", ev, "apply updates")
    elif up:
        F("host", a, "patch.pending", f"{up} package updates pending", "low", ev, "apply updates")
    cm = num(kv.get("pkg.cache_mtime"))
    if cm and time.time() - cm > 7 * 86400:
        F("host", a, "patch.metadata_stale", f"package metadata {int((time.time()-cm)/86400)} days old: pending-update count is unreliable",
          "low", ev, "enable periodic metadata refresh")
    if kv.get("reboot_required") == "yes":
        F("host", a, "patch.reboot_required", f"reboot required to activate installed updates (uptime {kv.get('uptime_days')}d)",
          "medium", ev, "schedule a reboot (planned maintenance)")
    if kv.get("pkg.auto_updates") == "no":
        F("host", a, "patch.auto_updates_off", "automatic security updates are off", "low", ev, "enable unattended-upgrades")
    ufw = kv.get("fw.ufw", "")
    if "fw.ufw" in kv and ufw not in ("active", "活动", "激活") and kv.get("fw.nft_input_policy") not in ("drop",) \
            and kv.get("fw.iptables_input_policy") in ("ACCEPT", "", None):
        F("network", a, "fw.host_firewall_off", "no host firewall: INPUT default-accept, ufw inactive", "medium", ev,
          "default-deny INPUT except ssh/needed ports (tailnet/LAN only)")
    if kv.get("fw.iptables_input_policy") == "ACCEPT" and kv.get("os.name", "").lower().find("xiaoqiang") >= 0:
        pass
    for k, sev, title, fix in [
            ("disk.filevault", "high", "FileVault disk encryption is off", "enable FileVault"),
            ("fw.app_firewall", "medium", "macOS application firewall is off", "enable the firewall"),
            ("sip", "high", "System Integrity Protection is off", "re-enable SIP"),
            ("gatekeeper", "high", "Gatekeeper is off", "spctl --master-enable")]:
        if kv.get(k) == "off":
            F("host", a, f"macos.{k.replace('.', '_')}_off", title, sev, ev, fix, needs_human=(k != "fw.app_firewall"))
    if kv.get("fw.stealth") == "off":
        F("host", a, "macos.fw_stealth_off", "macOS firewall stealth mode is off", "low", ev, "enable stealth mode")
    if num(kv.get("pkg.os_updates_pending")):
        F("host", a, "patch.os_updates_pending", f"{kv['pkg.os_updates_pending']} OS updates pending", "medium", ev,
          "install macOS updates", needs_human=True)
    if num(kv.get("pkg.brew_outdated")) > 20:
        F("host", a, "patch.brew_outdated", f"{kv['pkg.brew_outdated']} Homebrew packages outdated", "low", ev, "brew upgrade")
    for k, v in kv.items():
        if k.startswith("fw.profile_") and v == "off":
            F("network", a, f"win.{k.replace('.', '_')}", f"Windows firewall profile {k[11:]} is off", "high", ev, "enable it")
    if kv.get("av.realtime") == "off":
        F("host", a, "win.av_realtime_off", "Defender real-time protection off", "high", ev, "enable it")
    if num(kv.get("av.signature_age_days")) > 7:
        F("host", a, "win.av_signatures_stale", f"AV signatures {kv['av.signature_age_days']} days old", "medium", ev, "update")
    if kv.get("disk.bitlocker") in ("Off", "0"):
        F("host", a, "win.disk_unencrypted", "system drive not encrypted (BitLocker/device encryption off)", "medium", ev,
          "enable device encryption (keep the recovery key offline)", needs_human=True)
    if kv.get("smb.v1") == "True":
        F("host", a, "win.smb1_enabled", "SMBv1 server enabled", "high", ev, "disable SMB1")
    lh = kv.get("pkg.last_hotfix")
    if lh and (time.time() - time.mktime(time.strptime(lh, "%Y-%m-%d"))) > 45 * 86400:
        F("host", a, "patch.windows_stale", f"last Windows update installed {lh}", "medium", ev, "run Windows Update")
    sp = kv.get("os.security_patch")
    if sp and re.match(r"\d{4}-\d{2}-\d{2}", sp) and (time.time() - time.mktime(time.strptime(sp, "%Y-%m-%d"))) > 90 * 86400:
        F("host", a, "patch.android_security_patch_old", f"Android security patch level {sp} (> 90 days)", "medium", ev,
          "install the vendor OTA (vendor may have stopped updates)", needs_human=True)
    if num(kv.get("proc.secret_in_argv_suspects")):
        F("data-secrets", a, "secret.in_process_argv", "a process carries a credential on its command line (visible to ps)",
          "medium", ev, "pass it via a 0600 file or env instead of argv")
    if num(kv.get("telnetd")):
        F("network", a, "telnet.daemon_running", "telnetd is running", "high", ev, "disable telnetd")
    wild = [l for l in listen if re.match(r"^(0\.0\.0\.0|\*|\[::\]|::|00000000):", l)]
    for l in wild:
        port = num(l.split()[0].rsplit(":", 1)[1])
        if port in DB_PORTS:
            F("network", a, f"listen.db_wildcard.{port}", f"database-like port {port} listens on all interfaces ({l})",
              "medium", ev, "bind to localhost/bridge only")
    if not skip_metric:
        c.metric("security_host_wildcard_listeners", len(wild), "Sockets listening on all interfaces", host=name)


def main():
    inst = spsdk.load_instance()
    c = spsdk.Collector("host", VERSION)
    for h in inst.get("hosts", []):
        a = f"host:{h['name']}"
        if not spsdk.in_scope(inst, h["name"], "host"):
            continue   # instance scope: another collector covers this asset (not a gap)
        if not h.get("exec"):
            c.gap(a, h.get("gap", "no exec adapter configured"))
            continue
        rc, out, err, script = collect(h)
        kv, listen, timeouts = parse(out)
        if rc != 0 and not [k for k in kv if k != END]:
            c.gap(a, f"exec failed rc={rc}: {err.strip()[-160:]}")
            continue
        miss = unread(kv, listen, timeouts, script, rc)
        for k in miss:
            kv.pop(k, None)       # "unknown" is not a value: no check may read it
        gaps = narrow_gaps(miss)
        ev = c.raw(f"{h['name']}.json", {"profile": h["profile"], "kv": kv, "listen": listen, "rc": rc, "unread": miss})
        c.ok(a)
        n = len(c.findings)
        checks(c, h["name"], kv, listen, ev, skip_metric="listeners" in {g[0] for g in gaps})
        # a part with an unread key may still have produced a finding from its OTHER keys (e.g. ufw inactive, nft
        # unknown): that is a guess, not an observation - drop it, the narrow gap stands for the whole part
        blocked = [p for _, _, chks in gaps for p in chks]
        c.findings[n:] = [f for f in c.findings[n:] if not any(fnmatch.fnmatchcase(f["check"], p) for p in blocked)]
        for part, why, chks in gaps:
            c.gap(f"{a}/{part}", f"{h['name']} {part}: could not check ({why})"[:300], checks=chks)
            print(f"[host] {h['name']}: {part} could not be checked: {why}", file=sys.stderr)
    c.write()


if __name__ == "__main__":
    main()
