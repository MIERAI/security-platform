#!/usr/bin/env python3
"""Collector `host`: host/endpoint hardening, READ-ONLY, through an exec adapter + an OS profile.

Instance config `hosts: [{name, exec: <exec adapter cfg>|null, profile: linux|macos|windows|termux|busybox, gap?}]`.
A profile is a script printing key=value lines; the checks below only read those keys, so new OSes are
new profiles, not new checks. Password prompts are impossible (exec adapters are non-interactive).
"""
import base64
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


def collect(h):
    prof = h["profile"]
    path = os.path.join(HERE, "profiles", prof + (".ps1" if prof == "windows" else ".sh"))
    script = open(path).read()
    e = ex.executor(h["exec"])
    if prof == "windows":
        b64 = base64.b64encode(script.encode("utf-16-le")).decode()
        return e.run(["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", b64], timeout=180)
    return e.run(["sh", "-s"], stdin=script, timeout=180)


def parse(out):
    kv, listen = {}, []
    for line in out.splitlines():
        line = line.strip()
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        if k == "listen":
            listen.append(v)
        else:
            kv[k] = v.strip()
    return kv, listen


def num(v, default=0):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return default


def checks(c, name, kv, listen, ev):
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
        rc, out, err = collect(h)
        kv, listen = parse(out)
        if rc != 0 and not kv:
            c.gap(a, f"exec failed rc={rc}: {err.strip()[-160:]}")
            continue
        ev = c.raw(f"{h['name']}.json", {"profile": h["profile"], "kv": kv, "listen": listen, "rc": rc})
        c.ok(a)
        checks(c, h["name"], kv, listen, ev)
    c.write()


if __name__ == "__main__":
    main()
