#!/usr/bin/env python3
"""Collector `secrets-files`: the "files" secrets-store adapter. Where secrets live, never what they are.

Instance config `secrets_files: [{host, exec, roots, exclude?, sudo?, python?}]` (Windows targets: an exec adapter
with `shell: windows` and `python:` pointing at the target's interpreter; permissions come from ACLs). Runs remote/scan.py through the
exec adapter. Records path, kind, permissions, age, and boolean properties (encrypted / passphrase / embedded key).
Future adapters behind the same contract: Vault, AWS/GCP Secret Manager, 1Password (list metadata + rotation dates).
"""
import json
import os
import sys
import time

HERE = os.path.dirname(__file__)
ROOT = os.path.join(HERE, "..", "..")
sys.path[:0] = [os.path.join(ROOT, "sdk"), ROOT]
import spsdk  # noqa: E402
from adapters import exec as ex  # noqa: E402

VERSION = open(os.path.join(HERE, "VERSION")).read().strip()
PRIVATE_KINDS = {"private-key", "kubeconfig", "tf-state", "dotenv", "rclone-config", "age-key", "netrc", "docker-config",
                 "gh-config", "k3s-token", "secret-file"}


def main():
    inst = spsdk.load_instance()
    c = spsdk.Collector("secrets-files", VERSION)
    now = time.time()
    total_old = 0
    for t in inst.get("secrets_files", []):
        host = t["host"]
        A = f"host:{host}"
        if not spsdk.in_scope(inst, host, "secrets-files"):
            continue   # instance scope: another collector covers this asset (not a gap)
        if not t.get("exec"):
            c.gap(A, t.get("gap", "no exec adapter"))
            continue
        script = open(os.path.join(HERE, "remote", "scan.py")).read()
        conf = json.dumps({"roots": t["roots"], "exclude": t.get("exclude", []), "maxdepth": t.get("maxdepth", 5)})
        py = t.get("python", "python3")
        # write the script to stdin of `python -c` loader so the config can be an argv
        loader = "import sys;exec(sys.stdin.buffer.read().decode('utf-8'))"
        argv = (["sudo", "-n"] if t.get("sudo") else []) + [py, "-c", loader, conf]
        rc, out, err = ex.executor(t["exec"]).run(argv, stdin=script, timeout=600)
        if rc != 0 and t.get("sudo"):
            rc, out, err = ex.executor(t["exec"]).run([py, "-c", loader, conf], stdin=script, timeout=600)
            if rc == 0:
                c.gap(f"{A}/privileged-paths", "sudo -n not available; privileged paths skipped")
        if rc != 0:
            c.gap(A, f"scan failed rc={rc}: {err.strip()[-160:]}")
            continue
        res = json.loads(out.strip().splitlines()[-1])
        home = res["home"]
        items = res["items"]
        for i in items:
            i["path"] = i["path"].replace(home, "~", 1).replace("\\", "/")
        ev = c.raw(f"{host}.json", items)
        c.ok(A)
        old = 0
        for i in items:
            asset = f"secret-file:{host}:{i['path']}"
            if i["mode"] == "unknown":
                c.gap(f"{asset}/permissions", "file permissions could not be read")
                mode = 0
            else:
                mode = int(i["mode"], 8)
            age_d = int((now - i["mtime"]) / 86400)
            kind = i["kind"]
            if kind in PRIVATE_KINDS and mode & 0o077 and not (kind == "kubeconfig" and not i.get("embedded_client_key") and not i.get("token_auth")):
                sev = "high" if mode & 0o004 else "medium"
                if i.get("encrypted"):
                    sev = "low"
                c.finding("data-secrets", asset, "secret.permissions_too_open",
                          f"{kind}{' (encrypted)' if i.get('encrypted') else ''} readable by group/others (mode {i['mode']})", sev,
                          f"{ev}#{i['path']}", "chmod 600 (dirs 700)")
            if kind == "private-key" and i.get("passphrase") is False and not os.path.basename(i["path"]).startswith("ssh_host_"):
                # (an SSH server's host key never has a passphrase: the daemon must read it unattended)
                c.finding("data-secrets", asset, "secret.ssh_key_no_passphrase",
                          f"private key without passphrase ({i.get('type', i.get('format'))}, {age_d}d old)", "medium",
                          f"{ev}#{i['path']}", "add a passphrase (ssh-keygen -p) + agent, or move to a hardware/Secure-Enclave key",
                          needs_human=True)
            if kind == "kubeconfig" and i.get("embedded_client_key"):
                c.finding("data-secrets", asset, "secret.kubeconfig_embedded_client_key",
                          "kubeconfig embeds a client private key (long-lived, not revocable)", "medium",
                          f"{ev}#{i['path']}", "short-lived credentials (OIDC/exec plugin); keep admin certs offline")
            if kind == "tf-state" and not i.get("encrypted"):
                c.finding("data-secrets", asset, "secret.tf_state_plaintext", "plaintext Terraform/OpenTofu state (may contain secrets)",
                          "medium", f"{ev}#{i['path']}", "enable state encryption or delete stale state files")
            if kind == "rclone-config" and not i.get("encrypted"):
                c.finding("data-secrets", asset, "secret.rclone_config_plaintext",
                          "rclone config not encrypted (remote credentials only obscured)", "medium",
                          f"{ev}#{i['path']}", "rclone config encryption, or keep 600 on a trusted host")
            if kind == "docker-config" and i.get("inline_auth"):
                c.finding("data-secrets", asset, "secret.docker_inline_auth", "registry credentials stored inline in docker config",
                          "medium", f"{ev}#{i['path']}", "use a credential helper (credsStore)")
            if kind == "gh-config" and i.get("token_in_file"):
                c.finding("data-secrets", asset, "secret.gh_token_in_file", "GitHub token stored in plain file", "medium",
                          f"{ev}#{i['path']}", "gh auth login with keyring storage")
            if kind == "notes" and i.get("credential_like_lines"):
                c.finding("ai-agents", asset, "secret.credential_in_notes",
                          f"{i['credential_like_lines']} line(s) that look like a credential value in a notes/memory file read by AI agents",
                          "high", f"{ev}#{i['path']}",
                          "remove the values (keep only 'where it is stored'), then rotate those credentials", needs_human=True)
            if kind in PRIVATE_KINDS and age_d > 90:
                old += 1
                if kind in ("private-key", "age-key", "k3s-token", "secret-file", "dotenv"):
                    c.finding("data-secrets", asset, "secret.age_over_90d", f"{kind} unchanged for {age_d} days (rotation unknown)",
                              "low" if age_d < 365 else "medium", f"{ev}#{i['path']}", "rotate on a schedule; record rotation date")
        total_old += old
        c.metric("security_secrets_total", sum(1 for i in items if i["kind"] in PRIVATE_KINDS), "Secret files found",
                 store=f"files:{host}")
        c.metric("security_secrets_older_than_90d", old, "Secret files older than 90 days", store=f"files:{host}")
    c.write()


if __name__ == "__main__":
    main()
