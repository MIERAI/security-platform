"""Runs on the target host (python3, stdlib only). READ-ONLY. Finds where secrets LIVE and prints metadata only:
path, kind, mode, owner uid, size, mtime, plus boolean properties (encrypted?, passphrase?). Never prints content.
Windows: POSIX mode bits do not exist; `mode` is derived from the file's ACL (one PowerShell Get-Acl call for all
found files, by SID so it is locale independent): readable by Everyone / Users / Authenticated Users -> 0o644,
readable by another account -> 0o640, otherwise (owner, the scanning account, SYSTEM, Administrators) 0o600; `acl`
lists the other readers (SIDs).
usage: python3 scan.py <json-config>   config: {"roots": [...], "exclude": [...], "maxdepth": N}
"""
import json
import os
import re
import stat
import subprocess
import sys

cfg = json.loads(sys.argv[1])
HOME = os.path.expanduser("~")
if os.environ.get("SUDO_USER"):  # run via sudo: "~" means the invoking user's home, not root's
    import pwd
    HOME = pwd.getpwnam(os.environ["SUDO_USER"]).pw_dir


def expand(p):
    return HOME + p[1:] if p.startswith("~") else p

EXCL_DIRS = {"node_modules", ".git", "venv", ".venv", "__pycache__", "Caches", "pkg", ".cache", "site-packages",
             "proc", "go-build", ".npm", ".rustup", ".cargo", "Library", "snap", ".local"}
excl = [expand(e) for e in cfg.get("exclude", [])]
maxdepth = cfg.get("maxdepth", 5)
CRED_LINE = re.compile(r"((密码|口令|password|passwd|pwd|token|secret)\s*[:=：（(]\s*[^\s`<$]{3,}"
                       r"|(密码|口令)\s+[A-Za-z0-9!@#%^&*._-]{3,}\s*[;；,，)）])", re.I)


def head(p, n=4096):
    try:
        with open(p, "rb") as f:
            return f.read(n)
    except OSError:
        return b""


WIN = os.name == "nt"


def reparse(p):
    """Junctions / symlinks (e.g. the legacy "Application Data" junctions on Windows) are not walked: no loops, no
    duplicates, no denied legacy paths."""
    try:
        st = os.lstat(p)
    except OSError:
        return True
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & 0x400)


def classify(p, name):
    low = name.lower()
    p = p.replace("\\", "/")
    h = head(p, 200)
    if b"PRIVATE KEY" in h and h.startswith(b"-----BEGIN"):
        return "private-key"
    if (("/.kube/") in p or "kubeconfig" in low or low.endswith(".yaml")) and \
            b"clusters:" in head(p, 1 << 16) and b"users:" in head(p, 1 << 16):
        return "kubeconfig"
    if low.endswith((".tfstate", ".tfstate.backup")) and "/.terraform/" not in p:  # .terraform/ = backend metadata
        return "tf-state"
    if low == ".env" or (low.startswith(".env.") and not low.endswith((".example", ".sample", ".template"))):
        return "dotenv"
    if low == "rclone.conf":
        return "rclone-config"
    if low == "keys.txt" and b"AGE-SECRET-KEY" in head(p):
        return "age-key"
    if low in (".netrc", "_netrc"):
        return "netrc"
    if low == "config.json" and os.path.basename(os.path.dirname(p)) == ".docker":
        return "docker-config"
    if low == "hosts.yml" and "gh" in p:
        return "gh-config"
    if low in ("token", "node-token") and "rancher" in p:
        return "k3s-token"
    if "/.secrets/" in p or low.endswith((".password", ".passwd", ".secret", ".token", ".key")):
        return "secret-file"
    if low.endswith(".md") and ("memory" in p or "MEMORY" in p):
        return "notes"
    return None


def props(p, kind):
    d = {}
    if kind == "private-key":
        h = head(p, 8192)
        d["format"] = "openssh" if b"OPENSSH" in h else "pem"
        if b"ENCRYPTED" in h:
            d["passphrase"] = True
        else:
            r = subprocess.run(["ssh-keygen", "-y", "-P", "", "-f", p], capture_output=True, text=True,
                               stdin=subprocess.DEVNULL, timeout=10)
            d["passphrase"] = r.returncode != 0
            if r.returncode == 0:
                d["type"] = r.stdout.split()[0]
    elif kind == "kubeconfig":
        h = head(p, 1 << 20)
        d["embedded_client_key"] = b"client-key-data" in h
        d["token_auth"] = b"token:" in h
    elif kind == "tf-state":
        d["encrypted"] = b'"encrypted_data"' in head(p, 1 << 16)
    elif kind == "rclone-config":
        d["encrypted"] = head(p, 64).startswith(b"# Encrypted rclone")
    elif kind == "docker-config":
        h = head(p, 1 << 16)
        d["inline_auth"] = b'"auth":' in h
    elif kind == "gh-config":
        d["token_in_file"] = b"oauth_token" in head(p, 1 << 16)
    elif kind == "notes":
        n = 0
        try:
            for line in open(p, errors="replace"):
                if CRED_LINE.search(line) and "不写明文" not in line:
                    n += 1
        except OSError:
            pass
        d["credential_like_lines"] = n
    elif kind == "dotenv":
        try:
            d["vars"] = sum(1 for l in open(p, errors="replace") if re.match(r"\s*[A-Za-z_][A-Za-z0-9_]*\s*=", l))
        except OSError:
            pass
    return d


out = []
for root in cfg["roots"]:
    root = expand(root)
    if os.path.isfile(root):
        walk = [(os.path.dirname(root), [], [os.path.basename(root)])]
    else:
        walk = os.walk(root)
    base_depth = root.rstrip("/\\").count(os.sep)
    for dp, dns, fns in walk:
        if any(dp.startswith(e) for e in excl):
            dns[:] = []
            continue
        dns[:] = [d for d in dns if d not in EXCL_DIRS and dp.count(os.sep) - base_depth < maxdepth
                  and not reparse(os.path.join(dp, d))]
        for fn in fns:
            p = os.path.join(dp, fn)
            if any(p.startswith(e) for e in excl):
                continue
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode) or st.st_size > (64 << 20):
                continue
            kind = classify(p, fn)
            if not kind:
                continue
            pr = props(p, kind)
            if kind == "notes" and not pr.get("credential_like_lines"):
                continue
            out.append(dict(path=p, kind=kind, mode=oct(st.st_mode & 0o777), uid=st.st_uid, size=st.st_size,
                            mtime=int(st.st_mtime), **pr))
BROAD = {"S-1-1-0", "S-1-5-32-545", "S-1-5-11", "S-1-5-7"}          # Everyone, Users, Authenticated Users, Anonymous
TRUSTED = {"S-1-5-18", "S-1-5-32-544", "S-1-3-0"}                   # SYSTEM, Administrators, CREATOR OWNER


def windows_acl(items):
    """path -> (synthetic mode, readers) from one PowerShell call."""
    if not items:
        return {}
    ps = ("$ErrorActionPreference='SilentlyContinue';[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
          "$me=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;Write-Output ('me'+[char]9+$me+[char]9+$me);"
          "foreach($p in [Console]::In.ReadToEnd().Split([char]10)){$p=$p.Trim();if(-not $p){continue};$a=Get-Acl -LiteralPath $p;"
          "$o=try{$a.GetOwner([Security.Principal.SecurityIdentifier]).Value}catch{''};"
          "foreach($r in $a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){"
          "if($r.AccessControlType -eq 'Allow' -and ($r.FileSystemRights.value__ -band 0x1)){"
          "Write-Output ($p+[char]9+$o+[char]9+$r.IdentityReference.Value)}}}")
    r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], input="\n".join(i["path"] for i in items),
                       capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
    acl, me = {}, None
    for line in r.stdout.splitlines():
        parts = line.rstrip("\r").split("\t")
        if len(parts) == 3:
            path, owner, sid = parts
            if path == "me":
                me = sid      # the scanning account (the home's user): reading its own secrets is expected
                continue
            acl.setdefault(path, set())
            if sid not in (owner, me) and sid not in TRUSTED:
                acl[path].add(sid)
    res = {}
    for path, readers in acl.items():
        mode = 0o644 if readers & BROAD else (0o640 if readers else 0o600)
        res[path] = (mode, sorted(readers))
    return res


if WIN:
    acl = windows_acl(out)
    for i in out:
        if i["path"] in acl:
            i["mode"] = oct(acl[i["path"]][0])
            i["acl"] = acl[i["path"]][1]
        else:
            i["mode"] = "unknown"
print(json.dumps({"home": HOME, "items": out}))
