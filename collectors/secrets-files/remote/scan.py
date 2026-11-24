"""Runs on the target host (python3, stdlib only). READ-ONLY. Finds where secrets LIVE and prints metadata only:
path, kind, mode, owner uid, size, mtime, plus boolean properties (encrypted?, passphrase?). Never prints content.
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


def classify(p, name):
    low = name.lower()
    h = head(p, 200)
    if b"PRIVATE KEY" in h and h.startswith(b"-----BEGIN"):
        return "private-key"
    if ((os.sep + ".kube" + os.sep) in p or "kubeconfig" in low or low.endswith(".yaml")) and \
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
    base_depth = root.rstrip("/").count("/")
    for dp, dns, fns in walk:
        if any(dp.startswith(e) for e in excl):
            dns[:] = []
            continue
        dns[:] = [d for d in dns if d not in EXCL_DIRS and dp.count("/") - base_depth < maxdepth]
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
print(json.dumps({"home": HOME, "items": out}))
