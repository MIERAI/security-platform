"""spool adapters: move findings documents from a collection SITE (e.g. an external vantage host, a cluster CronJob)
to the HUB that keeps the ledger. Documents are attacker intelligence: they stay on private storage end to end.

  Spool(cfg).list() -> [name]      get(name) -> text      ack(name)      put(name, text)
cfg: {type: exec, exec: <exec adapter cfg>, dir: <directory on that host>}   any host reachable by an exec adapter
     {type: local, dir: <directory>}
     {type: kubernetes-secret, namespace, kubeconfig?, context?}   one Secret per document (gzip; data never in
         logs or ConfigMaps); a site in a cluster writes them (RBAC: create secrets in its namespace), the hub reads
         and deletes them. kubeconfig empty = in-cluster ServiceAccount.
Future (interface only): s3.
"""
import base64
import gzip
import hashlib
import json
import os
import re
import shlex
import subprocess

from . import exec as ex

VERSION = "0.2.0"
LABEL = "security-platform/outbox"


class ExecSpool:
    def __init__(self, cfg):
        self.x = ex.executor(cfg.get("exec") or {"type": "local"})
        self.dir = cfg["dir"].rstrip("/")

    def _sh(self, script, stdin=None, timeout=120):
        rc, out, err = self.x.run(["sh", "-c", script], stdin=stdin, timeout=timeout)
        if rc != 0:
            raise RuntimeError(f"spool rc={rc}: {err.strip()[-160:]}")
        return out

    def _d(self):   # keep ~ expandable by the remote shell, quote the rest
        d = self.dir
        return ('"$HOME"' + shlex.quote(d[1:])) if d.startswith("~") else shlex.quote(d)

    def list(self, suffix=".json"):
        out = self._sh(f'd={self._d()}; mkdir -p "$d"; cd "$d" && for f in *{suffix}; do [ -f "$f" ] && echo "$f"; done; true')
        return sorted(x for x in out.splitlines() if x and "/" not in x)

    def get(self, name):
        return self._sh(f'cat {self._d()}/{shlex.quote(name)}', timeout=300)

    def ack(self, name):
        self._sh(f'd={self._d()}; mkdir -p "$d/sent" && mv "$d/"{shlex.quote(name)} "$d/sent/"')

    def put(self, name, text):
        self._sh(f'd={self._d()}; umask 077; mkdir -p "$d" && cat > "$d/".{shlex.quote(name)}.tmp && '
                 f'mv "$d/".{shlex.quote(name)}.tmp "$d/"{shlex.quote(name)}', stdin=text)


class KubeSecretSpool:
    def __init__(self, cfg):
        self.ns = cfg["namespace"]
        self.kc = ["kubectl"] + (["--kubeconfig", os.path.expanduser(cfg["kubeconfig"])] if cfg.get("kubeconfig") else []) + \
            (["--context", cfg["context"]] if cfg.get("context") else []) + ["-n", self.ns]

    @staticmethod
    def secret_name(name):
        base = re.sub(r"[^a-z0-9-]+", "-", name.lower()).strip("-")[:200]
        return f"sp-outbox-{base}-{hashlib.sha1(name.encode()).hexdigest()[:8]}"

    def _k(self, args, stdin=None):
        p = subprocess.run(self.kc + args, input=stdin, capture_output=True, text=True, timeout=120)
        if p.returncode != 0:
            raise RuntimeError(f"kubectl {args[0]} rc={p.returncode}: {p.stderr.strip()[-160:]}")
        return p.stdout

    def list(self, suffix=".json"):
        items = json.loads(self._k(["get", "secrets", "-l", f"{LABEL}=true", "-o", "json"]))["items"]
        names = [(i["metadata"].get("annotations") or {}).get(LABEL + "-name", "") for i in items]
        return sorted(n for n in names if n.endswith(suffix))

    def get(self, name):
        sec = json.loads(self._k(["get", "secret", self.secret_name(name), "-o", "json"]))
        return gzip.decompress(base64.b64decode(sec["data"]["doc"])).decode()

    def ack(self, name):
        self._k(["delete", "secret", self.secret_name(name), "--ignore-not-found"])

    def put(self, name, text):
        data = base64.b64encode(gzip.compress(text.encode())).decode()
        if len(data) > 900_000:
            raise ValueError(f"{name}: {len(data)} bytes after compression: too large for one Secret")
        sec = {"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
               "metadata": {"name": self.secret_name(name), "labels": {LABEL: "true", "app.kubernetes.io/part-of": "security-platform"},
                            "annotations": {LABEL + "-name": name}},
               "data": {"doc": data}}
        self._k(["create", "-f", "-"], stdin=json.dumps(sec))


def _future(cfg):
    raise NotImplementedError(f"spool adapter {cfg.get('type')!r} is a documented future adapter")


ADAPTERS = {"exec": ExecSpool, "local": ExecSpool, "kubernetes-secret": KubeSecretSpool, "s3": _future}


def spool(cfg):
    return ADAPTERS[cfg.get("type", "exec")](cfg)
