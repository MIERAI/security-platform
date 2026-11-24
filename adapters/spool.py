"""spool adapters: move findings documents from a collection SITE (e.g. an external vantage host, a cluster CronJob)
to the HUB that keeps the ledger. Documents are attacker intelligence: they stay on private storage end to end.

  Spool(cfg).list() -> [name]      get(name) -> text      ack(name)      put(name, text)
cfg: {type: exec, exec: <exec adapter cfg>, dir: <directory on that host>}   any host reachable by an exec adapter
     {type: local, dir: <directory>}
     {type: kubernetes-secret, namespace?, box?, site?, + adapters/kubeapi.py transport (server+token_file+ca_file |
         in-cluster | kubeconfig)}   the hub's authenticated inbox: one Secret per document (gzip; never in logs or
         ConfigMaps); writers can only create, the hub reads and deletes (deploy/kubernetes/hub).
Store and forward: a site writes to a LOCAL spool first (always works offline); the runner's `forward` drains it to
a remote spool every tick and only acknowledges what was delivered (docs/runner.md).
Future (interface only): s3.
"""
import base64
import gzip
import hashlib
import json
import os
import re
import shlex
import time

from . import exec as ex

VERSION = "0.3.0"
PREFIX = "security-platform"
LABEL = PREFIX + "/outbox"


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
    """An authenticated inbox in a Kubernetes namespace: one Secret per document (gzip). Writers need only `create
    secrets` there (they cannot read what others sent); the hub lists, reads and deletes. Labels:
      security-platform/outbox=true, security-platform/box=<outbox|state|...>, security-platform/site=<site>
    The site label is what the hub trusts; the product's admission policy (deploy/kubernetes/hub) rejects a Secret
    whose site label does not match the writer's ServiceAccount, so a site cannot speak for another one.
    Several documents may share a name (a site's job state is re-sent every run): get() returns the newest, ack()
    deletes them all."""
    def __init__(self, cfg):
        from . import kubeapi
        self.api = kubeapi.client(cfg)
        self.ns = self.api.namespace or cfg.get("namespace")
        if not self.ns:
            raise ValueError("kubernetes-secret spool: namespace required outside a cluster")
        self.box, self.site = cfg.get("box", "outbox"), cfg.get("site", "")
        self._items = None

    @staticmethod
    def secret_name(name, box="outbox", site="", salt=""):
        base = re.sub(r"[^a-z0-9-]+", "-", f"{box}-{site}".lower()).strip("-")[:60]
        return f"sp-{base}-{hashlib.sha1((name + salt).encode()).hexdigest()[:12]}"

    def _path(self, name=None):
        return f"/api/v1/namespaces/{self.ns}/secrets" + (f"/{name}" if name else "")

    def _list(self):
        sel = f"{LABEL}=true" + (f",{PREFIX}/site={self.site}" if self.site else "")
        items = self.api.request("GET", self._path(), query={"labelSelector": sel}).get("items") or []
        by = {}
        for i in items:
            md = i["metadata"]
            if (md.get("labels") or {}).get(PREFIX + "/box", "outbox") != self.box:
                continue
            n = (md.get("annotations") or {}).get(LABEL + "-name", "")
            by.setdefault(n, []).append(i)
        for v in by.values():
            v.sort(key=lambda i: (i["metadata"].get("creationTimestamp", ""), i["metadata"]["name"]), reverse=True)
        self._items = by
        return by

    def list(self, suffix=".json"):
        return sorted(n for n in self._list() if n.endswith(suffix))

    def get(self, name):
        items = (self._items if self._items and name in self._items else self._list()).get(name)
        if not items:
            raise KeyError(name)
        return gzip.decompress(base64.b64decode(items[0]["data"]["doc"])).decode()

    def ack(self, name):
        for i in (self._items or self._list()).get(name, []):
            try:
                self.api.request("DELETE", self._path(i["metadata"]["name"]))
            except Exception as e:  # noqa: BLE001
                if getattr(e, "status", None) != 404:
                    raise
        if self._items:
            self._items.pop(name, None)

    def put(self, name, text):
        data = base64.b64encode(gzip.compress(text.encode())).decode()
        if len(data) > 900_000:
            raise ValueError(f"{name}: {len(data)} bytes after compression: too large for one Secret")
        labels = {LABEL: "true", PREFIX + "/box": self.box, "app.kubernetes.io/part-of": "security-platform"}
        if self.site:
            labels[PREFIX + "/site"] = self.site
        sec = {"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
               "metadata": {"name": self.secret_name(name, self.box, self.site, str(time.time_ns())),
                            "labels": labels, "annotations": {LABEL + "-name": name}},
               "data": {"doc": data}}
        self.api.request("POST", self._path(), body=sec)


def _future(cfg):
    raise NotImplementedError(f"spool adapter {cfg.get('type')!r} is a documented future adapter")


ADAPTERS = {"exec": ExecSpool, "local": ExecSpool, "kubernetes-secret": KubeSecretSpool, "s3": _future}


def spool(cfg):
    return ADAPTERS[cfg.get("type", "exec")](cfg)
