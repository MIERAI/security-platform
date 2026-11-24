"""spool adapters: move findings documents from a collection SITE (e.g. an external vantage host, a cluster CronJob)
to the HUB that keeps the ledger. Documents are attacker intelligence: they stay on private storage end to end.

  Spool(cfg).list() -> [name]      get(name) -> text      ack(name)      put(name, text)
cfg: {type: exec, exec: <exec adapter cfg>, dir: <directory on that host>}   any host reachable by an exec adapter
     {type: local, dir: <directory>}
Future (interface only): kubernetes-secret (a CronJob writes a Secret, the hub reads and deletes it), s3.
"""
import shlex

from . import exec as ex

VERSION = "0.1.0"


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


def _future(cfg):
    raise NotImplementedError(f"spool adapter {cfg.get('type')!r} is a documented future adapter")


ADAPTERS = {"exec": ExecSpool, "local": ExecSpool, "kubernetes-secret": _future, "s3": _future}


def spool(cfg):
    return ADAPTERS[cfg.get("type", "exec")](cfg)
