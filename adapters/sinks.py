"""metrics sink adapters: deliver the platform's metrics (Prometheus text format) to a monitoring system.

  publish(cfg, text) -> None   (raises on failure; the runner records it and keeps going)

The text is the node_exporter "textfile" format: the most widely understood hand-off for batch jobs
(node_exporter, Grafana Alloy, Telegraf, the OpenTelemetry collector, Datadog's OpenMetrics check all read it).
Implemented:
  textfile              {type: textfile, path: <file>, exec?: <exec adapter cfg>}   atomic write, local or on a host
  kubernetes-configmap  {type: kubernetes-configmap, kubeconfig?, context?, namespace, name, key?}
                        a ConfigMap served by the platform's metrics exporter (deploy/kubernetes) and scraped by
                        the cluster's Prometheus; the cluster adds its own target labels (namespace, pod)
  remote_write          {type: remote_write, url, bearer_token_file?, labels?: {}, timeout?}
                        Prometheus remote-write 1.0 (protobuf + snappy, stdlib only) to any compatible receiver
                        (Prometheus with the receiver on, Mimir, Thanos Receive, VictoriaMetrics, Grafana Cloud)
Secrets are read from files (mode 0600 required) and never logged.
"""
import os
import re
import stat
import struct
import subprocess
import time
import urllib.request

from . import exec as ex

VERSION = "0.2.0"


# ---- textfile ---------------------------------------------------------------------------------------------
def textfile(cfg, text):
    path = cfg["path"]
    if cfg.get("exec"):
        d = os.path.dirname(path) or "."
        script = f'umask 022; mkdir -p "{d}" && cat > "{path}.tmp" && mv "{path}.tmp" "{path}"'
        rc, _, err = ex.executor(cfg["exec"]).run(["sh", "-c", script], stdin=text, timeout=60)
        if rc != 0:
            raise RuntimeError(f"textfile via exec rc={rc}: {err.strip()[-160:]}")
        return
    path = os.path.expanduser(path)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path + ".tmp", "w") as f:
        f.write(text)
    os.replace(path + ".tmp", path)


# ---- kubernetes ConfigMap ---------------------------------------------------------------------------------
def kubernetes_configmap(cfg, text):
    """Server-side apply of one key; other keys/fields keep their owners. Transport: adapters/kubeapi.py (kubectl
    with a kubeconfig, the pod's ServiceAccount in a cluster, or server + token_file). Namespace defaults to the pod's."""
    from . import kubeapi
    api = kubeapi.client(cfg)
    ns = cfg.get("namespace") or api.namespace
    cm = {"apiVersion": "v1", "kind": "ConfigMap",
          "metadata": {"name": cfg["name"], "namespace": ns,
                       "labels": {"app.kubernetes.io/part-of": "security-platform",
                                  "app.kubernetes.io/component": "metrics"}},
          "data": {cfg.get("key", "security-platform.prom"): text}}
    api.request("PATCH", f"/api/v1/namespaces/{ns}/configmaps/{cfg['name']}", body=cm,
                query={"fieldManager": "security-platform-runner", "force": "true"})


# ---- remote_write -----------------------------------------------------------------------------------------
LINE = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{(.*)\})?\s+(\S+)(\s+\d+)?$')
LABEL = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"')


def parse_text(text):
    """Prometheus text format -> [(name, {labels}, value)] (comments skipped)."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = LINE.match(line)
        if not m:
            raise ValueError(f"not a sample line: {line[:120]!r}")
        labels = {k: bytes(v, "utf-8").decode("unicode_escape") for k, v in LABEL.findall(m.group(3) or "")}
        out.append((m.group(1), labels, float(m.group(4))))
    return out


def _varint(n):
    b = bytearray()
    while True:
        x = n & 0x7F
        n >>= 7
        if n:
            b.append(x | 0x80)
        else:
            b.append(x)
            return bytes(b)


def _ld(field, payload):   # length-delimited field
    return _varint(field << 3 | 2) + _varint(len(payload)) + payload


def encode_write_request(samples, ts_ms):
    """prometheus.WriteRequest (remote-write 1.0): repeated TimeSeries{labels, samples}."""
    out = bytearray()
    for name, labels, value in samples:
        ls = sorted(dict(labels, __name__=name).items())
        ts = b"".join(_ld(1, _ld(1, k.encode()) + _ld(2, v.encode())) for k, v in ls)
        sample = _varint(1 << 3 | 1) + struct.pack("<d", value) + _varint(2 << 3 | 0) + _varint(ts_ms)
        ts += _ld(2, sample)
        out += _ld(1, ts)
    return bytes(out)


def snappy_literal(data):
    """Valid snappy block format using only literal elements (no compression: small payloads, no C library)."""
    out = bytearray(_varint(len(data)))
    for i in range(0, len(data), 65536):
        chunk = data[i:i + 65536]
        n = len(chunk) - 1
        if n < 60:
            out.append(n << 2)
        elif n < 256:
            out += bytes([60 << 2, n])
        else:
            out += bytes([61 << 2]) + struct.pack("<H", n)
        out += chunk
    return bytes(out)


def read_secret_file(p):
    p = os.path.expanduser(p)
    st = os.stat(p)
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise PermissionError(f"{p} must not be readable by group/others (chmod 600)")
    return open(p).read().strip()


def remote_write(cfg, text, now=None):
    samples = [(n, dict(cfg.get("labels", {}), **lab), v) for n, lab, v in parse_text(text)]
    body = snappy_literal(encode_write_request(samples, int((now or time.time()) * 1000)))
    req = urllib.request.Request(cfg["url"], data=body, method="POST", headers={
        "Content-Encoding": "snappy", "Content-Type": "application/x-protobuf",
        "X-Prometheus-Remote-Write-Version": "0.1.0", "User-Agent": "security-platform-runner"})
    if cfg.get("bearer_token_file"):
        req.add_header("Authorization", "Bearer " + read_secret_file(cfg["bearer_token_file"]))
    try:
        with urllib.request.urlopen(req, timeout=cfg.get("timeout", 30)) as r:
            if r.status // 100 != 2:
                raise RuntimeError(f"remote_write HTTP {r.status}")
    except urllib.error.HTTPError as e:   # never echo the request (it carries the token)
        raise RuntimeError(f"remote_write HTTP {e.code}") from None


ADAPTERS = {"textfile": textfile, "kubernetes-configmap": kubernetes_configmap, "remote_write": remote_write}


def publish(cfg, text):
    return ADAPTERS[cfg["type"]](cfg, text)
