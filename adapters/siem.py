"""SIEM sinks: ledger findings as OCSF 1.x Finding events (core/ocsf.py) to a SIEM or a log shipper (core/export.py).

  deliver(cfg, events, done) -> None
      events: [(finding id, OCSF event dict)]; `done(ids)` is called after each batch the receiver accepted, so a
      failure part-way loses nothing and re-sends nothing that was accepted. Raises on failure (status code only).

Which events: core/export.py sends, per sink, `mode: changes` (default: a finding that is new or whose status,
severity or title changed since this sink last accepted it; activity Create / Update / Close) or `mode: all` (every
ledger entry on every run: a snapshot for SIEMs that expire state). `min_severity` (default info) filters both.

Implemented:
  http    {type: http, url, token_file?, auth_scheme?: Bearer, headers?: {}, format?: ndjson | json,
           wrap?: <key>, batch_size?: 500, retries?: 3, timeout?: 30}
          POST batches to any HTTP collector: ndjson (one event per line, application/x-ndjson; most log pipelines,
          Vector/Fluent Bit/Logstash http inputs, OpenSearch Ingestion) or json (one array per batch). `wrap: event`
          turns each event into {"event": {...}} (HTTP event collectors that expect an envelope). The token comes from a
          0600 file and goes into `Authorization: <auth_scheme> <token>`. Retries 429 / 5xx / connection errors with
          backoff (Retry-After honoured); any other status fails at once.
  file    {type: file, path, max_bytes?: 100MB}
          append JSON lines (mode 0600) for a log shipper that tails the file; rotated to <path>.1 past max_bytes.
  stdout  {type: stdout}    JSON lines on stdout (a container's log stream).
The events carry asset names and titles: the destination must be as private as the ledger.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request

from .sinks import read_secret_file

VERSION = "0.1.0"


def _lines(evs, wrap=None):
    return [json.dumps({wrap: e} if wrap else e, sort_keys=True, separators=(",", ":")) for e in evs]


def http(cfg, events, done, sleep=time.sleep, opener=None):
    opener = opener or urllib.request.urlopen
    size = int(cfg.get("batch_size", 500))
    retries = int(cfg.get("retries", 3))
    fmt = cfg.get("format", "ndjson")
    if fmt not in ("ndjson", "json"):
        raise ValueError("siem http: format must be ndjson or json")
    token = read_secret_file(cfg["token_file"]) if cfg.get("token_file") else None
    for i in range(0, len(events), size):
        batch = events[i:i + size]
        lines = _lines([e for _, e in batch], cfg.get("wrap"))
        body = ("\n".join(lines) + "\n" if fmt == "ndjson" else "[" + ",".join(lines) + "]").encode()
        headers = dict(cfg.get("headers") or {}, **{
            "Content-Type": "application/x-ndjson" if fmt == "ndjson" else "application/json",
            "User-Agent": "security-platform-export"})
        if token:
            headers["Authorization"] = f"{cfg.get('auth_scheme', 'Bearer')} {token}"
        for attempt in range(retries + 1):
            req = urllib.request.Request(cfg["url"], data=body, method="POST", headers=headers)
            try:
                with opener(req, timeout=cfg.get("timeout", 30)) as r:
                    if r.status // 100 != 2:
                        raise RuntimeError(f"siem http HTTP {r.status}")
                break
            except urllib.error.HTTPError as e:   # never echo the request: it carries the token
                if (e.code == 429 or e.code >= 500) and attempt < retries:
                    sleep(min(float((e.headers or {}).get("Retry-After") or 2 ** attempt), 300))
                    continue
                raise RuntimeError(f"siem http HTTP {e.code}") from None
            except (urllib.error.URLError, OSError) as e:
                if attempt < retries:
                    sleep(2 ** attempt)
                    continue
                raise RuntimeError(f"siem http: {type(e).__name__}") from None
        done([fid for fid, _ in batch])


def file(cfg, events, done):
    path = os.path.expanduser(cfg["path"])
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    if os.path.exists(path) and os.path.getsize(path) > int(cfg.get("max_bytes", 100 * 1024 * 1024)):
        os.replace(path, path + ".1")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a") as f:
        for line in _lines([e for _, e in events], cfg.get("wrap")):
            f.write(line + "\n")
        f.flush()
        os.fsync(f.fileno())
    done([fid for fid, _ in events])


def stdout(cfg, events, done):
    for line in _lines([e for _, e in events], cfg.get("wrap")):
        sys.stdout.write(line + "\n")
    sys.stdout.flush()
    done([fid for fid, _ in events])


ADAPTERS = {"http": http, "file": file, "stdout": stdout}


def deliver(cfg, events, done, **kw):
    return ADAPTERS[cfg["type"]](cfg, events, done, **kw)
