#!/usr/bin/env python3
"""core export: push the ledger into the tools a team already has (component `core`).

usage: export.py --data <private data dir> --instance <instance config> [--dry-run] [--only tickets|siem]

The platform keeps no UI and no user accounts of its own: findings go where the team already works.
  export.tickets: [..]   one ticket per finding in an issue tracker (adapters/tickets.py; GitHub Issues)
  export.siem:    [..]   OCSF 1.x Finding events to a SIEM / log pipeline (adapters/siem.py; http, file, stdout)
Reads <data>/ledger.json (+ <data>/tracker/items.json for owner / due date when present). Writes
<data>/state/export/<sink>.json (per-sink delivery state) and <data>/metrics/export.prom (aggregates only: sink
name, result). Every sink runs even when another fails; exit 1 when any failed (the runner records it and retries
on the next slot). Detection and alerting stay in the SIEM; this is aggregation, de-duplication and lifecycle.
"""
import argparse
import hashlib
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path[:0] = [HERE, ROOT, os.path.join(ROOT, "sdk")]
import ocsf  # noqa: E402
from adapters import siem, tickets  # noqa: E402
from spsdk import load_config, render  # noqa: E402

VERSION = open(os.path.join(HERE, "VERSION")).read().strip()
RANK = tickets.RANK
CLOSED = ("fixed", "false_positive")


def log(msg):
    print(f"[export] {msg}", file=sys.stderr)


def sink_name(kind, i, cfg):
    return str(cfg.get("name") or f"{kind}-{cfg.get('type')}-{i}")


def load_state(data, name):
    p = os.path.join(data, "state", "export", name + ".json")
    try:
        return json.load(open(p))
    except (OSError, ValueError):
        return {}


def save_state(data, name, st):
    d = os.path.join(data, "state", "export")
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, name + ".json")
    with open(os.open(p + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
        json.dump(st, f, indent=1, sort_keys=True)
    os.replace(p + ".tmp", p)


# ---- SIEM ------------------------------------------------------------------------------------------------------
def digest_of(e):
    return hashlib.sha256(json.dumps([e["status"], e["severity"], e.get("title")]).encode()).hexdigest()[:16]


def siem_events(entries, cfg, sent):
    """-> [(fid, OCSF event)] to send and {fid: digest} they represent. `sent`: what this sink already accepted."""
    mode = cfg.get("mode", "changes")
    if mode not in ("changes", "all"):
        raise ValueError("siem: mode must be changes or all")
    floor = RANK[cfg.get("min_severity", "info")]
    out, digests = [], {}
    for fid in sorted(entries):
        e = entries[fid]
        if RANK.get(e["severity"], 9) > floor:
            continue
        h = digest_of(e)
        if mode == "changes" and sent.get(fid) == h:
            continue
        if mode == "changes" and fid not in sent and e["status"] in CLOSED:
            continue            # never seen open by this sink: nothing to close
        ev = ocsf.to_ocsf(e)
        act = (3, "Close") if e["status"] in CLOSED else (1, "Create") if fid not in sent else (2, "Update")
        ev.update(activity_id=act[0], activity_name=act[1], type_uid=ev["class_uid"] * 100 + act[0])
        out.append((fid, ev))
        digests[fid] = h
    return out, digests


def run_siem(data, i, cfg, entries, dry):
    name = sink_name("siem", i, cfg)
    st = load_state(data, name)
    sent = st.get("sent", {})
    events, digests = siem_events(entries, cfg, sent)
    if dry:
        log(f"{name}: would send {len(events)} event(s)")
        return name, {"sent": 0, "pending": len(events)}
    count = [0]

    def done(ids):          # after every accepted batch: a failure later re-sends nothing that was accepted
        for f in ids:
            sent[f] = digests[f]
        count[0] += len(ids)
        st["sent"] = sent
        save_state(data, name, st)
    siem.deliver(cfg, events, done)
    log(f"{name}: sent {count[0]} event(s)")
    return name, {"sent": count[0]}


# ---- tickets -----------------------------------------------------------------------------------------------------
def run_tickets(data, i, cfg, entries, items, dry, backend_kw=None):
    name = sink_name("tickets", i, cfg)
    cfg = dict(cfg, dry_run=bool(cfg.get("dry_run")) or dry)
    b = tickets.backend(cfg, **(backend_kw or {}))
    n = tickets.sync(b, entries, cfg, items, log=lambda m: log(f"{name}: {m}"))
    log(f"{name}: {n}")
    return name, n


# ---- metrics -------------------------------------------------------------------------------------------------------
def series(results, data, now):
    s = []
    for name, r in sorted(results.items()):
        st = load_state(data, name)
        if r.get("error"):
            st["failures_total"] = st.get("failures_total", 0) + 1
            st["consecutive_failures"] = st.get("consecutive_failures", 0) + 1
        else:
            st["consecutive_failures"] = 0
            st["last_success"] = int(now)
        save_state(data, name, st)
        lab = {"sink": name}
        if st.get("last_success"):
            s.append(("security_export_last_success_timestamp_seconds", lab, st["last_success"],
                      "When the export sink last completed (tickets synced / events accepted)"))
        s.append(("security_export_failures_total", lab, st.get("failures_total", 0), "Failed export runs (counter)"))
        s.append(("security_export_consecutive_failures", lab, st.get("consecutive_failures", 0),
                  "Export runs failed in a row (0 = the last one worked)"))
        for k, v in sorted(r.items()):
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                continue
            s.append(("security_export_items", dict(lab, result=k), v, "Last export run: tickets or events by result"))
    return s


def main(argv=None, backend_kw=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--instance", required=True)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--only", choices=["tickets", "siem"])
    ap.add_argument("--now", type=float)
    a = ap.parse_args(argv)
    now = a.now or time.time()
    cfg = (load_config(a.instance) or {}).get("export") or {}
    lp = os.path.join(a.data, "ledger.json")
    entries = json.load(open(lp)).get("entries", {}) if os.path.exists(lp) else {}
    ip = os.path.join(a.data, "tracker", "items.json")
    items = json.load(open(ip)).get("items", {}) if os.path.exists(ip) else {}
    results, failed = {}, 0
    jobs = [("tickets", i, c) for i, c in enumerate(cfg.get("tickets") or [])] + \
           [("siem", i, c) for i, c in enumerate(cfg.get("siem") or [])]
    for kind, i, c in jobs:
        if a.only and kind != a.only:
            continue
        name = sink_name(kind, i, c)
        try:
            if kind == "tickets":
                name, r = run_tickets(a.data, i, c, entries, items, a.dry_run, backend_kw)
                if r.get("errors"):
                    r["error"] = True
            else:
                name, r = run_siem(a.data, i, c, entries, a.dry_run)
        except Exception as e:  # noqa: BLE001 - one sink down must not block the others
            r = {"error": True}
            log(f"{name}: FAILED {type(e).__name__}: {str(e)[:200]}")
        failed += bool(r.get("error"))
        results[name] = r
    if not jobs:
        log("no export sinks configured (instance `export:`)")
    if not a.dry_run:
        mp = os.path.join(a.data, "metrics", "export.prom")
        os.makedirs(os.path.dirname(mp), exist_ok=True)
        with open(mp + ".tmp", "w") as f:
            f.write(render(series(results, a.data, now)))
        os.replace(mp + ".tmp", mp)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
