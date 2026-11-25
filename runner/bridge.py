#!/usr/bin/env python3
"""bridge: the Python parts a runner in another language reuses while they are still Python (component `runner`).

The Go runner (`sp runner`, docs/runner.md) schedules, locks, runs and records jobs itself; what still lives only in
Python it calls here, one operation per process, so both runners do exactly the same thing with the same code:

    bridge.py collector-finish --instance F --data D --job J --run-dir R --stamp S   validate, promote, outbox
    bridge.py job              --instance F --data D --job J --run-dir R            ingest, push, snapshot, pull-snapshot,
                                                                                    remediation (shadow)
    bridge.py ledger           --instance F --data D --run-dir R                    ledger merge (shadow)
    bridge.py send-state       --instance F --data D --job J                        public state -> state_outbox
    bridge.py forward          --instance F --data D --index I                      store and forward, one entry
    bridge.py sink             --instance F --data D --index I --text FILE          one metrics sink

Each prints one JSON object on stdout; diagnostics go to stderr (the runner's log). Exit 0 unless the arguments are
wrong: an operation's failure is in its JSON (`rc`, `error`), as the Python runner records it.
"""
import argparse
import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import runner  # noqa: E402  - the Python runner: the same methods, so behaviour cannot drift
from adapters import sinks, spool  # noqa: E402  (runner put the product root on sys.path)

IN_PROCESS = ("ingest", "push", "snapshot", "pull-snapshot", "remediation")   # remediation: its shadow runs


def failure(e):
    return f"{type(e).__name__}: {str(e)[:200]}"


def collector_finish(r, a):
    """runner.job_collector after the collector exited 0 with a document: validate, promote, then the outbox
    (site) or the ledger (hub: the caller merges, so it can choose the ledger implementation)."""
    import validate
    run_dir, name = a.run_dir, a.job
    j = r.jobs[name]
    doc = os.path.join(run_dir, f"{j.get('as') or j['collector']}.findings.json")
    errs = validate.validate_findings(json.load(open(doc)))
    if errs:
        return {"rc": 65, "note": f"contract violation: {errs[:3]}", "merge": False}
    r.promote(run_dir)
    if r.role == "site":
        to_outbox(r, run_dir, name, a.stamp)
        return {"rc": 0, "note": "document to outbox", "merge": False}
    if r.cfg.get("outbox"):
        try:
            to_outbox(r, run_dir, name, a.stamp)
        except Exception as e:  # noqa: BLE001 - as the runner: the local ledger is this hub's job, the copy best effort
            runner.log(f"{name}: copy to outbox: {type(e).__name__}: {str(e)[:160]}")
    return {"rc": 0, "note": "", "merge": True}


def to_outbox(r, run_dir, name, stamp):
    """runner.to_outbox with the caller's clock for the stamp."""
    for sp in r.spools(r.cfg.get("outbox")):
        for p in sorted(glob.glob(os.path.join(run_dir, "inventory.*.json")) + glob.glob(os.path.join(run_dir, "*.findings.json"))):
            sp.put(f"{stamp}-{name}.{os.path.basename(p)}", open(p).read())


def job(r, a):
    j = r.jobs[a.job]
    if j["type"] not in IN_PROCESS:
        return {"rc": 64, "note": f"type {j['type']} does not run in the bridge"}
    rc, note = getattr(r, "job_" + j["type"].replace("-", "_"))(a.job, j, a.run_dir)
    return {"rc": rc, "note": note}


def ledger(r, a):
    """runner.ledger: the merge with runner.implementations.ledger (here: its shadow run, contract runner §7)."""
    rc, note = r.ledger(a.run_dir)
    return {"rc": rc, "note": note}


def send_state(r, a):
    r.send_state(a.job, r.load_state(a.job))
    return {}


def forward(r, a):
    f = (r.cfg.get("forward") or [])[a.index]
    sent = 0
    try:
        src, dst = spool.spool(f["from"]), spool.spool(f["to"])
        for n in src.list():
            dst.put(n, src.get(n))
            src.ack(n)
            sent += 1
        return {"sent": sent, "pending": len(src.list()), "error": ""}
    except Exception as e:  # noqa: BLE001 - offline, remote down: retried next tick
        return {"sent": sent, "error": failure(e)}


def sink(r, a):
    s = (r.cfg.get("sinks") or [])[a.index]
    try:
        sinks.publish(s, open(a.text).read())
        return {"error": ""}
    except Exception as e:  # noqa: BLE001 - one sink down must not block the others
        return {"error": failure(e)}


OPS = {"collector-finish": collector_finish, "job": job, "ledger": ledger, "send-state": send_state, "forward": forward, "sink": sink}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("op", choices=sorted(OPS))
    ap.add_argument("--instance", required=True)
    ap.add_argument("--data", required=True)
    ap.add_argument("--job")
    ap.add_argument("--run-dir")
    ap.add_argument("--stamp")
    ap.add_argument("--index", type=int)
    ap.add_argument("--text")
    a = ap.parse_args(argv)
    log, runner.log = runner.log, lambda msg: None   # the calling runner logged the configuration warnings already
    try:
        r = runner.Runner(a.instance, a.data)
    except Exception as e:  # noqa: BLE001
        r = e
    finally:
        runner.log = log
    try:
        if isinstance(r, Exception):
            raise r
        out = OPS[a.op](r, a)
    except Exception as e:  # noqa: BLE001 - reported like the runner's internal error (70)
        out = {"rc": 70, "note": failure(e), "error": failure(e)}
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
