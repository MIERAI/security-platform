#!/usr/bin/env python3
"""Writes reference.json: what the Python reference (runner/cron.py, runner.Runner.offset, json.dump, format) computes
for a fixed sample of inputs, in UTC (outside daylight saving time, where the Go runner deliberately differs: contract
runner §3.1). The Go tests compare against it. Re-run after changing the sample:

    TZ=UTC python3 internal/runner/testdata/gen_reference.py
"""
import hashlib
import json
import os
import random
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "runner"))
os.environ["TZ"] = "UTC"
time.tzset()
import cron  # noqa: E402

rng = random.Random(7)
EXPRS = ["30 3 * * *", "*/15 * * * *", "0 9 * * 1", "0 9 * * 7", "0 0 1 * 1", "5,35 */2 * * *", "0 0 29 2 *",
         "1-10/3 4 * * *", "0 12 15 * *", "59 23 31 12 *", "0 6 * 1-3 1-5", "*/7 1-5 * * 0", "17 * * * *",
         "0 0 * * 0,6", "45 2 1,15 * 3", "0 0 31 2 *", "30 4/6 * * *", "0 22 * * 1-5"]
cases = []
for e in EXPRS:
    c = cron.Cron(e)
    for _ in range(12):
        now = rng.randrange(1_700_000_000, 1_950_000_000)
        nxt = c.next(now)   # interval() of a schedule that never fires raises in the reference; the Go runner says 0
        cases.append({"expr": e, "now": now, "prev": c.prev(now), "next": nxt, "interval": c.interval(now) if nxt else 0})
offsets = []
for i in range(40):
    job, slot, jitter = f"job-{i % 5}", rng.randrange(1_700_000_000, 1_950_000_000) // 60 * 60, rng.choice([1, 60, 1200, 3600, 86400])
    offsets.append({"job": job, "slot": slot, "jitter": jitter,
                    "offset": int(hashlib.sha1(f"{job}|{slot}".encode()).hexdigest()[:8], 16) % jitter})
floats = [0.0, 1.0, 0.1, 12.3, 100.0, 1e15, 1e16, 1.5e16, 0.0001, 0.00001, 123456789.0, -2.5, 3.14159265358979,
          1e-7, 2.0 ** 60, 0.5, 1234567.0, 99999.95]
fmt = [{"f": f, "repr": repr(f), "g": format(f, "g")} for f in floats]
doc = {"b": [1, 2.5, {"z": None, "a": True}], "a": "é \U0001F600\"\\\n\t\x01<>&", "c": {}, "d": [], "n": -3}
out = {"cron": cases, "offset": offsets, "floats": fmt, "json_input": doc, "json": json.dumps(doc, indent=1, sort_keys=True)}
with open(os.path.join(HERE, "reference.json"), "w") as f:
    json.dump(out, f, indent=1)
    f.write("\n")
print(f"{len(cases)} cron, {len(offsets)} offset, {len(fmt)} float cases")
