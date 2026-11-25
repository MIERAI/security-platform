#!/usr/bin/env python3
"""Writes golden.json: how the reference implementation (Python 3.12 + PyYAML) formats, rounds and sums numbers and
types YAML scalars. The Go tests read it; regenerate after a reference change:
    python3 internal/pyvalue/testdata/gen_golden.py   (needs Python >= 3.12 for sum(), and PyYAML)"""
import json, math, os, random, struct, sys
import yaml

assert sys.version_info >= (3, 12), "sum() of floats is compensated from Python 3.12 on"
rng = random.Random(20261125)
bits = lambda f: struct.unpack("<Q", struct.pack("<d", f))[0]


def floats():
    fixed = [0.0, -0.0, 1.0, 100.0, 66.66666666666667, 6.25, 18.75, 0.05, 0.15, 0.25, 0.35, 2.675, 1e16, 1e15,
             9999999999999998.0, 1e-4, 1e-5, 123456.0, 1234567.0, 0.1 + 0.2, 1 / 3, 2.5, -2.5, 1e300, 5e-324,
             float("inf"), float("-inf"), float("nan"), 72.25, 28.625, 45.45454545454545, 1e6, 999999.5]
    rnd = [rng.uniform(0, 100) for _ in range(300)] + [rng.randint(0, 2000) / 20 for _ in range(200)]
    rnd += [math.ldexp(rng.random(), rng.randint(-60, 70)) for _ in range(200)]
    return fixed + rnd


def fmt(f):
    return {"bits": str(bits(f)), "repr": repr(f), "g": format(f, "g"), "f1": format(f, ".1f"),
            "round1": str(bits(round(f, 1))) if math.isfinite(f) else str(bits(f))}


def sums():
    out = []
    for _ in range(300):
        n = rng.randint(0, 12)
        vals = []
        for _ in range(n):
            k = rng.random()
            vals.append(rng.randint(0, 20) if k < 0.4 else round(rng.uniform(0, 100), rng.choice([1, 2, 6])))
        if rng.random() < 0.2:
            vals = [round(rng.uniform(0, 100), 1) for _ in range(12)]
        s = sum(vals)
        out.append({"values": [{"int": v} if isinstance(v, int) else {"float": str(bits(v))} for v in vals],
                    "int": isinstance(s, int), "result": str(s) if isinstance(s, int) else str(bits(s))})
    return out


SCALARS = ["yes", "No", "on", "OFF", "y", "true", "False", "~", "null", "", "0", "017", "0o17", "0x1F", "0b101",
           "1_000", "+12", "-0", "1:30", "1:30:15", "1.5", "1.", ".5", "1e5", "1.0e+5", "1.0e5", "-.inf", ".NaN",
           "6.8523015e+5", "2030-01-31", "2030-1-31", "2030-01-31T10:00:00Z", "2030-01-31 10:00:00.5 +09:00",
           "2030-01-31t10:00:00-05", "abc", "12:30:45.25", "0.", "+.5", "1__0", "08", "0_7", "=x", "'q'", "-1:20"]


def describe(v):
    import datetime
    if v is None or isinstance(v, (bool, str)):
        return {"type": type(v).__name__, "str": str(v)}
    if isinstance(v, int):
        return {"type": "int", "str": str(v)}
    if isinstance(v, float):
        return {"type": "float", "str": repr(v)}
    if isinstance(v, (datetime.datetime, datetime.date)):
        return {"type": type(v).__name__, "str": str(v)}
    return {"type": type(v).__name__, "str": repr(v)}


def scalars():
    out = []
    for s in SCALARS:
        try:
            v = yaml.safe_load(f"k: {s}\n")["k"]
            out.append({"text": s, "want": describe(v)})
        except yaml.YAMLError as e:
            out.append({"text": s, "error": True})
    return out


json.dump({"floats": [fmt(f) for f in floats()], "sums": sums(), "yaml": scalars()},
          open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "golden.json"), "w"), indent=0)
