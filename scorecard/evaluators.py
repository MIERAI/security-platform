"""Scorecard evaluators: how an automated or evidence control decides pass / fail / unknown (component `scorecard`).

An evaluator is `fn(ctx, src) -> (status, detail)` registered in EVALUATORS under the `type` that a control's
`source:` names. status is one of "pass", "fail", "unknown" (no data, stale data, missing configuration: counted as
NOT passing - no data != secure). `detail` is one short line for the private report; never a secret value.

Adding an evaluator = one function + one registry entry here (and a test). Controls only ever name a type, so an
instance or another company adds controls without touching code, and adds code only for a new KIND of evidence.

Built-in types:
  findings    count ledger entries matching a selector (the ledger's SLI selector keys: check_in, check_prefix,
              severity_in, layer_in, kind, kind_not, attr_true, attr_any_true; plus asset_contains, status_in
              (default [open])); pass when count <= max (default 0). `require_collector: name | [names]` +
              `max_age` (default 3d): unknown unless that collector covered something recently (otherwise
              "0 findings" may just mean "nobody looked"). `require_coverage: <asset prefix>`: unknown unless the
              newest documents (<data>/latest) show an `ok` coverage entry for such an asset - the control is only
              as good as the specific thing it needs to have been looked at.
  sli         a ledger SLI meets its objective: {sli: name}
  metric      a sample of the published metrics: {name, match: {label: regex}, agg: max|min|sum|count, op, value,
              absent: unknown|pass|fail}
  collector_fresh  {collectors: [names] | "*", max_age}: each covered at least one asset within max_age
  job         {jobs: [names] | "*", max_age}: runner jobs whose last run succeeded within max_age
  file        evidence document {path, max_age?, contains?, mode_max?}: exists; reviewed (git commit date, else
              mtime) within max_age; text matches `contains`; permission bits within mode_max (e.g. "0700")
  all / any   {of: [sources]}: every / at least one sub-source passes (unknown wins over fail in `all`)
  builtin     {name: pillars_covered | functions_covered | attestations_current}: about the scorecard itself
  none        {reason}: declared but not implemented yet -> status "not_implemented" (counted as failing)
"""
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path[:0] = [os.path.join(ROOT, "core")]

UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 7 * 86400}


def duration(v, default=None):
    if v is None:
        return default
    if isinstance(v, (int, float)):
        return float(v)
    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([smhdw])\s*", str(v))
    if not m:
        raise ValueError(f"bad duration {v!r} (e.g. 90d, 12h)")
    return float(m.group(1)) * UNITS[m.group(2)]


def ts(s):
    """ISO date or datetime (UTC) -> epoch."""
    s = str(s)
    if "T" in s:
        return time.mktime(time.strptime(s[:19], "%Y-%m-%dT%H:%M:%S")) - time.timezone
    return time.mktime(time.strptime(s[:10], "%Y-%m-%d")) - time.timezone


def age_text(seconds):
    return f"{seconds / 86400:.1f}d" if seconds >= 86400 else f"{seconds / 3600:.1f}h"


# ---- selector (same keys as the ledger's SLI selector, so catalogs read alike) -------------------------------
def selected(e, sel):
    at = e.get("attributes") or {}
    return (("check_in" not in sel or e["check"] in sel["check_in"])
            and ("check_prefix" not in sel or any(e["check"].startswith(x) for x in sel["check_prefix"]))
            and ("severity_in" not in sel or e["severity"] in sel["severity_in"])
            and ("layer_in" not in sel or e["layer"] in sel["layer_in"])
            and ("kind" not in sel or e.get("kind") == sel["kind"])
            and ("kind_not" not in sel or e.get("kind") != sel["kind_not"])
            and ("asset_contains" not in sel or any(x in e["asset"] for x in _list(sel["asset_contains"])))
            and ("attr_true" not in sel or at.get(sel["attr_true"]))
            and ("attr_any_true" not in sel or any(at.get(x) for x in sel["attr_any_true"])))


def _list(v):
    return v if isinstance(v, list) else [v]


def collectors_fresh(ctx, names, max_age):
    """-> (ok, detail). A collector is fresh when it covered >= 1 asset within max_age (ledger.collectors)."""
    cols = (ctx.ledger.get("collectors") or {})
    if names == "*":
        names = sorted(cols)
        if not names:
            return False, "no collector has run yet"
    stale = []
    for n in _list(names):
        last = (cols.get(n) or {}).get("last_good_run")
        if not last:
            stale.append(f"{n}: never covered anything")
        elif ctx.now - ts(last) > max_age:
            stale.append(f"{n}: last good run {age_text(ctx.now - ts(last))} ago")
    return (not stale), "; ".join(stale) or f"{len(_list(names))} collector(s) fresh"


# ---- evaluators ----------------------------------------------------------------------------------------------
def ev_findings(ctx, src):
    req = src.get("require_collector")
    if req:
        ok, why = collectors_fresh(ctx, req, duration(src.get("max_age"), 3 * 86400))
        if not ok:
            return "unknown", f"no recent coverage ({why})"
    pre = src.get("require_coverage")
    if pre:
        cols = set(_list(req)) if req and req != "*" else None
        if not any(a.startswith(pre) and st == "ok" and (cols is None or col in cols) for col, a, st in ctx.coverage):
            return "unknown", f"nothing covered {pre}* (adapter not configured or failing)"
    status_in = src.get("status_in", ["open"])
    hits = [e for e in (ctx.ledger.get("entries") or {}).values() if e.get("status") in status_in and selected(e, src)]
    mx = int(src.get("max", 0))
    detail = f"{len(hits)} matching finding(s) (max {mx})"
    if hits:
        detail += ": " + ", ".join(sorted({e["check"] for e in hits})[:6])
    return ("pass" if len(hits) <= mx else "fail"), detail


def ev_sli(ctx, src):
    s = (ctx.ledger.get("sli") or {}).get(src["sli"])
    if s is None:
        return "unknown", f"SLI {src['sli']} not computed yet"
    return ("pass" if s.get("ok") else "fail"), f"SLI {src['sli']} = {s.get('value')} (objective <= {s.get('target')})"


OPS = {"<=": lambda a, b: a <= b, ">=": lambda a, b: a >= b, "==": lambda a, b: a == b, "<": lambda a, b: a < b,
       ">": lambda a, b: a > b, "!=": lambda a, b: a != b}


def ev_metric(ctx, src):
    match = {k: re.compile(str(v)) for k, v in (src.get("match") or {}).items()}
    vals = [v for n, lab, v in ctx.metrics if n == src["name"]
            and all(rx.fullmatch(lab.get(k, "")) for k, rx in match.items())]
    if not vals:
        return src.get("absent", "unknown"), f"metric {src['name']} absent"
    agg = src.get("agg", "max")
    v = {"max": max, "min": min, "sum": sum, "count": len}[agg](vals)
    if src.get("age"):                       # the value is an epoch timestamp: compare its age instead
        v = ctx.now - v
        target = duration(src["value"])
        ok = OPS[src.get("op", "<=")](v, target)
        return ("pass" if ok else "fail"), f"{src['name']} age {age_text(v)} ({src.get('op', '<=')} {src['value']})"
    ok = OPS[src.get("op", "<=")](v, float(src.get("value", 0)))
    return ("pass" if ok else "fail"), f"{agg}({src['name']}) = {v:g} ({src.get('op', '<=')} {src.get('value', 0)})"


def ev_collector_fresh(ctx, src):
    ok, why = collectors_fresh(ctx, src.get("collectors", "*"), duration(src.get("max_age"), 2 * 86400))
    return ("pass" if ok else "fail"), why


def ev_job(ctx, src):
    jobs = src.get("jobs", "*")
    states = ctx.runner_states
    if jobs == "*":
        jobs = sorted(states)
        if not jobs:
            return "unknown", "no runner job state (is the runner installed?)"
    max_age, bad = duration(src.get("max_age"), 2 * 86400), []
    for j in _list(jobs):
        st = states.get(j)
        if not st:
            bad.append(f"{j}: never ran")
        elif not st.get("last_success") or ctx.now - st["last_success"] > max_age:
            bad.append(f"{j}: no success within {src.get('max_age', '2d')}")
        elif st.get("last_rc") not in (0, None):
            bad.append(f"{j}: last run failed (rc={st.get('last_rc')})")
    return ("pass" if not bad else "fail"), "; ".join(bad[:6]) or f"{len(_list(jobs))} job(s) healthy"


def last_changed(path):
    """git commit date of the path (when it is in a git work tree), else mtime."""
    d = path if os.path.isdir(path) else os.path.dirname(path)
    try:
        p = subprocess.run(["git", "-C", d, "log", "-1", "--format=%ct", "--", path], capture_output=True, text=True,
                           timeout=10)
        if p.returncode == 0 and p.stdout.strip():
            return float(p.stdout.strip())
    except (OSError, subprocess.SubprocessError):
        pass
    return os.stat(path).st_mtime


def ev_file(ctx, src):
    p = os.path.expanduser(src["path"])
    if not os.path.isabs(p):
        p = os.path.join(ROOT, p)
    if not os.path.exists(p):
        return "fail", f"{src['path']} missing"
    notes = []
    if src.get("max_age"):
        age = ctx.now - last_changed(p)
        if age > duration(src["max_age"]):
            return "fail", f"{src['path']} not reviewed for {age_text(age)} (max {src['max_age']})"
        notes.append(f"changed {age_text(age)} ago")
    if src.get("contains"):
        text = open(p, errors="replace").read() if os.path.isfile(p) else ""
        if not re.search(src["contains"], text, re.M):
            return "fail", f"{src['path']} lacks /{src['contains']}/"
    if src.get("mode_max"):
        mode = os.stat(p).st_mode & 0o777
        if mode & ~int(str(src["mode_max"]), 8):
            return "fail", f"{src['path']} mode {oct(mode)} exceeds {src['mode_max']}"
        notes.append(f"mode {oct(mode)}")
    return "pass", f"{src['path']} present" + (f" ({', '.join(notes)})" if notes else "")


def ev_all(ctx, src):
    res = [evaluate(ctx, s) for s in src["of"]]
    if all(r[0] == "pass" for r in res):
        return "pass", "; ".join(r[1] for r in res)
    st = "unknown" if any(r[0] == "unknown" for r in res) else "fail"
    return st, "; ".join(r[1] for r in res if r[0] != "pass")


def ev_any(ctx, src):
    res = [evaluate(ctx, s) for s in src["of"]]
    for r in res:
        if r[0] == "pass":
            return r
    st = "unknown" if all(r[0] == "unknown" for r in res) else "fail"
    return st, "; ".join(r[1] for r in res)


def ev_builtin(ctx, src):
    name = src["name"]
    if name in ("pillars_covered", "functions_covered"):
        key, want = ("pillars", ctx.pillars) if name == "pillars_covered" else ("functions", ctx.functions)
        auto = src.get("check", ["automated"])
        have = set()
        for c in ctx.controls:
            if c["check"] in auto and c.get("_status") == "pass":
                have.update(c[key] if key == "pillars" else [c["function"]])
        missing = [x for x in want if x not in have]
        return ("pass" if not missing else "fail"), (f"no passing {'/'.join(auto)} control for: {', '.join(missing)}"
                                                    if missing else f"every {key[:-1]} has a passing {'/'.join(auto)} control")
    if name == "attestations_current":
        att = [c for c in ctx.controls if c["check"] == "attested"]
        bad = [c["id"] for c in att if c.get("_status") in ("expired",)]
        return ("pass" if not bad else "fail"), (f"expired: {', '.join(bad)}" if bad else f"{len(att)} attested controls, none expired")
    raise ValueError(f"unknown builtin {name!r}")


def ev_none(ctx, src):
    return "not_implemented", src.get("reason", "not implemented yet")


EVALUATORS = {"findings": ev_findings, "sli": ev_sli, "metric": ev_metric, "collector_fresh": ev_collector_fresh,
              "job": ev_job, "file": ev_file, "all": ev_all, "any": ev_any, "builtin": ev_builtin, "none": ev_none}
DEFERRED = {"builtin"}   # evaluated after every other control (they look at the others' results)


def evaluate(ctx, src):
    fn = EVALUATORS.get(src.get("type"))
    if fn is None:
        return "unknown", f"unknown source type {src.get('type')!r}"
    try:
        return fn(ctx, src)
    except Exception as e:  # noqa: BLE001 - one broken control must not hide the rest of the scorecard
        return "unknown", f"evaluator error: {type(e).__name__}: {str(e)[:160]}"


def load_json(p, default):
    try:
        with open(p) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default
