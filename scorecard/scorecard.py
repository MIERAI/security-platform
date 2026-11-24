#!/usr/bin/env python3
"""scorecard: score the security programme per dimension, pillar and NIST CSF function (component `scorecard`).

    scorecard.py compute --data D [--instance F] [--now EPOCH] [--catalog DIR ...]
    scorecard.py attest  --data D CONTROL --by WHO [--note TEXT] [--days N | --expires YYYY-MM-DD] [--false]
                         [--not-applicable REASON]
    scorecard.py lint    [--catalog DIR ...] [--instance F]
    scorecard.py list    [--catalog DIR ...] [--instance F] [--dimension ID]

Security is decided by the weakest link: every dimension has a score (weighted pass ratio of its controls, 0-100),
the overall status is FAIL as soon as ONE dimension is below its threshold (default 75), and the overall score is the
minimum. docs/scorecard.md explains the model; the catalog is data (scorecard/catalog/<NN>-<dimension>.yaml, one
file per dimension), so another organisation brings its own catalog and weights (instance `scorecard:` block).

Inputs (contracts only): <data>/ledger.json, <data>/metrics/security-platform.prom (the last published metrics),
<data>/state/runner/*.json (job states), <data>/attestations.yaml (humans only), the catalog.
Outputs: <data>/reports/scorecard.json (security-platform/scorecard/v1), <data>/reports/scorecard.md,
<data>/metrics/scorecard.prom, <data>/state/scorecard.json (regression state).
"""
import argparse
import glob
import json
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path[:0] = [HERE, os.path.join(ROOT, "sdk"), ROOT]
import evaluators as ev  # noqa: E402
from spsdk import load_config, render  # noqa: E402

VERSION = open(os.path.join(HERE, "VERSION")).read().strip()
SCHEMA = "security-platform/scorecard/v1"
CATALOG_SCHEMA = "security-platform/scorecard-catalog/v1"
ATTEST_SCHEMA = "security-platform/attestations/v1"
PILLARS = ["network", "device", "people", "software"]
FUNCTIONS = {"GV": "Govern", "ID": "Identify", "PR": "Protect", "DE": "Detect", "RS": "Respond", "RC": "Recover"}
CHECKS = ("automated", "attested", "evidence")
PASSING = {"pass"}
EXPIRING_SOON = 14 * 86400


# ---- catalog ---------------------------------------------------------------------------------------------------
def catalog_dirs(inst, extra=None):
    sc = (inst or {}).get("scorecard") or {}
    dirs = [] if sc.get("replace_catalog") else [os.path.join(HERE, "catalog")]
    dirs += [os.path.expanduser(d) for d in (sc.get("catalog_dirs") or [])]
    return dirs + list(extra or [])


def load_catalog(dirs, inst=None):
    """-> (dimensions {id: meta}, controls [..]). Later directories may add dimensions and controls; a control id
    that already exists is replaced (an organisation's own version of a product control)."""
    dims, ctrls = {}, {}
    for d in dirs:
        for p in sorted(glob.glob(os.path.join(d, "*.yaml")) + glob.glob(os.path.join(d, "*.json"))):
            doc = load_config(p) or {}
            if doc.get("schema") != CATALOG_SCHEMA:
                raise ValueError(f"{p}: schema must be {CATALOG_SCHEMA}")
            dm = dict(doc["dimension"], _file=os.path.relpath(p, ROOT) if p.startswith(ROOT) else p)
            dims.setdefault(dm["id"], {}).update(dm)
            for c in doc.get("controls") or []:
                c = dict(c, dimension=dm["id"], _file=dm["_file"])
                c.setdefault("pillars", dm.get("pillars", []))
                ctrls[c["id"]] = c
    sc = (inst or {}).get("scorecard") or {}
    for cid, o in (sc.get("overrides") or {}).items():
        if cid in ctrls:
            ctrls[cid].update(o)
    for c in ctrls.values():
        c["function"] = str(c.get("csf", "")).split(".")[0]
        c.setdefault("weight", 1)
        c.setdefault("cis", [])
    return dims, sorted(ctrls.values(), key=lambda c: (dims.get(c["dimension"], {}).get("order", 99), c["id"]))


def lint(dims, controls):
    errs, seen = [], set()
    for d in dims.values():
        for k in ("id", "title", "order"):
            if k not in d:
                errs.append(f"dimension {d.get('id')}: {k} missing")
    for c in controls:
        cid = c.get("id", "?")
        if cid in seen:
            errs.append(f"{cid}: duplicate id")
        seen.add(cid)
        if not re.fullmatch(r"[a-z0-9-]+\.[a-z0-9_.-]+", cid):
            errs.append(f"{cid}: id must be <dimension>.<name> (lowercase)")
        elif cid.split(".")[0] != c["dimension"]:
            errs.append(f"{cid}: id prefix must be its dimension {c['dimension']!r} (one catalog file per dimension)")
        for k in ("title", "csf", "check", "weight"):
            if k not in c:
                errs.append(f"{cid}: {k} missing")
        if c.get("check") not in CHECKS:
            errs.append(f"{cid}: check must be one of {CHECKS}")
        if c.get("function") not in FUNCTIONS:
            errs.append(f"{cid}: csf {c.get('csf')!r} must start with one of {sorted(FUNCTIONS)}")
        if not c.get("pillars") or set(c["pillars"]) - set(PILLARS):
            errs.append(f"{cid}: pillars must be a non-empty subset of {PILLARS}")
        if not isinstance(c.get("weight"), (int, float)) or c["weight"] < 0:
            errs.append(f"{cid}: weight must be a number >= 0")
        if c.get("check") in ("automated", "evidence"):
            src = c.get("source") or {}
            if src.get("type") not in ev.EVALUATORS:
                errs.append(f"{cid}: source.type must be one of {sorted(ev.EVALUATORS)}")
        if c.get("check") == "attested" or attestable(c):
            try:
                ev.duration(c.get("validity"))
            except ValueError as e:
                errs.append(f"{cid}: validity: {e}")
            if not c.get("validity"):
                errs.append(f"{cid}: attested controls need a validity (e.g. 90d): attestations expire and reopen")
            if not c.get("question"):
                errs.append(f"{cid}: attested controls need the question a human answers")
    return errs


def attestable(c):
    """A human may attest this control: check `attested`, or an automated one with an `attestation` fallback."""
    return c.get("check") == "attested" or '"attestation"' in json.dumps(c.get("source") or {})


# ---- variables ---------------------------------------------------------------------------------------------------
VAR = re.compile(r"\$\{([a-zA-Z0-9_]+)\}")


def substitute(obj, vars_, missing):
    if isinstance(obj, str):
        def rep(m):
            if m.group(1) in vars_:
                return str(vars_[m.group(1)])
            missing.add(m.group(1))
            return m.group(0)
        return VAR.sub(rep, obj)
    if isinstance(obj, list):
        return [substitute(x, vars_, missing) for x in obj]
    if isinstance(obj, dict):
        return {k: substitute(v, vars_, missing) for k, v in obj.items()}
    return obj


# ---- attestations --------------------------------------------------------------------------------------------------
def load_attestations(data):
    p = os.path.join(data, "attestations.yaml")
    if not os.path.exists(p):
        return {}
    return (load_config(p) or {}).get("attestations") or {}


def attestation_status(c, a, now):
    """-> (status, detail, expires_epoch|None) for an attested control."""
    if not a:
        return "unattested", f"not attested: a human answers \"{c.get('question', c['title'])}\" (scorecard.py attest)", None
    if not a.get("attested_by"):
        return "unattested", "attestation without attested_by is ignored", None
    at = ev.ts(a["at"]) if a.get("at") else None
    exp = ev.ts(a["expires"]) if a.get("expires") else (at + ev.duration(c["validity"]) if at else None)
    if exp is None:
        return "unattested", "attestation without a date (at/expires) is ignored", None
    if exp <= now:
        return "expired", f"attestation by {a['attested_by']} expired {time.strftime('%Y-%m-%d', time.gmtime(exp))}: re-attest", exp
    if a.get("value") is False:
        return "fail", f"attested as NOT holding by {a['attested_by']}" + (f": {a['note']}" if a.get("note") else ""), exp
    soon = " (expires within 14 days)" if exp - now < EXPIRING_SOON else ""
    return "pass", f"attested by {a['attested_by']} until {time.strftime('%Y-%m-%d', time.gmtime(exp))}{soon}", exp


def not_applicable(a, now):
    """A control is excluded from the score only with a human's approval and an expiry (like an exception)."""
    na = (a or {}).get("not_applicable")
    if not na or not a.get("attested_by") or not a.get("expires"):
        return None
    return na if ev.ts(a["expires"]) > now else None


# ---- compute ----------------------------------------------------------------------------------------------------
class Ctx:
    def __init__(self, data, now, controls, pillars, functions):
        self.data, self.now, self.controls, self.pillars, self.functions = data, now, controls, pillars, functions
        self.ledger = ev.load_json(os.path.join(data, "ledger.json"), {})
        self.metrics = []
        mp = os.path.join(data, "metrics", "security-platform.prom")
        if os.path.exists(mp):
            from adapters import sinks
            try:
                with open(mp) as f:
                    self.metrics = [m for m in sinks.parse_text(f.read()) if not m[0].startswith("security_score")]
            except ValueError:
                self.metrics = []
        self.attestations, self.current = {}, None
        self.coverage = []          # (collector, asset, status) of the newest document of every collector
        for p in glob.glob(os.path.join(data, "latest", "*.findings.json")):
            d = ev.load_json(p, {})
            col = (d.get("collector") or {}).get("name", "")
            self.coverage += [(col, g.get("asset", ""), g.get("status")) for g in d.get("coverage") or []]
        self.runner_states = {}
        for p in glob.glob(os.path.join(data, "state", "runner", "*.json")):
            n = os.path.basename(p)[:-5]
            if n != "sinks":
                self.runner_states[n] = ev.load_json(p, {})
        for p in glob.glob(os.path.join(data, "state", "sites", "*.json")):
            for n, st in (ev.load_json(p, {}).get("jobs") or {}).items():
                self.runner_states.setdefault(n, st)


def score_of(items):
    w = sum(c["weight"] for c in items if c["_status"] != "na")
    p = sum(c["weight"] for c in items if c["_status"] in PASSING)
    return (round(100.0 * p / w, 1) if w else 0.0), w, p


def compute(data, inst=None, now=None, extra_dirs=None):
    now = now or time.time()
    sc = (inst or {}).get("scorecard") or {}
    threshold = float(sc.get("threshold", 75))
    dims, controls = load_catalog(catalog_dirs(inst, extra_dirs), inst)
    controls = [c for c in controls if not c.get("disabled")]
    vars_ = dict(data=data, product=ROOT, **{k: v for k, v in (sc.get("vars") or {}).items()})
    att = load_attestations(data)
    ctx = Ctx(data, now, controls, sc.get("pillars", PILLARS), list(FUNCTIONS))
    ctx.attestations = att
    deferred = []
    for c in controls:
        a = att.get(c["id"])
        na = not_applicable(a, now)
        c["_expires"] = None
        if na:
            c["_status"], c["_detail"] = "na", f"not applicable (approved by {a['attested_by']}): {na}"
            continue
        if c["check"] == "attested":
            c["_status"], c["_detail"], c["_expires"] = attestation_status(c, a, now)
            continue
        missing = set()
        src = substitute(c.get("source") or {}, vars_, missing)
        if missing:
            c["_status"], c["_detail"] = "unknown", f"configure scorecard.vars: {', '.join(sorted(missing))}"
            continue
        if src.get("type") in ev.DEFERRED:
            deferred.append((c, src))
            continue
        ctx.current = c
        c["_status"], c["_detail"] = ev.evaluate(ctx, src)
    for c, src in deferred:
        ctx.current = c
        c["_status"], c["_detail"] = ev.evaluate(ctx, src)

    def group(pred):
        return [c for c in controls if pred(c)]

    out_dims = {}
    for did, d in sorted(dims.items(), key=lambda kv: kv[1].get("order", 99)):
        items = group(lambda c, did=did: c["dimension"] == did)
        s, w, p = score_of(items)
        th = float(d.get("threshold", threshold))
        out_dims[did] = {"title": d["title"], "order": d.get("order"), "owner": d.get("owner"), "threshold": th,
                         "pillars": sorted({x for c in items for x in c["pillars"]}),
                         "functions": sorted({c["function"] for c in items}),
                         "score": s, "status": "PASS" if (items and s >= th) else "FAIL", "weight_total": w,
                         "weight_passed": p, "controls": len(items),
                         "failing": [c["id"] for c in items if c["_status"] not in PASSING | {"na"}]}
    pillars = {}
    for pl in ctx.pillars:
        items = group(lambda c, pl=pl: pl in c["pillars"])
        s, w, p = score_of(items)
        pillars[pl] = {"score": s, "controls": len(items), "status": "PASS" if (items and s >= threshold) else "FAIL",
                       "failing": [c["id"] for c in items if c["_status"] not in PASSING | {"na"}]}
    functions = {}
    for f, title in FUNCTIONS.items():
        items = group(lambda c, f=f: c["function"] == f)
        s, w, p = score_of(items)
        functions[f] = {"title": title, "score": s, "controls": len(items)}
    cross = {}
    for did in out_dims:
        for pl in ctx.pillars:
            items = group(lambda c, did=did, pl=pl: c["dimension"] == did and pl in c["pillars"])
            if items:
                cross[f"{did}|{pl}"] = score_of(items)[0]
    att_counts = {"valid": 0, "expiring": 0, "expired": 0, "missing": 0}
    for c in controls:
        if not attestable(c) or c["_status"] == "na" or (c["check"] != "attested" and c.get("_expires") is None
                                                           and c["_status"] not in ("unattested", "expired")):
            continue            # an automated control decided by its API counts as no attestation
        if c["_status"] == "expired":
            att_counts["expired"] += 1
        elif c["_status"] == "unattested":
            att_counts["missing"] += 1
        elif c["_expires"] and c["_expires"] - now < EXPIRING_SOON:
            att_counts["expiring"] += 1
        else:
            att_counts["valid"] += 1
    scores = [d["score"] for d in out_dims.values()]
    result = {
        "schema": SCHEMA, "scorecard_version": VERSION, "computed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "threshold": threshold, "status": "PASS" if out_dims and all(d["status"] == "PASS" for d in out_dims.values()) else "FAIL",
        "overall": min(scores) if scores else 0.0, "mean": round(sum(scores) / len(scores), 1) if scores else 0.0,
        "weakest": min(out_dims, key=lambda k: out_dims[k]["score"]) if out_dims else None,
        "dimensions": out_dims, "pillars": pillars, "functions": functions, "dimension_pillar": cross,
        "attestations": att_counts,
        "controls": [{"id": c["id"], "dimension": c["dimension"], "title": c["title"], "pillars": c["pillars"],
                      "csf": c.get("csf"), "function": c["function"], "cis": c.get("cis", []), "check": c["check"],
                      "weight": c["weight"], "status": c["_status"], "detail": c["_detail"],
                      "needs_human": bool(c.get("needs_human") or c["check"] == "attested"),
                      "attestable": attestable(c), "question": c.get("question"),
                      "remediation": c.get("remediation", ""),
                      "expires": time.strftime("%Y-%m-%d", time.gmtime(c["_expires"])) if c.get("_expires") else None}
                     for c in controls]}
    return result


# ---- regression state + outputs ------------------------------------------------------------------------------------
def update_regressions(data, result):
    """A dimension that drops below its threshold counts one regression (first sight is the baseline, like
    security_sli_new_total). The alert fires on the counter's increase, never on a standing low score."""
    p = os.path.join(data, "state", "scorecard.json")
    st = ev.load_json(p, {"below": {}, "regressions_total": {}})
    for did, d in result["dimensions"].items():
        below = d["status"] == "FAIL"
        prev = st["below"].get(did)
        st["regressions_total"].setdefault(did, 0)
        if prev is False and below:
            st["regressions_total"][did] += 1
        st["below"][did] = below
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p + ".tmp", "w") as f:
        json.dump(st, f, indent=1, sort_keys=True)
    os.replace(p + ".tmp", p)
    result["regressions_total"] = dict(st["regressions_total"])
    return result


def prom(result, now):
    s = []
    H = "Security scorecard: weighted pass ratio of the controls (0-100); the weakest dimension decides"
    for did, d in result["dimensions"].items():
        s.append(("security_score", {"dimension": did}, d["score"], H))
    for pl, d in result["pillars"].items():
        s.append(("security_score", {"pillar": pl}, d["score"], H))
    for f, d in result["functions"].items():
        if d["controls"]:
            s.append(("security_score", {"function": f}, d["score"], H))
    for k, v in sorted(result["dimension_pillar"].items()):
        did, pl = k.split("|")
        s.append(("security_score", {"dimension": did, "pillar": pl}, v, H))
    s.append(("security_score_overall", {}, result["overall"], "Overall score = the weakest dimension's score"))
    s.append(("security_score_threshold", {}, result["threshold"], "A dimension below this fails the scorecard"))
    s.append(("security_score_pass", {}, 1 if result["status"] == "PASS" else 0, "1 while every dimension meets its threshold"))
    counts = {}
    for c in result["controls"]:
        k = (c["dimension"], "pass" if c["status"] == "pass" else "na" if c["status"] == "na" else "fail")
        counts[k] = counts.get(k, 0) + 1
    for did in result["dimensions"]:
        for st in ("pass", "fail", "na"):
            s.append(("security_score_controls", {"dimension": did, "status": st}, counts.get((did, st), 0),
                      "Controls per dimension and result (details in the private scorecard report)"))
    for did, n in sorted(result.get("regressions_total", {}).items()):
        s.append(("security_score_regressions_total", {"dimension": did}, n,
                  "Times the dimension dropped below its threshold (counter; the alert fires on increases)"))
    for st, n in result["attestations"].items():
        s.append(("security_attestations", {"state": st}, n, "Attested (human) controls by state; expired ones fail again"))
    s.append(("security_scorecard_last_compute_timestamp_seconds", {}, int(now), "When the scorecard was last computed"))
    return render(s)


def markdown(r):
    L = [f"# Security scorecard {r['computed_at']}", "",
         f"**{r['status']}** - overall (weakest dimension) {r['overall']} / threshold {r['threshold']:g}; mean {r['mean']}; "
         f"weakest: {r['weakest']}.", "", "PRIVATE: failing controls are attacker intelligence.", "",
         "## Dimensions", "", "| # | dimension | score | status | pillars | CSF | failing controls |", "|---|---|---|---|---|---|---|"]
    for did, d in r["dimensions"].items():
        L.append(f"| {d['order']} | {d['title']} (`{did}`) | {d['score']} | {d['status']} | {', '.join(d['pillars'])} | "
                 f"{', '.join(d['functions'])} | {', '.join(d['failing']) or '-'} |")
    L += ["", "## Pillars", "", "| pillar | score | controls |", "|---|---|---|"]
    L += [f"| {p} | {d['score']} | {d['controls']} |" for p, d in r["pillars"].items()]
    L += ["", "## NIST CSF 2.0 functions", "", "| function | score | controls |", "|---|---|---|"]
    L += [f"| {f} {d['title']} | {d['score']} | {d['controls']} |" for f, d in r["functions"].items()]
    a = r["attestations"]
    L += ["", f"## Attestations: {a['valid']} valid, {a['expiring']} expiring within 14 days, {a['expired']} expired, "
              f"{a['missing']} missing", ""]
    L += ["## Controls", "", "| control | dim | check | w | status | detail | CIS |", "|---|---|---|---|---|---|---|"]
    order = {"fail": 0, "expired": 0, "unattested": 1, "unknown": 2, "not_implemented": 3, "pass": 5, "na": 6}
    for c in sorted(r["controls"], key=lambda c: (order.get(c["status"], 4), c["dimension"], c["id"])):
        L.append(f"| `{c['id']}` {c['title'][:70]} | {c['dimension']} | {c['check']} | {c['weight']:g} | {c['status']} | "
                 f"{str(c['detail'])[:160].replace('|', '/')} | {', '.join(map(str, c['cis']))} |")
    return "\n".join(L) + "\n"


def write_outputs(data, result, now):
    for sub in ("reports", "metrics"):
        os.makedirs(os.path.join(data, sub), exist_ok=True)

    def put(rel, text):        # private regardless of the caller's umask (failing controls are attacker intelligence)
        p = os.path.join(data, rel)
        with open(os.open(p + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
            f.write(text)
        os.replace(p + ".tmp", p)
    put("reports/scorecard.json", json.dumps(result, indent=1, sort_keys=True, ensure_ascii=False))
    put("reports/scorecard.md", markdown(result))
    put("metrics/scorecard.prom", prom(result, now))


# ---- attest ----------------------------------------------------------------------------------------------------------
def attest(data, inst, cid, by, note=None, days=None, expires=None, value=True, na=None, now=None):
    """Record a human attestation. Only a human runs this (an agent may draft the command, never execute it as the
    human): the ledger's rule for exceptions applies - no attested_by, no effect."""
    now = now or time.time()
    _, controls = load_catalog(catalog_dirs(inst), inst)
    c = next((x for x in controls if x["id"] == cid), None)
    if c is None:
        raise SystemExit(f"unknown control {cid}")
    if not attestable(c) and not na:
        raise SystemExit(f"{cid} is {c['check']} without an attestation fallback (only --not-applicable may be recorded)")
    p = os.path.join(data, "attestations.yaml")
    doc = (load_config(p) or {}) if os.path.exists(p) else {}
    doc.setdefault("schema", ATTEST_SCHEMA)
    doc.setdefault("attestations", {})
    at = time.strftime("%Y-%m-%d", time.localtime(now))
    if not expires:
        span = ev.duration(f"{days}d") if days else ev.duration(c.get("validity", "90d"))
        expires = time.strftime("%Y-%m-%d", time.localtime(now + span))
    e = {"attested_by": by, "at": at, "expires": expires}
    if na:
        e["not_applicable"] = na
    else:
        e["value"] = bool(value)
    if note:
        e["note"] = note
    doc["attestations"][cid] = e
    import yaml
    with open(os.open(p + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
        f.write("# Human attestations (security-platform scorecard). PRIVATE. Only humans edit this file:\n"
                "#   scorecard.py attest --data <dir> <control> --by <you> [--note ...] [--days N] [--false]\n")
        yaml.safe_dump(doc, f, sort_keys=True, allow_unicode=True)
    os.replace(p + ".tmp", p)
    return e


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("cmd", choices=["compute", "attest", "lint", "list", "version"])
    ap.add_argument("control", nargs="?")
    ap.add_argument("--data")
    ap.add_argument("--instance")
    ap.add_argument("--now", type=float)
    ap.add_argument("--catalog", action="append", default=[])
    ap.add_argument("--dimension")
    ap.add_argument("--by")
    ap.add_argument("--note")
    ap.add_argument("--days", type=int)
    ap.add_argument("--expires")
    ap.add_argument("--false", dest="value", action="store_false")
    ap.add_argument("--not-applicable", dest="na")
    a = ap.parse_args(argv)
    if a.cmd == "version":
        print(VERSION)
        return 0
    inst = load_config(a.instance) if a.instance else {}
    if a.cmd in ("lint", "list"):
        dims, controls = load_catalog(catalog_dirs(inst, a.catalog), inst)
        errs = lint(dims, controls)
        if a.cmd == "lint":
            for e in errs:
                print(e, file=sys.stderr)
            print(f"{len(dims)} dimensions, {len(controls)} controls, {len(errs)} error(s)", file=sys.stderr)
            return 1 if errs else 0
        for c in controls:
            if not a.dimension or c["dimension"] == a.dimension:
                print(f"{c['id']:45} {c['check']:9} w={c['weight']:<3g} {','.join(c['pillars']):24} {c.get('csf', ''):8} {c['title']}")
        return 0
    if not a.data:
        ap.error("--data is required")
    data = os.path.abspath(os.path.expanduser(a.data))
    if a.cmd == "attest":
        if not a.control or not a.by:
            ap.error("attest needs CONTROL and --by")
        e = attest(data, inst, a.control, a.by, a.note, a.days, a.expires, a.value, a.na, a.now)
        print(json.dumps({a.control: e}))
        return 0
    now = a.now or time.time()
    r = update_regressions(data, compute(data, inst, now, a.catalog))
    write_outputs(data, r, now)
    print(f"[scorecard {VERSION}] {r['status']} overall={r['overall']} weakest={r['weakest']} "
          + " ".join(f"{k}={v['score']}" for k, v in r["dimensions"].items()), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
