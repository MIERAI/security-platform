#!/usr/bin/env python3
"""core ledger: merge one run's findings documents into the private ledger, compute SLIs, write outputs.

usage: ledger.py --run <run dir> --data <private data dir>
Inputs (contracts only): <run>/*.findings.json (schema findings/v1), <data>/exceptions.yaml (human-approved),
<data>/catalog-review.yaml (last Re-plan review dates), generators/sli-catalog.yaml.
Outputs: <data>/ledger.json, <run>/sli.prom, <run>/ledger.prom, <data>/reports/latest-auto.md, <run>/ocsf.jsonl
Lifecycle rules (docs/design.md section 1): only a run that COVERED the asset can mark a finding fixed;
only a human (exceptions.yaml) can make it `accepted`; expired exceptions reopen it.
"""
import argparse
import glob
import json
import os
import statistics
import sys
import time

HERE = os.path.dirname(__file__)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "sdk"))
import ocsf  # noqa: E402
import validate  # noqa: E402
from spsdk import render  # noqa: E402

VERSION = open(os.path.join(HERE, "VERSION")).read().strip()


def t(s):
    return time.mktime(time.strptime(s[:19], "%Y-%m-%dT%H:%M:%S")) - time.timezone if "T" in s else \
        time.mktime(time.strptime(s[:10], "%Y-%m-%d")) - time.timezone


def load_yaml(p, default):
    if not os.path.exists(p):
        return default
    import yaml
    return yaml.safe_load(open(p)) or default


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)
    ap.add_argument("--data", required=True)
    a = ap.parse_args()
    lp = os.path.join(a.data, "ledger.json")
    ledger = json.load(open(lp)) if os.path.exists(lp) else {"schema": "security-platform/ledger/v1", "entries": {}, "runs": []}
    E = ledger["entries"]
    now_s = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    docs, invalid = [], {}
    for p in sorted(glob.glob(os.path.join(a.run, "*.findings.json"))):
        d = json.load(open(p))
        errs = validate.validate_findings(d)
        if errs:
            invalid[os.path.basename(p)] = errs[:5]
            continue
        docs.append(d)
    gaps_total = 0
    for d in docs:
        col = d["collector"]["name"]
        gap_names = [g["asset"].split(":", 1)[-1] for g in d["coverage"] if g["status"] == "gap"]
        gaps_total += len(gap_names)
        seen = set()
        for f in d["findings"]:
            seen.add(f["id"])
            e = E.get(f["id"])
            if e is None:
                e = E[f["id"]] = dict(first_seen=f["observed_at"], status="open", fixed_at=None, reopened_count=0)
            elif e["status"] == "fixed":
                e.update(status="open", fixed_at=None, reopened_count=e.get("reopened_count", 0) + 1,
                         time_to_fix_days=None)
            e.update({k: f[k] for k in ("id", "check", "layer", "asset", "title", "severity", "evidence", "remediation",
                                       "needs_human", "owner", "kind")},
                     refs=f.get("refs", []), attributes=f.get("attributes", {}), collector=col,
                     collector_version=d["collector"]["version"], last_seen=f["observed_at"])
            at = e["attributes"]
            if e["kind"] == "vulnerability" and at.get("cve"):
                disclosed = max([x for x in (at.get("published_at"), at.get("kev_added")) if x] or [None])
                if disclosed:
                    e["disclosed_at"] = disclosed
                    e["time_to_know_hours"] = round(max(0, t(e["first_seen"]) - t(disclosed)) / 3600, 1)
        for fid_, e in E.items():
            if e.get("collector") != col or fid_ in seen or e["status"] not in ("open",):
                continue
            if any(g and g in e["asset"] for g in gap_names):
                continue  # not covered this time: unknown, keep state
            e.update(status="fixed", fixed_at=d["run"]["finished_at"],
                     time_to_fix_days=round((t(d["run"]["finished_at"]) - t(e["first_seen"])) / 86400, 2))
    # exceptions: human-approved only, with expiry
    exc = load_yaml(os.path.join(a.data, "exceptions.yaml"), {}).get("exceptions", {})
    expired = 0
    for fid_, x in exc.items():
        e = E.get(fid_)
        if not e or e["status"] == "fixed":
            continue
        if not x.get("approved_by") or not x.get("expires"):
            continue  # an exception without a human and an expiry is ignored
        if t(str(x["expires"])) > time.time():
            e.update(status="accepted", exception={k: str(v) for k, v in x.items()})
        else:
            expired += 1
            e.update(status="open", exception=dict({k: str(v) for k, v in x.items()}, expired=True))
    # ---- SLIs ----------------------------------------------------------------------------------------------
    catalog = load_yaml(os.path.join(HERE, "..", "generators", "sli-catalog.yaml"), {"slis": []})
    metrics = {}
    for p in glob.glob(os.path.join(a.run, "*.findings.json")):
        for m in json.load(open(p)).get("metrics", []):
            metrics.setdefault(m["name"], []).append(m["value"])
    openE = [e for e in E.values() if e["status"] == "open"]
    review = load_yaml(os.path.join(a.data, "catalog-review.yaml"), {})
    last_review = review.get("last_reviewed")
    computed = {
        "oldest_fixable_critical_cve_days": max([(time.time() - t(e["attributes"]["published_at"])) / 86400 for e in openE
                                                 if e["kind"] == "vulnerability" and e["attributes"].get("base_severity") == "critical"
                                                 and e["attributes"].get("fixed") and e["attributes"].get("published_at")] or [0]),
        "coverage_gaps": gaps_total,
        "check_catalog_age_days": (time.time() - t(str(last_review))) / 86400 if last_review else -1,
    }
    sli = {}
    for s in catalog["slis"]:
        src = s["source"]
        if "findings" in src:
            sel = src["findings"]
            v = sum(1 for e in openE
                    if ("check_in" not in sel or e["check"] in sel["check_in"])
                    and ("severity_in" not in sel or e["severity"] in sel["severity_in"])
                    and ("kind" not in sel or e["kind"] == sel["kind"])
                    and ("attr_true" not in sel or e["attributes"].get(sel["attr_true"])))
        elif "metric" in src:
            vals = metrics.get(src["metric"]["name"], [])
            v = (max if src["metric"].get("agg") == "max" else sum)(vals) if vals else 0
        else:
            v = computed[src["ledger"]]
        sli[s["name"]] = dict(value=round(v, 1), target=s["objective"]["target"], ok=v <= s["objective"]["target"],
                              description=s["description"])
    fixed = [e["time_to_fix_days"] for e in E.values() if e.get("time_to_fix_days") is not None]
    series = [("security_sli", {"sli": k}, v["value"], "Security SLI current value") for k, v in sli.items()]
    series += [("security_sli_objective", {"sli": k}, v["target"], "Security SLI objective (value must stay <=)") for k, v in sli.items()]
    counts = {}
    for e in E.values():
        k = (e["layer"], e["severity"], e["status"])
        counts[k] = counts.get(k, 0) + 1
    series += [("security_findings", {"layer": l, "severity": s, "status": st}, n, "Ledger entries by layer/severity/status")
               for (l, s, st), n in sorted(counts.items())]
    series += [("security_findings_reopened_total", {}, sum(e.get("reopened_count", 0) for e in E.values()),
                "Regressions: fixed findings that came back (counter)"),
               ("security_exceptions_active", {}, sum(1 for e in E.values() if e["status"] == "accepted"), "Active exceptions"),
               ("security_exceptions_expired", {}, expired, "Exceptions past expiry (finding reopened)"),
               ("security_time_to_fix_days", {"quantile": "0.5"}, statistics.median(fixed) if fixed else 0, "Time to fix"),
               ("security_time_to_fix_days", {"quantile": "1"}, max(fixed) if fixed else 0, "Time to fix"),
               ("security_contract_invalid_documents", {}, len(invalid), "Findings documents rejected by schema validation"),
               ("security_ledger_last_update_timestamp_seconds", {}, int(time.time()), "Ledger heartbeat")]
    with open(os.path.join(a.run, "sli.prom"), "w") as f:
        f.write(render(series))
    # cat all collector .prom + sli.prom => one file for textfile/remote_write
    with open(os.path.join(a.run, "all.prom"), "w") as f:
        for p in sorted(glob.glob(os.path.join(a.run, "*.prom"))):
            if not p.endswith("all.prom"):
                f.write(open(p).read())
    with open(os.path.join(a.run, "ocsf.jsonl"), "w") as f:
        for e in E.values():
            f.write(json.dumps(ocsf.to_ocsf(e)) + "\n")
    ledger["runs"].append({"at": now_s, "run_dir": os.path.relpath(a.run, a.data), "core": VERSION,
                           "collectors": {d["collector"]["name"]: d["collector"]["version"] for d in docs},
                           "invalid": invalid})
    ledger["sli"] = sli
    ledger["updated_at"] = now_s
    json.dump(ledger, open(lp, "w"), indent=1, sort_keys=True, ensure_ascii=False)
    report(a.data, ledger)
    print(f"[ledger {VERSION}] entries={len(E)} open={len(openE)} invalid_docs={len(invalid)} gaps={gaps_total}", file=sys.stderr)
    for k, v in sli.items():
        print(f"  SLI {k} = {v['value']} (<= {v['target']}) {'OK' if v['ok'] else 'BREACH'}", file=sys.stderr)


def report(data, ledger):
    E = ledger["entries"].values()
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    rows = sorted([e for e in E if e["status"] == "open"], key=lambda e: (order[e["severity"]], e["layer"], e["asset"]))
    os.makedirs(os.path.join(data, "reports"), exist_ok=True)
    with open(os.path.join(data, "reports", "latest-auto.md"), "w") as f:
        f.write(f"# Ledger (auto) {ledger['updated_at']}\n\nPRIVATE - attacker intelligence. Do not publish.\n\n## SLIs\n\n"
                "| SLI | value | objective | state |\n|---|---|---|---|\n")
        for k, v in ledger["sli"].items():
            f.write(f"| {k} | {v['value']} | <= {v['target']} | {'OK' if v['ok'] else '**BREACH**'} |\n")
        f.write("\n## Open findings\n\n| sev | layer | asset | title | needs human | id |\n|---|---|---|---|---|---|\n")
        for e in rows:
            f.write(f"| {e['severity']} | {e['layer']} | `{e['asset'][:80]}` | {e['title'][:120].replace('|', '/')} | "
                    f"{'yes' if e['needs_human'] else ''} | {e['id']} |\n")


if __name__ == "__main__":
    main()
