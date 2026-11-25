#!/usr/bin/env python3
"""core ledger: merge one run's findings documents into the private ledger, compute SLIs, write outputs.

usage: ledger.py --run <run dir> --data <private data dir> [--latest <dir>]
Inputs (contracts only): <run>/*.findings.json (schema findings/v1), <data>/exceptions.yaml (human-approved),
<data>/catalog-review.yaml (last Re-plan review dates), generators/sli-catalog.yaml.
Outputs: <data>/ledger.json, <run>/sli.prom, <data>/metrics/ledger.prom, <data>/reports/latest-auto.md, <run>/ocsf.jsonl
--latest: the newest document of EVERY collector (the runner keeps it); collector-reported metrics and coverage gaps
are computed from it, so a run of one collector does not hide the others' numbers.
Lifecycle rules (docs/design.md section 1): only a run that COVERED the asset can mark a finding fixed;
only a human (exceptions.yaml) can make it `accepted`; expired exceptions reopen it.
Retired assets: an "ok" coverage entry with `complete_scope: <asset prefix>` declares that the run listed EVERY existing
asset under that prefix (an authoritative, complete inventory). A finding of that collector on an asset under the
prefix that the run neither covered nor reported as a gap belongs to an asset that no longer exists: it is closed as
fixed with `fixed_reason: asset_retired`. No declaration (partial or failed inventory, older collectors) = unknown.
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


# An "ok" coverage entry of these types also covers findings on sub-assets of other types with the same scope
# (e.g. host:h covers secret-file:h:<path>; k8s-cluster:c covers k8s-workload:c/...). Everything else must match
# exactly or as a prefix (net-endpoint:h@ip covers net-endpoint:h@ip:443).
UMBRELLA = {"host": ("secret-file",), "k8s-cluster": ("k8s-workload", "k8s-namespace", "k8s-identity", "k8s-cluster", "cis")}


def scope(asset):
    typ, _, rest = asset.partition(":")
    for i, ch in enumerate(rest):
        if ch in "/:@":
            return typ, rest[:i]
    return typ, rest


class Coverage:
    """The "ok" coverage entries of one run, indexed so that a lookup costs O(len(asset)) instead of O(len(oks)).
    Same rules as before (bench/scale.py measured the linear scan at minutes per run for 100k findings):
      - exact match, or an entry that is a prefix of the asset ending right before one of ":/@";
      - an UMBRELLA entry (host:h, k8s-cluster:c) covers its sub-asset types with the same scope."""

    def __init__(self, oks):
        self.exact = set(oks)
        self.umbrella = {scope(c) for c in self.exact if c.partition(":")[0] in UMBRELLA}

    def __contains__(self, asset):
        if asset in self.exact:
            return True
        for i, ch in enumerate(asset):
            if ch in ":/@" and asset[:i] in self.exact:
                return True
        t, sc = scope(asset)
        return any(t in sub and (ct, sc) in self.umbrella for ct, sub in UMBRELLA.items())


def covered(asset, oks, gap_names):
    """A finding may be marked fixed only if this run COVERED its asset (design §1: no coverage = unknown).
    `oks`: a list of coverage assets or a prebuilt Coverage (reuse one per document: large runs)."""
    if any(g and g in asset for g in gap_names):
        return False
    return asset in (oks if isinstance(oks, Coverage) else Coverage(oks))


def retired(asset, scopes, listed, gap_names):
    """The asset is under a scope the run inventoried COMPLETELY (`complete_scope` of an ok coverage entry) and the run
    did not list it at all (neither ok nor gap): it no longer exists. Any gap that may concern it wins (unknown)."""
    if not any(asset.startswith(sc) for sc in scopes) or any(g and g in asset for g in gap_names):
        return False
    return asset not in listed


def urgent(e):
    """The time-to-know objective's class: KEV, or critical/high (base or prioritized)."""
    at = e.get("attributes") or {}
    return bool(at.get("kev")) or e["severity"] in ("critical", "high") or at.get("base_severity") == "critical"


def asset_class(asset):
    typ = asset.split(":", 1)[0]
    return typ if typ in ("image", "repo", "host") else "other"


def selected(e, sel):
    at = e.get("attributes") or {}
    return (("check_in" not in sel or e["check"] in sel["check_in"])
            and ("check_prefix" not in sel or any(e["check"].startswith(x) for x in sel["check_prefix"]))
            and ("severity_in" not in sel or e["severity"] in sel["severity_in"])
            and ("layer_in" not in sel or e["layer"] in sel["layer_in"])
            and ("kind" not in sel or e["kind"] == sel["kind"])
            and ("kind_not" not in sel or e["kind"] != sel["kind_not"])
            and ("attr_true" not in sel or at.get(sel["attr_true"]))
            and ("attr_any_true" not in sel or any(at.get(x) for x in sel["attr_any_true"])))


def load_yaml(p, default):
    if not os.path.exists(p):
        return default
    import yaml
    return yaml.safe_load(open(p)) or default


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)
    ap.add_argument("--data", required=True)
    ap.add_argument("--latest")
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
    cov_seen = ledger.setdefault("coverage_seen", {})   # collector -> assets it has covered before (time-to-know baseline)
    for d in docs:
        col = d["collector"]["name"]
        gap_names = [g["asset"].split(":", 1)[-1] for g in d["coverage"] if g["status"] == "gap"]
        gaps_total += len(gap_names)
        seen = set()
        prev_ok = cov_seen.get(col, [])
        prev_cov = Coverage(prev_ok)
        for f in d["findings"]:
            seen.add(f["id"])
            e = E.get(f["id"])
            if e is None:
                # time-to-know counts only what appears on an asset this collector had ALREADY covered: the first
                # inventory of a new asset (or the first run of a new check source) is a baseline, not a detection delay
                e = E[f["id"]] = dict(first_seen=f["observed_at"], status="open", fixed_at=None, reopened_count=0,
                                      ttk_counted=bool(prev_ok) and f["asset"] in prev_cov)
            elif e["status"] == "fixed":
                e.update(status="open", fixed_at=None, fixed_reason=None, reopened_count=e.get("reopened_count", 0) + 1,
                         time_to_fix_days=None)
            e.update({k: f[k] for k in ("id", "check", "layer", "asset", "title", "severity", "evidence", "remediation",
                                       "needs_human", "owner", "kind")},
                     refs=f.get("refs", []), attributes=f.get("attributes", {}), collector=col,
                     collector_version=d["collector"]["version"], last_seen=f["observed_at"])
            at = e["attributes"]
            if e["kind"] == "vulnerability" and (at.get("cve") or at.get("advisory")):
                disclosed = max([x for x in (at.get("published_at"), at.get("kev_added")) if x] or [None])
                if disclosed:
                    e["disclosed_at"] = disclosed
                    e["time_to_know_hours"] = round(max(0, t(e["first_seen"]) - t(disclosed)) / 3600, 1)
        oks = [g["asset"] for g in d["coverage"] if g["status"] == "ok"]
        cov_seen[col] = sorted(set(prev_ok) | set(oks))
        scopes = [g["complete_scope"] for g in d["coverage"] if g["status"] == "ok" and g.get("complete_scope")]
        listed = Coverage([g["asset"] for g in d["coverage"]]) if scopes else None   # ok AND gap entries
        oks = Coverage(oks)
        for fid_, e in E.items():
            if e.get("collector") != col or fid_ in seen or e["status"] not in ("open", "accepted"):
                continue
            if covered(e["asset"], oks, gap_names):
                reason = "not_observed"
            elif scopes and retired(e["asset"], scopes, listed, gap_names):
                reason = "asset_retired"
            else:
                continue  # not covered this time (gap, offline, or simply out of this run's scope): keep state
            e.update(status="fixed", fixed_at=d["run"]["finished_at"], fixed_reason=reason,
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
    cur_docs = docs
    if a.latest:
        cur_docs = []
        for p in sorted(glob.glob(os.path.join(a.latest, "*.findings.json"))):
            d = json.load(open(p))
            if not validate.validate_findings(d):
                cur_docs.append(d)
    # coverage exceptions: a gap a HUMAN accepted for a while (an offline personal device declared out of scope, a
    # device waiting for a credential). Same rules as finding exceptions: approved_by + expires, else ignored;
    # expired = counted again. Keyed by the coverage asset, optionally "<collector>|<asset>".
    cexc = load_yaml(os.path.join(a.data, "exceptions.yaml"), {}).get("coverage_exceptions") or {}
    gaps_total, gaps_excepted, cexc_expired, gaps_by_col = 0, 0, 0, {}
    for d in cur_docs:
        gaps_by_col.setdefault(d["collector"]["name"], 0)
        for g in d["coverage"]:
            if g["status"] != "gap":
                continue
            x = cexc.get(f"{d['collector']['name']}|{g['asset']}") or cexc.get(g["asset"])
            if x and x.get("approved_by") and x.get("expires"):
                if t(str(x["expires"])) > time.time():
                    gaps_excepted += 1
                    continue
                cexc_expired += 1
            gaps_total += 1
            gaps_by_col[d["collector"]["name"]] += 1
    for d in cur_docs:
        for m in d.get("metrics", []):
            metrics.setdefault(m["name"], []).append(m["value"])
    # platform health per collector: the last run that covered at least one asset ("no findings != secure")
    cols = ledger.setdefault("collectors", {})
    for d in docs:
        c = cols.setdefault(d["collector"]["name"], {})
        c["last_run"] = d["run"]["finished_at"]
        if any(g["status"] == "ok" for g in d["coverage"]):
            c["last_good_run"] = d["run"]["finished_at"]
    openE = [e for e in E.values() if e["status"] == "open"]
    ttk_recent = [e for e in E.values() if e.get("ttk_counted") and e.get("time_to_know_hours") is not None
                  and time.time() - t(e["first_seen"]) < 30 * 86400]
    review = load_yaml(os.path.join(a.data, "catalog-review.yaml"), {})
    last_review = review.get("last_reviewed")
    computed = {
        "oldest_fixable_critical_cve_days": max([(time.time() - t(e["attributes"]["published_at"])) / 86400 for e in openE
                                                 if e["kind"] == "vulnerability" and e["attributes"].get("base_severity") == "critical"
                                                 and e["attributes"].get("fixed") and e["attributes"].get("published_at")] or [0]),
        "coverage_gaps": gaps_total,
        "check_catalog_age_days": (time.time() - t(str(last_review))) / 86400 if last_review else -1,
        "time_to_know_hours_max_30d": max([e["time_to_know_hours"] for e in ttk_recent if urgent(e)] or [0]),
    }
    sli = {}
    for s in catalog["slis"]:
        src = s["source"]
        if "findings" in src:
            sel = src["findings"]
            members = sorted(e["id"] for e in openE if selected(e, sel))
            v = len(members)
            prev = ledger.setdefault("sli_members", {}).get(s["name"])
            cnt = ledger.setdefault("sli_new_total", {})
            if prev is not None:        # first sight of an SLI = baseline, not "new"
                cnt[s["name"]] = cnt.get(s["name"], 0) + len(set(members) - set(prev))
            else:
                cnt.setdefault(s["name"], 0)
            ledger["sli_members"][s["name"]] = members
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
    series += [("security_sli_ok", {"sli": k}, 1 if v["ok"] else 0, "1 while the SLI meets its objective (slo-platform bool SLI)")
               for k, v in sli.items()]
    series += [("security_sli_new_total", {"sli": k}, n, "Findings that ENTERED the SLI's set (new or reopened; counter)")
               for k, n in sorted(ledger.get("sli_new_total", {}).items())]
    for col, c in sorted(cols.items()):
        if c.get("last_good_run"):
            series.append(("security_collector_last_good_run_timestamp_seconds", {"collector": col}, int(t(c["last_good_run"])),
                           "Last run that covered at least one asset (a blind run does not count)"))
    series += [("security_findings_reopened_total", {}, sum(e.get("reopened_count", 0) for e in E.values()),
                "Regressions: fixed findings that came back (counter)"),
               ("security_exceptions_active", {}, sum(1 for e in E.values() if e["status"] == "accepted"), "Active exceptions"),
               ("security_exceptions_expired", {}, expired + cexc_expired, "Exceptions past expiry (finding reopened / gap counted again)"),
               ("security_coverage_gaps_excepted", {}, gaps_excepted, "Coverage gaps under a human-approved, unexpired exception"),
              ] + [("security_coverage_gaps_open", {"collector": k}, v, "Coverage gaps not under an exception, per collector (latest documents)")
                   for k, v in sorted(gaps_by_col.items())] + [
               ("security_time_to_fix_days", {"quantile": "0.5"}, statistics.median(fixed) if fixed else 0, "Time to fix"),
               ("security_time_to_fix_days", {"quantile": "1"}, max(fixed) if fixed else 0, "Time to fix"),
               ("security_contract_invalid_documents", {}, len(invalid), "Findings documents rejected by schema validation"),
               ("security_ledger_last_update_timestamp_seconds", {}, int(time.time()), "Ledger heartbeat")]
    by_cls = {}
    for e in ttk_recent:
        by_cls.setdefault((asset_class(e["asset"]), "urgent" if urgent(e) else "other"), []).append(e["time_to_know_hours"])
    for (cls, pr), v in sorted(by_cls.items()):
        series += [("security_time_to_know_hours", {"asset_class": cls, "priority": pr, "quantile": q}, val,
                    "Advisory/KEV publication -> first detection on an already-covered asset (last 30 days)")
                   for q, val in (("0.5", statistics.median(v)), ("1", max(v)))]
        series.append(("security_time_to_know_detections", {"asset_class": cls, "priority": pr}, len(v),
                       "Detections counted for time-to-know (last 30 days)"))
    with open(os.path.join(a.run, "sli.prom"), "w") as f:
        f.write(render(series))
    os.makedirs(os.path.join(a.data, "metrics"), exist_ok=True)
    with open(os.path.join(a.data, "metrics", "ledger.prom.tmp"), "w") as f:
        f.write(render(series))
    os.replace(os.path.join(a.data, "metrics", "ledger.prom.tmp"), os.path.join(a.data, "metrics", "ledger.prom"))
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
    if os.path.exists(lp + ".tmp"):
        os.remove(lp + ".tmp")
    with open(os.open(lp + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:   # 0600 whatever the umask
        json.dump(ledger, f, indent=1, sort_keys=True, ensure_ascii=False)
    os.replace(lp + ".tmp", lp)
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
