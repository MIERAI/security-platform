#!/usr/bin/env python3
"""generators: SLI catalog -> Prometheus rules, Grafana dashboard, slo-platform SLO drafts (component `generators`).

usage: gen.py [--out dist]        Depends only on the SLI catalog and metric names (the contract), never on collectors.
Outputs are DRAFTS for an instance's GitOps repo; nothing here deploys anything.
"""
import argparse
import json
import os

import yaml

HERE = os.path.dirname(__file__)
VERSION = open(os.path.join(HERE, "VERSION")).read().strip()


def rules(cat):
    groups = [{"name": "security-platform.sli", "rules": []}, {"name": "security-platform.health", "rules": []}]
    for s in cat["slis"]:
        al = s.get("alert", {})
        groups[0]["rules"].append({
            "alert": "SecuritySLOBreach_" + s["name"],
            "expr": f'max(security_sli{{sli="{s["name"]}"}}) > {s["objective"]["target"]}',
            "for": al.get("for", "1h"),
            "labels": {"severity": al.get("severity", "ticket"), "component": "security-platform", "sli": s["name"]},
            "annotations": {"summary": f'Security SLI {s["name"]} above objective ({s["objective"]["target"]})',
                            "description": s["description"] + " - value {{ $value }}. Details: the private ledger.",
                            "runbook": "docs/runbooks.md#slo-breach"}})
    groups[1]["rules"] += [
        {"alert": "SecurityFindingRegression", "expr": "increase(security_findings_reopened_total[1d]) > 0", "for": "0m",
         "labels": {"severity": "ticket", "component": "security-platform"},
         "annotations": {"summary": "A fixed security finding came back (regression) - write a postmortem",
                         "runbook": "docs/runbooks.md#regression"}},
        {"alert": "SecurityCollectorStale",
         "expr": "time() - max by (collector) (security_collector_last_run_timestamp_seconds) > 2 * 86400", "for": "1h",
         "labels": {"severity": "ticket", "component": "security-platform"},
         "annotations": {"summary": "Collector {{ $labels.collector }} has not run for 2 days: no findings != secure",
                         "runbook": "docs/runbooks.md#collector-stale"}},
        {"alert": "SecurityLedgerStale", "expr": "time() - security_ledger_last_update_timestamp_seconds > 2 * 86400",
         "for": "1h", "labels": {"severity": "ticket", "component": "security-platform"},
         "annotations": {"summary": "Security ledger not updated for 2 days"}},
        {"alert": "SecurityContractViolation", "expr": "security_contract_invalid_documents > 0", "for": "0m",
         "labels": {"severity": "ticket", "component": "security-platform"},
         "annotations": {"summary": "A collector emitted a findings document that fails the schema (it was ignored)"}},
        {"alert": "SecurityIntelFeedStale", "expr": "max by (feed) (security_intel_feed_age_seconds) > 3 * 86400", "for": "1h",
         "labels": {"severity": "ticket", "component": "security-platform"},
         "annotations": {"summary": "Threat-intel feed {{ $labels.feed }} older than 3 days"}},
        {"alert": "SecurityExceptionExpired", "expr": "security_exceptions_expired > 0", "for": "0m",
         "labels": {"severity": "ticket", "component": "security-platform"},
         "annotations": {"summary": "A risk acceptance expired; the finding is open again - renew (human) or fix"}},
    ]
    return {"apiVersion": "monitoring.coreos.com/v1", "kind": "PrometheusRule",
            "metadata": {"name": "security-platform", "labels": {"app.kubernetes.io/part-of": "security-platform",
                                                                 "security-platform/generator-version": VERSION}},
            "spec": {"groups": groups}}


def panel(pid, title, expr, kind="stat", x=0, y=0, w=6, h=4, legend=None, unit=None, thresholds=None):
    p = {"id": pid, "type": kind, "title": title, "gridPos": {"x": x, "y": y, "w": w, "h": h},
         "datasource": {"type": "prometheus", "uid": "${datasource}"},
         "targets": [{"refId": "A", "expr": expr, **({"legendFormat": legend} if legend else {})}],
         "fieldConfig": {"defaults": {**({"unit": unit} if unit else {}),
                                      "thresholds": thresholds or {"mode": "absolute", "steps": [
                                          {"color": "green", "value": None}, {"color": "red", "value": 1}]}}, "overrides": []},
         "options": {}}
    if kind == "timeseries":
        p["fieldConfig"]["defaults"]["custom"] = {"stacking": {"mode": "normal"}, "fillOpacity": 30}
    return p


def dashboard(cat):
    ps, pid, y = [], 1, 0
    ps.append({"id": pid, "type": "row", "title": "Security SLOs (value / objective)", "gridPos": {"x": 0, "y": y, "w": 24, "h": 1}})
    y += 1
    for i, s in enumerate(cat["slis"]):
        pid += 1
        t = s["objective"]["target"]
        ps.append(panel(pid, s["name"], f'max(security_sli{{sli="{s["name"]}"}})', x=(i % 5) * 4 + (i % 5 > 3) * 0, y=y + (i // 5) * 4, w=4,
                        thresholds={"mode": "absolute", "steps": [{"color": "green", "value": None},
                                                                  {"color": "red", "value": t + (1 if t == 0 else 0.001)}]}))
    y += ((len(cat["slis"]) + 4) // 5) * 4
    pid += 1
    ps.append({"id": pid, "type": "row", "title": "Findings (aggregates only; details stay in the private ledger)",
               "gridPos": {"x": 0, "y": y, "w": 24, "h": 1}})
    y += 1
    pid += 1
    ps.append(panel(pid, "Open findings by layer", 'sum by (layer) (security_findings{status="open"})', "timeseries", 0, y, 12, 8, "{{layer}}"))
    pid += 1
    ps.append(panel(pid, "Open findings by severity", 'sum by (severity) (security_findings{status="open"})', "timeseries", 12, y, 12, 8, "{{severity}}"))
    y += 8
    pid += 1
    ps.append(panel(pid, "Regressions (reopened, total)", "max(security_findings_reopened_total)", x=0, y=y, w=6))
    pid += 1
    ps.append(panel(pid, "Time to fix p50 (days)", 'max(security_time_to_fix_days{quantile="0.5"})', x=6, y=y, w=6,
                    thresholds={"mode": "absolute", "steps": [{"color": "green", "value": None}, {"color": "orange", "value": 7}]}))
    pid += 1
    ps.append(panel(pid, "Active exceptions", "max(security_exceptions_active)", x=12, y=y, w=6,
                    thresholds={"mode": "absolute", "steps": [{"color": "green", "value": None}]}))
    pid += 1
    ps.append(panel(pid, "Expired exceptions", "max(security_exceptions_expired)", x=18, y=y, w=6))
    y += 4
    pid += 1
    ps.append({"id": pid, "type": "row", "title": "Platform health (inner loop)", "gridPos": {"x": 0, "y": y, "w": 24, "h": 1}})
    y += 1
    pid += 1
    ps.append(panel(pid, "Collector age (hours) - no findings != secure",
                    "(time() - max by (collector) (security_collector_last_run_timestamp_seconds)) / 3600", "bargauge", 0, y, 12, 8,
                    "{{collector}}", thresholds={"mode": "absolute", "steps": [{"color": "green", "value": None},
                                                                               {"color": "orange", "value": 26},
                                                                               {"color": "red", "value": 48}]}))
    pid += 1
    ps.append(panel(pid, "Coverage gaps by collector", "max by (collector) (security_collector_gaps)", "bargauge", 12, y, 12, 8, "{{collector}}"))
    y += 8
    pid += 1
    ps.append(panel(pid, "Intel feed age (hours)", "max by (feed) (security_intel_feed_age_seconds) / 3600", "bargauge", 0, y, 12, 6, "{{feed}}",
                    thresholds={"mode": "absolute", "steps": [{"color": "green", "value": None}, {"color": "red", "value": 72}]}))
    pid += 1
    ps.append(panel(pid, "Invalid findings documents", "max(security_contract_invalid_documents)", x=12, y=y, w=12, h=6))
    return {"uid": "security-platform", "title": "Security platform (SRE way)", "schemaVersion": 39, "version": 1,
            "tags": ["security-platform", f"generator-{VERSION}"], "time": {"from": "now-30d", "to": "now"},
            "templating": {"list": [{"name": "datasource", "type": "datasource", "query": "prometheus", "label": "Prometheus"}]},
            "panels": ps}


def slo_drafts(cat):
    """slo-platform `slos:` drafts. slo-platform has no 'gauge <= N' SLI type yet; `age` over a heartbeat metric
    expresses "the good state was seen recently". The threshold form is recorded as a feature request."""
    out = {"app": "security-platform", "env": "<instance>", "note": "DRAFT for slo-platform (do not deploy in phase 0)",
           "slos": [
               {"name": "security-collectors-fresh", "objective": 99, "description": "every collector ran in the last 26h",
                "severities": {"fastBurn": "ticket", "mediumBurn": "ticket"},
                "age": {"metric": "security_collector_last_run_timestamp_seconds", "matchers": "", "max": "26h"}},
               {"name": "security-ledger-fresh", "objective": 99, "description": "ledger updated in the last 26h",
                "severities": {"fastBurn": "ticket", "mediumBurn": "ticket"},
                "age": {"metric": "security_ledger_last_update_timestamp_seconds", "matchers": "", "max": "26h"}}],
           "requested_slo_platform_feature": {
               "type": "threshold", "why": "security SLIs are gauges that must stay <= N (e.g. unauth services = 0)",
               "proposed": {s["name"]: {"metric": f'security_sli{{sli="{s["name"]}"}}', "max": s["objective"]["target"]}
                            for s in cat["slis"]}}}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(HERE, "..", "dist"))
    a = ap.parse_args()
    cat = yaml.safe_load(open(os.path.join(HERE, "sli-catalog.yaml")))
    os.makedirs(a.out, exist_ok=True)
    yaml.safe_dump(rules(cat), open(os.path.join(a.out, "prometheus-rules.yaml"), "w"), sort_keys=False, allow_unicode=True)
    json.dump(dashboard(cat), open(os.path.join(a.out, "grafana-dashboard.json"), "w"), indent=1)
    yaml.safe_dump(slo_drafts(cat), open(os.path.join(a.out, "slo-platform-slos.draft.yaml"), "w"), sort_keys=False)
    print(f"[generators {VERSION}] wrote {a.out}")


if __name__ == "__main__":
    main()
