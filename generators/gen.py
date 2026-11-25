#!/usr/bin/env python3
"""generators: SLI catalog -> Prometheus rules, Grafana dashboard, slo-platform SLOs (component `generators`).

usage: gen.py [--out dist] [--instance <instance.yaml>] [--app security-platform] [--env prod]
Depends only on the SLI catalog and metric names (the contract), never on collectors. With --instance, the collectors
of the instance's runner jobs get one freshness SLO each; without it, every collector in the product does.
Outputs (nothing here deploys anything; an instance copies them into its GitOps repository):
  prometheus-rules.yaml       PrometheusRule: REGRESSION-ONLY alerts (labels severity page|ticket, like any other alert)
  grafana-dashboard.json      the dashboard (aggregates only: no finding, asset or address ever reaches it)
  grafana-dashboard.configmap.yaml   the same as a ConfigMap for Grafana's sidecar (label grafana_dashboard)
  slo-platform-slos.yaml      values for slo-platform's SLO chart (platform/slo): `age` + `bool` SLIs
Every alert keeps the `namespace` label (aggregations are `by (namespace, ...)`), so routing that depends on it
(e.g. slo-platform: silent for -dev/-staging) applies unchanged.
"""
import argparse
import glob
import json
import os
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
VERSION = open(os.path.join(HERE, "VERSION")).read().strip()
RUNBOOK = "docs/runbooks.md"   # --runbook-url: the instance points it at its copy of the docs
COMMON = {"component": "security-platform"}


def alert(name, expr, sev, summary, runbook, for_="0m", description=None, extra=None):
    a = {"alert": name, "expr": expr, "for": for_, "labels": dict(COMMON, severity=sev, **(extra or {})),
         "annotations": {"summary": summary, "runbook_url": f"{RUNBOOK}#{runbook}"}}
    if description:
        a["annotations"]["description"] = description
    return a


def rules(cat):
    reg = []
    for s in cat["slis"]:
        al = s.get("alert")
        if not al:
            continue
        if al.get("trigger") != "increase":
            raise ValueError(f"sli {s['name']}: alerts are regression-only (alert.trigger: increase)")
        reg.append(alert(
            "SecurityRegression_" + s["name"],
            f'sum by (namespace) (increase(security_sli_new_total{{sli="{s["name"]}"}}[{al.get("window", "3h")}])) > 0',
            al.get("severity", "ticket"), al.get("summary", f"New findings in {s['name']}"), "regression",
            description=s["description"] + ". Details only in the private ledger / digest.", extra={"sli": s["name"]}))
    reg.append(alert("SecurityScoreRegression",
                     "sum by (namespace, dimension) (increase(security_score_regressions_total[3h])) > 0", "ticket",
                     "Security scorecard: dimension {{ $labels.dimension }} dropped below its threshold (the weakest link decides)",
                     "score-regression",
                     description="Failing controls are listed in the private scorecard report (reports/scorecard.md) and the digest."))
    reg.append(alert("SecurityFindingRegression",
                     "sum by (namespace) (increase(security_findings_reopened_total[3h])) > 0", "ticket",
                     "A fixed security finding came back (regression): write a postmortem", "regression"))
    health = [
        alert("SecurityCollectorStale",
              "time() - max by (namespace, collector) (security_collector_last_good_run_timestamp_seconds)"
              " > 2 * max by (namespace, collector) (security_collector_expected_interval_seconds) + 3600",
              "ticket", "Collector {{ $labels.collector }} has not covered anything for 2 intervals: no findings != secure",
              "collector-stale", for_="30m"),
        alert("SecurityLedgerStale", "time() - max by (namespace) (security_ledger_last_update_timestamp_seconds) > 2 * 86400",
              "ticket", "The security ledger has not been updated for 2 days (hub down?)", "collector-stale", for_="1h"),
        alert("SecurityRunnerStale",
              "time() - max by (namespace, site) (security_runner_tick_timestamp_seconds)"
              " > max by (namespace, site) (security_runner_tick_max_gap_seconds)",
              "ticket", "The security runner {{ $labels.site }} has not ticked in time (trigger, environment, host or sink broken)",
              "runner-stale", for_="15m"),
        alert("SecurityMetricsSinkFailing", "max by (namespace, site, sink) (security_runner_sink_consecutive_failures) >= 4",
              "ticket", "Metrics sink {{ $labels.sink }} of {{ $labels.site }} failed 4 ticks in a row (retried every tick)",
              "runner-stale"),
        alert("SecurityExportFailing", "max by (namespace, sink) (security_export_consecutive_failures) >= 3",
              "ticket", "Export sink {{ $labels.sink }} (issue tracker / SIEM) failed 3 runs in a row: the team's tools "
              "fall behind the ledger", "export-failing"),
        alert("SecurityRemediationOverdue",
              'sum by (namespace) (security_remediation_overdue{severity=~"critical|high"}) > 0',
              "ticket", "{{ $value }} critical/high finding(s) past their remediation SLO (owner and due date in the private tracker)",
              "remediation-overdue", for_="1h"),
        alert("SecurityContractViolation", "max by (namespace) (security_contract_invalid_documents) > 0", "ticket",
              "A collector emitted a findings document that fails the schema (it was ignored)", "contract-violation"),
        alert("SecurityIntelFeedStale", "max by (namespace, feed) (security_intel_feed_age_seconds) > 3 * 86400", "ticket",
              "Threat-intel feed {{ $labels.feed }} older than 3 days", "intel-feed-stale", for_="1h"),
        alert("SecurityAttestationExpired", 'max by (namespace) (security_attestations{state="expired"}) > 0', "ticket",
              "{{ $value }} human attestation(s) expired: the control fails again until a human re-attests", "attestation-expired",
              for_="1h"),
        alert("SecurityScorecardStale",
              "time() - max by (namespace) (security_scorecard_last_compute_timestamp_seconds) > 2 * 86400", "ticket",
              "The security scorecard has not been computed for 2 days", "score-regression", for_="1h"),
        alert("SecurityExceptionExpired", "max by (namespace) (security_exceptions_expired) > 0", "ticket",
              "A risk acceptance expired; the finding is open again: renew (human) or fix", "exception-expired"),
    ]
    return {"apiVersion": "monitoring.coreos.com/v1", "kind": "PrometheusRule",
            "metadata": {"name": "security-platform", "labels": {"app.kubernetes.io/part-of": "security-platform",
                                                                 "security-platform/generator-version": VERSION}},
            "spec": {"groups": [{"name": "security-platform.regressions", "rules": reg},
                                {"name": "security-platform.health", "rules": health}]}}


def panel(pid, title, expr, kind="stat", x=0, y=0, w=6, h=4, legend=None, unit=None, thresholds=None, desc=None):
    p = {"id": pid, "type": kind, "title": title, "gridPos": {"x": x, "y": y, "w": w, "h": h},
         "datasource": {"type": "prometheus", "uid": "${datasource}"},
         "targets": [{"refId": "A", "expr": expr, **({"legendFormat": legend} if legend else {})}],
         "fieldConfig": {"defaults": {**({"unit": unit} if unit else {}),
                                      "thresholds": thresholds or {"mode": "absolute", "steps": [
                                          {"color": "green", "value": None}, {"color": "red", "value": 1}]}}, "overrides": []},
         "options": {}}
    if desc:
        p["description"] = desc
    if kind == "timeseries":
        p["fieldConfig"]["defaults"]["custom"] = {"stacking": {"mode": "normal"}, "fillOpacity": 30}
    return p


def dashboard(cat):
    ns = 'namespace=~"$namespace"'
    ps, pid, y = [], 1, 0

    def row(title):
        nonlocal pid, y
        pid += 1
        ps.append({"id": pid, "type": "row", "title": title, "gridPos": {"x": 0, "y": y, "w": 24, "h": 1}})
        y += 1

    def add(*a, **k):
        nonlocal pid
        pid += 1
        ps.append(panel(pid, *a, **k))

    row("Security scorecard: the weakest dimension decides (red = below threshold)")
    score_th = {"mode": "absolute", "steps": [{"color": "red", "value": None}, {"color": "green", "value": 75}]}
    add("Overall (weakest dimension)", f"min(security_score_overall{{{ns}}})", x=0, y=y, w=4, h=8, unit="none",
        thresholds=score_th, desc="min over dimensions; the scorecard FAILS when any dimension is below its threshold")
    add("Score by dimension", f'min by (dimension) (security_score{{{ns}, dimension!="", pillar=""}})', "bargauge", 4, y, 10, 8,
        "{{dimension}}", thresholds=score_th)
    add("Score by pillar", f'min by (pillar) (security_score{{{ns}, pillar!="", dimension=""}})', "bargauge", 14, y, 5, 8,
        "{{pillar}}", thresholds=score_th)
    add("Score by CSF function", f'min by (function) (security_score{{{ns}, function!=""}})', "bargauge", 19, y, 5, 8,
        "{{function}}", thresholds=score_th)
    y += 8
    add("Score history by dimension", f'min by (dimension) (security_score{{{ns}, dimension!="", pillar=""}})', "timeseries",
        0, y, 12, 7, "{{dimension}}")
    ps[-1]["fieldConfig"]["defaults"]["custom"] = {"stacking": {"mode": "none"}, "fillOpacity": 0}
    add("Failing controls by dimension", f'sum by (dimension) (security_score_controls{{{ns}, status="fail"}})', "bargauge",
        12, y, 6, 7, "{{dimension}}")
    add("Attestations by state", f"max by (state) (security_attestations{{{ns}}})", "bargauge", 18, y, 6, 7, "{{state}}",
        thresholds={"mode": "absolute", "steps": [{"color": "green", "value": None}]})
    y += 7
    row("Security SLIs (value; red = above objective)")
    for i, s in enumerate(cat["slis"]):
        t = s["objective"]["target"]
        add(s["name"], f'max(security_sli{{{ns}, sli="{s["name"]}"}})', x=(i % 6) * 4, y=y + (i // 6) * 4, w=4,
            desc=s["description"] + f" (objective <= {t})",
            thresholds={"mode": "absolute", "steps": [{"color": "green", "value": None},
                                                      {"color": "red", "value": t + (1 if t == 0 else 0.001)}]})
    y += ((len(cat["slis"]) + 5) // 6) * 4
    row("Findings (aggregates only; details stay in the private ledger)")
    add("Open findings by layer", f'sum by (layer) (security_findings{{{ns}, status="open"}})', "timeseries", 0, y, 12, 8, "{{layer}}")
    add("Open findings by severity", f'sum by (severity) (security_findings{{{ns}, status="open"}})', "timeseries", 12, y, 12, 8, "{{severity}}")
    y += 8
    add("New findings entering an SLI (24h)", f'sum by (sli) (increase(security_sli_new_total{{{ns}}}[24h]))', "bargauge", 0, y, 12, 6, "{{sli}}")
    add("Regressions (reopened, total)", f"max(security_findings_reopened_total{{{ns}}})", x=12, y=y, w=4, h=6)
    add("Time to fix p50 (days)", f'max(security_time_to_fix_days{{{ns}, quantile="0.5"}})', x=16, y=y, w=4, h=6,
        thresholds={"mode": "absolute", "steps": [{"color": "green", "value": None}, {"color": "orange", "value": 7}]})
    add("Exceptions active / expired", f"max(security_exceptions_active{{{ns}}})", x=20, y=y, w=4, h=3,
        thresholds={"mode": "absolute", "steps": [{"color": "green", "value": None}]})
    add("Expired exceptions", f"max(security_exceptions_expired{{{ns}}})", x=20, y=y + 3, w=4, h=3)
    y += 6
    row("Platform health (inner loop): no findings != secure")
    add("Collector: hours since last good run", f"(time() - max by (collector) (security_collector_last_good_run_timestamp_seconds{{{ns}}})) / 3600",
        "bargauge", 0, y, 12, 8, "{{collector}}",
        thresholds={"mode": "absolute", "steps": [{"color": "green", "value": None}, {"color": "orange", "value": 26}, {"color": "red", "value": 50}]})
    add("Coverage gaps by collector", f"max by (collector) (security_collector_gaps{{{ns}}})", "bargauge", 12, y, 12, 8, "{{collector}}")
    y += 8
    add("Runner jobs: hours since last success", f"(time() - max by (site, job) (security_runner_job_last_success_timestamp_seconds{{{ns}}})) / 3600",
        "bargauge", 0, y, 12, 8, "{{site}}/{{job}}",
        thresholds={"mode": "absolute", "steps": [{"color": "green", "value": None}, {"color": "orange", "value": 26}, {"color": "red", "value": 50}]})
    add("Runner job failures (24h)", f"sum by (site, job) (increase(security_runner_job_failures_total{{{ns}}}[24h]))", "bargauge", 12, y, 12, 8,
        "{{site}}/{{job}}")
    y += 8
    add("Remediation: overdue by severity", f"max by (severity) (security_remediation_overdue{{{ns}}})",
        "bargauge", 0, y, 12, 6, "{{severity}}")
    add("Time to remediate p50 (days) by severity", f'max by (severity) (security_time_to_remediate_days{{{ns}, quantile="0.5"}})',
        "bargauge", 12, y, 12, 6, "{{severity}}")
    y += 6
    add("Intel feed age (hours)", f"max by (feed) (security_intel_feed_age_seconds{{{ns}}}) / 3600", "bargauge", 0, y, 12, 6, "{{feed}}",
        thresholds={"mode": "absolute", "steps": [{"color": "green", "value": None}, {"color": "red", "value": 72}]})
    add("Hours since the hub published", f"(time() - max(security_metrics_published_timestamp_seconds{{{ns}}})) / 3600", x=12, y=y, w=6, h=6,
        thresholds={"mode": "absolute", "steps": [{"color": "green", "value": None}, {"color": "orange", "value": 26}, {"color": "red", "value": 50}]})
    add("Invalid findings documents", f"max(security_contract_invalid_documents{{{ns}}})", x=18, y=y, w=6, h=6)
    return {"uid": "security-platform", "title": "Security platform", "schemaVersion": 39, "version": 1,
            "tags": ["security-platform", f"generator-{VERSION}"], "time": {"from": "now-30d", "to": "now"},
            "templating": {"list": [
                {"name": "datasource", "type": "datasource", "query": "prometheus", "label": "Prometheus"},
                {"name": "namespace", "type": "query", "label": "namespace", "datasource": {"type": "prometheus", "uid": "${datasource}"},
                 "query": {"query": "label_values(security_ledger_last_update_timestamp_seconds, namespace)", "refId": "ns"},
                 "refresh": 2, "includeAll": True, "multi": False, "current": {"text": "All", "value": "$__all"}}]},
            "panels": ps}


def overview(cat):
    """The landing page: one screen that answers "are we OK, what is worst, what is late" in plain words. Aggregates
    only, like every generated panel; the details are one `sp explain <id>` away on the private hub."""
    ns = 'namespace=~"$namespace"'
    ps, pid = [], 0
    score_th = {"mode": "absolute", "steps": [{"color": "red", "value": None}, {"color": "green", "value": 75}]}
    zero_ok = {"mode": "absolute", "steps": [{"color": "green", "value": None}, {"color": "red", "value": 1}]}

    def add(*a, **k):
        nonlocal pid
        pid += 1
        ps.append(panel(pid, *a, **k))
        return ps[-1]

    def text(title, md, x, y, w, h):
        nonlocal pid
        pid += 1
        ps.append({"id": pid, "type": "text", "title": title, "gridPos": {"x": x, "y": y, "w": w, "h": h},
                   "options": {"mode": "markdown", "content": md}})

    add("Security score", f"min(security_score_overall{{{ns}}})", x=0, y=0, w=4, h=7, thresholds=score_th,
        desc="The weakest dimension's score (0-100). Below 75 = the programme fails somewhere; see the bars.")
    add("Critical + high open", f'sum(security_findings{{{ns}, status="open", severity=~"critical|high"}}) or vector(0)',
        x=4, y=0, w=4, h=7, thresholds=zero_ok, desc="Open findings that should be fixed this week or sooner.")
    add("Overdue fixes", f"sum(security_remediation_overdue{{{ns}}}) or vector(0)", x=8, y=0, w=4, h=7, thresholds=zero_ok,
        desc="Open findings past their fix-by date (remediation SLO). `sp findings --overdue` lists them.")
    add("New in 24h", f"sum(increase(security_sli_new_total{{{ns}}}[24h])) or vector(0)", x=12, y=0, w=4, h=7,
        thresholds=zero_ok, desc="Serious findings that appeared today (they also alert).")
    add("Came back (regressions)", f"max(security_findings_reopened_total{{{ns}}}) or vector(0)", x=16, y=0, w=4, h=7,
        thresholds=zero_ok, desc="Fixed findings that reappeared, ever. A rise means a fix was undone.")
    add("Could not check", f"sum(security_collector_gaps{{{ns}}}) or vector(0)", x=20, y=0, w=4, h=7,
        thresholds={"mode": "absolute", "steps": [{"color": "green", "value": None}, {"color": "orange", "value": 1}]},
        desc="Things in scope that no scan could look at. No finding there does NOT mean safe.")
    add("Score by pillar", f'min by (pillar) (security_score{{{ns}, pillar!="", dimension=""}})', "bargauge", 0, 7, 8, 9,
        "{{pillar}}", thresholds=score_th, desc="Network, device, people, software: the weakest pillar is where to invest.")
    add("Score by dimension", f'min by (dimension) (security_score{{{ns}, dimension!="", pillar=""}})', "bargauge", 8, 7, 10, 9,
        "{{dimension}}", thresholds=score_th, desc="docs/scorecard.md explains each dimension; reports/scorecard.md lists "
        "the failing controls.")
    add("Failing controls", f'sum by (dimension) (security_score_controls{{{ns}, status="fail"}})', "bargauge", 18, 7, 6, 9,
        "{{dimension}}", thresholds={"mode": "absolute", "steps": [{"color": "green", "value": None}, {"color": "orange", "value": 1}]})
    top = add("Top risks: open critical and high, by area", f'sort_desc(sum by (layer, severity) (security_findings{{{ns}, '
              f'status="open", severity=~"critical|high"}}))', "table", 0, 16, 12, 9,
              desc="Where the serious findings are. `sp findings --open --severity high` on the hub lists them; "
                   "`sp explain <id>` says how to fix each.")
    top["targets"][0].update(instant=True, format="table")
    top["transformations"] = [{"id": "organize", "options": {"excludeByName": {"Time": True},
                                                            "renameByName": {"layer": "area", "Value": "open"}}}]
    add("Overdue fixes by severity", f"max by (severity) (security_remediation_overdue{{{ns}}})", "bargauge", 12, 16, 6, 9,
        "{{severity}}", thresholds=zero_ok)
    add("Exposure and exploited vulnerabilities", f'max by (sli) (security_sli{{{ns}, sli=~"unauth_network_services|'
        f'kev_or_critical_exposed|kev_affecting_assets"}})', "bargauge", 18, 16, 6, 9, "{{sli}}", thresholds=zero_ok,
        desc="Open services without login seen from outside, and known-exploited (KEV) or critical vulnerabilities on "
             "exposed assets: the most urgent kinds of risk.")
    add("Open findings by severity (30 days)", f'sum by (severity) (security_findings{{{ns}, status="open"}})', "timeseries",
        0, 25, 12, 8, "{{severity}}")
    add("Platform health: hours since each job last succeeded",
        f"(time() - max by (job) (security_runner_job_last_success_timestamp_seconds{{{ns}}})) / 3600", "bargauge", 12, 25,
        12, 8, "{{job}}", thresholds={"mode": "absolute", "steps": [{"color": "green", "value": None},
                                                                     {"color": "orange", "value": 26}, {"color": "red", "value": 50}]})
    text("What to do", "**Red tiles first.** On the hub: `sp status` (one screen), `sp findings --open --severity high`, "
         "`sp explain <id>` (what, why, how to fix, how to verify). A fix is confirmed by the next scan; accepting a risk "
         "is a human entry in `exceptions.yaml` with an end date. Details never appear here: they stay in the private "
         "data directory. Full dashboard: *Security platform*.", 0, 33, 24, 3)
    d = dashboard(cat)
    return dict(d, uid="security-platform-overview", title="Security overview", panels=ps,
                tags=["security-platform", "overview", f"generator-{VERSION}"],
                links=[{"title": "Security platform (details)", "type": "dashboards", "tags": ["security-platform"]}])


def dashboard_configmap(dash, ov):
    return {"apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": "security-platform-dashboard", "labels": {"grafana_dashboard": "1",
                                                                           "app.kubernetes.io/part-of": "security-platform"}},
            "data": {"security-platform.json": json.dumps(dash, indent=1),
                     "security-platform-overview.json": json.dumps(ov, indent=1)}}


def collectors_of(instance):
    if not instance:
        return sorted(os.path.basename(os.path.dirname(p)) for p in glob.glob(os.path.join(ROOT, "collectors", "*", "collector.py")))
    sys.path.insert(0, os.path.join(ROOT, "runner"))
    import cron
    inst = yaml.safe_load(open(instance))
    out = {}
    for name, j in ((inst.get("runner") or {}).get("jobs") or {}).items():
        if (j or {}).get("type", "collector") == "collector":
            out[j.get("collector", name)] = cron.Cron(j["schedule"]).interval()
        for col, sched in ((j or {}).get("site_collectors") or {}).items():
            out[col] = cron.Cron(sched).interval()
    return out


def human(seconds):
    h = int(seconds // 3600)
    return f"{h // 24}d" if h % 24 == 0 and h >= 24 else f"{h}h"


def slos(cat, cols, app, env):
    """Values for slo-platform's SLO chart. Burn alerts are silent (severity info): the security platform alerts on
    regressions only (prometheus-rules.yaml); the SLOs are for the error budget and the weekly review."""
    silent = {"fastBurn": "info", "mediumBurn": "info", "slowBurn": "info", "longTermBurn": "info", "absent": "ticket"}
    out = []
    intervals = cols if isinstance(cols, dict) else {c: 86400 for c in cols}
    for col, iv in sorted(intervals.items()):
        mx = human(max(2 * iv + 2 * 3600, 26 * 3600))
        out.append({"name": f"security-collector-{col}-fresh", "objective": 95, "severities": dict(silent),
                    "description": f"The {col} collector covered at least one asset within {mx} (no findings != secure).",
                    "age": {"metric": "security_collector_last_good_run_timestamp_seconds", "matchers": f'collector="{col}"', "max": mx}})
    out.append({"name": "security-ledger-fresh", "objective": 95, "severities": dict(silent),
                "description": "The ledger merged a run within 50h (the hub may sleep; two missed days burn).",
                "age": {"metric": "security_ledger_last_update_timestamp_seconds", "matchers": "", "max": "50h"}})
    for s in cat["slis"]:
        out.append({"name": "security-" + s["name"].replace("_", "-"), "objective": 99, "severities": dict(silent),
                    "description": s["description"] + f" stays <= {s['objective']['target']}.",
                    "bool": {"metric": "security_sli_ok", "matchers": f'sli="{s["name"]}"'}})
    return {"app": app, "env": env, "slos": out}


def write_yaml(obj, path, header):
    with open(path, "w") as f:
        f.write(header)
        yaml.safe_dump(obj, f, sort_keys=False, allow_unicode=True, width=140)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(ROOT, "dist"))
    ap.add_argument("--instance")
    ap.add_argument("--app", default="security-platform")
    ap.add_argument("--env", default="prod")
    ap.add_argument("--runbook-url", help="base URL of docs/runbooks.md for alert annotations")
    a = ap.parse_args(argv)
    global RUNBOOK
    if a.runbook_url:
        RUNBOOK = a.runbook_url
    cat = yaml.safe_load(open(os.path.join(HERE, "sli-catalog.yaml")))
    os.makedirs(a.out, exist_ok=True)
    hdr = f"# generated by security-platform generators {VERSION} from generators/sli-catalog.yaml - do not edit\n"
    write_yaml(rules(cat), os.path.join(a.out, "prometheus-rules.yaml"), hdr)
    d = dashboard(cat)
    with open(os.path.join(a.out, "grafana-dashboard.json"), "w") as f:
        json.dump(d, f, indent=1)
        f.write("\n")
    o = overview(cat)
    with open(os.path.join(a.out, "grafana-overview.json"), "w") as f:
        json.dump(o, f, indent=1)
        f.write("\n")
    write_yaml(dashboard_configmap(d, o), os.path.join(a.out, "grafana-dashboard.configmap.yaml"), hdr)
    write_yaml(slos(cat, collectors_of(a.instance), a.app, a.env), os.path.join(a.out, "slo-platform-slos.yaml"), hdr)
    stale = os.path.join(a.out, "slo-platform-slos.draft.yaml")
    if os.path.exists(stale):
        os.remove(stale)
    print(f"[generators {VERSION}] wrote {a.out}")


if __name__ == "__main__":
    main()
