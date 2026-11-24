#!/usr/bin/env python3
"""Collector `detection`: is detection actually working, and how good is it? READ-ONLY.

Checks the detection pipeline end to end from the outside (docs/detection.md) and measures its quality:
  sensors      every configured cluster runs the runtime sensor and the node log shipper on every node (DaemonSets
               ready == desired; kubectl get, read-only)
  sources      every expected source delivered lines to the log store recently: k8s-audit per cluster, auth per
               host, codehost / overlay-network per account (LogQL count queries; no line content is read)
  ruler        the log store's ruler has the catalog's rules loaded (rule names compared with the catalog)
  quality      alerts per day (ALERTS history in a Prometheus the ruler remote-writes to), false-positive ratio
               (human verdicts), drills (time to detect), rule-content age (catalog `released`)
Gaps become findings (layer detection) so the ledger, regression alerts and the scorecard see them.

Instance config:
  detection:
    log_store: {url: http://127.0.0.1:3100, exec: {type: ssh, host: <log store host>}}  # or {url, token_file}
    alert_history: {url: http://127.0.0.1:9091, exec: {...}}       # optional: Prometheus with ALERTS
    alertmanager: {url: http://127.0.0.1:9093, exec: {...}}      # where detection alerts go: is page routed?
    clusters: [{name, kubeconfig, sensors: [falco, node-logs]}]   # every `kubernetes:` cluster must be here
    expected: {k8s-audit: [<cluster>...], auth: [<host>...], codehost: [<account>...], overlay-network: [<name>...]}
    windows: {k8s-audit: 30m, auth: 7d, codehost: 2d, overlay-network: 2d}   # defaults
    verdicts: <data>/detections/verdicts.yaml       drills: <data>/detections/drills
    drill_max_age: 90d   ttd_target: 5m   ruleset_max_age: 90d   fp_window: 30d
"""
import glob
import json
import os
import re
import shlex
import subprocess
import sys
import time
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..", "..")
sys.path[:0] = [os.path.join(ROOT, "sdk"), ROOT]
import spsdk  # noqa: E402
from adapters import exec as execad  # noqa: E402

VERSION = open(os.path.join(HERE, "VERSION")).read().strip()
UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 7 * 86400}
DEFAULT_WINDOWS = {"k8s-audit": "30m", "auth": "7d", "codehost": "2d", "overlay-network": "2d", "falco": "7d"}
LABEL = {"k8s-audit": "cluster", "auth": "host", "codehost": "host", "overlay-network": "host"}


def dur(v):
    if isinstance(v, (int, float)):
        return float(v)
    m = re.fullmatch(r"(\d+(?:\.\d+)?)([smhdw])", str(v).strip())
    if not m:
        raise ValueError(f"bad duration {v!r}")
    return float(m.group(1)) * UNITS[m.group(2)]


def load_yaml(p):
    try:
        return spsdk.load_config(p)
    except (OSError, ValueError):
        return None


class HTTP:
    """GET a JSON API either directly (url + optional bearer token file) or from a host through the exec adapter
    (`curl` there: the store listens on that host's loopback only)."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.url = cfg["url"].rstrip("/")

    def get(self, path, params=None, timeout=60):
        q = self.url + path + ("?" + urllib.parse.urlencode(params) if params else "")
        if self.cfg.get("exec"):
            rc, out, err = execad.executor(self.cfg["exec"]).run(["curl", "-sf", "--max-time", str(timeout), q], timeout=timeout + 15)
            if rc != 0:
                raise RuntimeError(f"curl rc={rc} {err.strip()[:120]}")
            return json.loads(out)
        req = urllib.request.Request(q)
        tf = self.cfg.get("token_file")
        if tf:
            with open(os.path.expanduser(tf)) as f:
                req.add_header("Authorization", "Bearer " + f.read().strip())
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r)


def catalog():
    cat = load_yaml(os.path.join(ROOT, "detections", "catalog.yaml"))
    return cat or {"rules": [], "prometheus": []}


def alert_name(rid):
    return "SecurityDetection" + "".join(p.capitalize() for p in rid.replace("_", "-").split("-"))


def kubectl(kc, args, timeout=60):
    base = ["kubectl"] + ([] if kc in (None, "", "in-cluster") else ["--kubeconfig", os.path.expanduser(kc)])
    try:
        p = subprocess.run(base + args, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        return 1, "", str(e)
    return p.returncode, p.stdout, p.stderr


def check_sensors(c, d):
    for cl in d.get("clusters") or []:
        name = cl["name"]
        rc, out, err = kubectl(cl.get("kubeconfig"), ["get", "daemonsets", "-A", "-o", "json"])
        asset = f"k8s-cluster:{name}"
        if rc != 0:
            c.gap(asset, f"cannot list DaemonSets: {err.strip()[:120]}")
            continue
        c.ok(asset)
        items = {i["metadata"]["name"]: i for i in json.loads(out).get("items", [])}
        for s in cl.get("sensors") or ["falco", "node-logs"]:
            ds = items.get(s)
            st = (ds or {}).get("status") or {}
            want, ready = st.get("desiredNumberScheduled", 0), st.get("numberReady", 0)
            c.metric("security_detection_sensor_ready_ratio", (ready / want) if want else 0,
                     "Nodes where the detection sensor is ready / nodes it should run on", cluster=name, kind=s)
            if not ds or want == 0 or ready < want:
                c.finding("detection", f"{asset}/{s}", "detection.sensor_missing",
                          f"detection sensor {s} is not ready on every node of cluster {name} ({ready}/{want})",
                          "high", c.raw(f"sensors-{name}.json", {s: {"desired": want, "ready": ready, "present": bool(ds)}}),
                          "deploy / repair the sensor through GitOps (docs/detection.md#deploying-an-instance)")


def check_backstop(c, d):
    for cl in d.get("clusters") or []:
        rc, out, err = kubectl(cl.get("kubeconfig"), ["get", "prometheusrules", "-A", "-o", "json"])
        if rc != 0:
            continue                      # the sensors check already recorded the cluster as a gap
        n = sum(len(g.get("rules", [])) for i in json.loads(out).get("items", [])
                if i["metadata"]["name"] == "security-detection" for g in (i.get("spec") or {}).get("groups", []))
        c.metric("security_detection_backstop_rules", n, "In-cluster detection rules (independent of the log store)", cluster=cl["name"])
        if not n:
            c.finding("detection", f"k8s-cluster:{cl['name']}/backstop", "detection.backstop_missing",
                      f"cluster {cl['name']} has no in-cluster detection rules: a log store outage blinds runtime detection",
                      "medium", c.raw(f"backstop-{cl['name']}.json", {"rules": 0}),
                      "deploy detections/falco (PrometheusRule security-detection) to the cluster")


def check_scope(c, d, inst):
    """Every cluster the instance knows (the k8s collector's `kubernetes:` list) must be under detection: sensors
    and an audit-log source. A cluster nobody watches is the weakest link."""
    known = [k["name"] for k in inst.get("kubernetes") or [] if k.get("name")]
    sensed = {cl["name"] for cl in d.get("clusters") or []}
    audited = set((d.get("expected") or {}).get("k8s-audit") or [])
    for name in known:
        missing = [w for w, ok in (("runtime sensor", name in sensed), ("audit log", name in audited)) if not ok]
        if missing:
            c.ok(f"k8s-cluster:{name}")
            c.finding("detection", f"k8s-cluster:{name}", "detection.cluster_not_covered",
                      f"cluster {name} is not under detection ({', '.join(missing)} missing)", "high",
                      c.raw(f"scope-{name}.json", {"missing": missing}),
                      "add the cluster to detection.clusters / detection.expected.k8s-audit after deploying the sensors")
    c.metric("security_detection_clusters_known", len(known), "Clusters in the instance")
    c.metric("security_detection_clusters_covered", sum(1 for n in known if n in sensed and n in audited),
             "Clusters with a runtime sensor and an audit-log source configured")


def check_routing(c, d):
    cfg = d.get("alertmanager")
    if not cfg:
        return
    asset = "detection-alertmanager:routing"
    try:
        st = HTTP(cfg).get("/api/v2/status")
    except Exception as e:  # noqa: BLE001
        c.gap(asset, f"alertmanager status: {type(e).__name__}: {str(e)[:100]}")
        return
    c.ok(asset)
    conf = (st.get("config") or {}).get("original", "")
    try:
        import yaml
        doc = yaml.safe_load(conf) or {}
    except Exception:  # noqa: BLE001 - no PyYAML / unparsable: decide on nothing rather than guess
        doc = {}
    notifying = {r["name"] for r in doc.get("receivers") or []
                 if any(k.endswith("_configs") and r.get(k) for k in r)}

    def routes(r):
        yield r
        for x in r.get("routes") or []:
            yield from routes(x)
    page = any('severity="page"' in str(m).replace(" ", "") or "severity=page" in str(m).replace(" ", "")
               for r in routes(doc.get("route") or {}) for m in (r.get("matchers") or [])
               if r.get("receiver") in notifying)
    c.metric("security_detection_page_route", 1 if page else 0, "1 if page-severity detection alerts reach a notifying receiver")
    if not page:
        c.finding("detection", asset, "detection.page_route_missing",
                  "page-severity detection alerts are recorded but reach no human (no notifying receiver on a severity=page route)",
                  "high", c.raw("routing.json", {"notifying_receivers": sorted(notifying)}),
                  "route severity=page to a receiver that notifies a person (docs/detection.md)")


def check_sources(c, d, store):
    windows = dict(DEFAULT_WINDOWS, **(d.get("windows") or {}))
    expected = d.get("expected") or {}
    seen_all = {}
    for source, label in LABEL.items():
        want = expected.get(source) or []
        if not want:
            continue
        w = windows[source]
        q = f'sum by ({label}) (count_over_time({{source="{source}"}}[{w}]))'
        try:
            res = store.get("/loki/api/v1/query", {"query": q})["data"]["result"]
        except Exception as e:  # noqa: BLE001 - the store unreachable is a gap, not a pass
            for x in want:
                c.gap(f"log-source:{source}/{x}", f"log store query failed: {type(e).__name__}: {str(e)[:100]}")
            continue
        seen = {r["metric"].get(label, ""): float(r["value"][1]) for r in res}
        seen_all[source] = seen
        live = 0
        for x in want:
            asset = f"log-source:{source}/{x}"
            c.ok(asset)
            if seen.get(x, 0) > 0:
                live += 1
            else:
                c.finding("detection", asset, "detection.source_silent",
                          f"no {source} log lines from {x} in the last {w}: detections for it are blind",
                          "high" if source in ("k8s-audit", "auth") else "medium",
                          c.raw(f"source-{source}.json", {"window": w, "seen": sorted(seen)}),
                          "fix the shipper for this source (docs/detection.md#log-contract) or remove it from detection.expected")
        c.metric("security_detection_sources_expected", len(want), "Sources that must deliver logs", source=source)
        c.metric("security_detection_sources_live", live, "Expected sources that delivered logs in their window", source=source)
    return seen_all


def check_ruler(c, d, store, cat):
    want = {alert_name(r["id"]) for r in cat.get("rules", [])}
    asset = "detection-ruler:log-store"
    try:
        doc = store.get("/prometheus/api/v1/rules")
    except Exception as e:  # noqa: BLE001
        c.gap(asset, f"ruler API: {type(e).__name__}: {str(e)[:100]}")
        return
    c.ok(asset)
    loaded = {r.get("name") for g in (doc.get("data") or {}).get("groups", []) for r in g.get("rules", [])}
    unhealthy = [r.get("name") for g in (doc.get("data") or {}).get("groups", []) for r in g.get("rules", [])
                 if r.get("health") not in (None, "ok", "unknown")]
    missing = sorted(want - loaded)
    c.metric("security_detection_rules_loaded", len(want & loaded), "Catalog rules loaded in the log store's ruler")
    c.metric("security_detection_rules_total", len(want), "Rules in the detection catalog (log-store rules)")
    c.metric("security_detection_rules_unhealthy", len(unhealthy), "Loaded rules whose last evaluation failed")
    if missing or unhealthy:
        c.finding("detection", asset, "detection.ruler_incomplete",
                  f"{len(missing)} catalog rule(s) not loaded, {len(unhealthy)} failing evaluation in the log store's ruler",
                  "high", c.raw("ruler.json", {"missing": missing, "unhealthy": unhealthy}),
                  "render the rules (detections/render.py --params) and deploy them to the ruler; check its log")


def check_alert_history(c, d):
    cfg = d.get("alert_history")
    if not cfg:
        return
    asset = "detection-alerts:history"
    try:
        h = HTTP(cfg)
        res = h.get("/api/v1/query", {"query": 'sum by (severity) (count_over_time(ALERTS{component="security-detection",alertstate="firing"}[24h]))'})
    except Exception as e:  # noqa: BLE001
        c.gap(asset, f"alert history query: {type(e).__name__}: {str(e)[:100]}")
        return
    c.ok(asset)
    per = {r["metric"].get("severity", ""): float(r["value"][1]) for r in res["data"]["result"]}
    for sev in ("page", "ticket", "info"):
        # samples of ALERTS at the ruler's 1m evaluation = firing minutes; an episode count would need more state
        c.metric("security_detection_alert_minutes_24h", per.get(sev, 0), "Minutes any detection alert was firing in the last 24h", severity=sev)


def check_verdicts(c, d, data, now):
    p = os.path.expanduser(d.get("verdicts") or os.path.join(data, "detections", "verdicts.yaml"))
    win = dur(d.get("fp_window", "30d"))
    doc = load_yaml(p) if os.path.exists(p) else None
    rows = [v for v in (doc or {}).get("verdicts", []) if isinstance(v, dict)]
    recent = []
    for v in rows:
        try:
            t = time.mktime(time.strptime(str(v.get("fired_at", ""))[:19], "%Y-%m-%dT%H:%M:%S")) - time.timezone
        except ValueError:
            continue
        if now - t <= win:
            recent.append(v)
    counts = {}
    for v in recent:
        counts[v.get("verdict", "?")] = counts.get(v.get("verdict", "?"), 0) + 1
    for k in ("true_positive", "false_positive", "benign", "drill"):
        c.metric("security_detection_verdicts", counts.get(k, 0), "Alert verdicts recorded by a human in the window", result=k)
    judged = sum(counts.get(k, 0) for k in ("true_positive", "false_positive", "benign"))
    if judged:
        c.metric("security_detection_false_positive_ratio", counts.get("false_positive", 0) / judged,
                 "False positives / judged alerts (drills excluded) in the window")


def check_drills(c, d, data, now):
    pat = os.path.join(os.path.expanduser(d.get("drills") or os.path.join(data, "detections", "drills")), "*.yaml")
    drills = []
    for p in sorted(glob.glob(pat)):
        x = load_yaml(p)
        if isinstance(x, dict) and x.get("action_at"):
            drills.append(x)
    asset = "detection-drills:lab"
    c.ok(asset)
    max_age, target = dur(d.get("drill_max_age", "90d")), dur(d.get("ttd_target", "5m"))
    if not drills:
        c.finding("detection", asset, "detection.drill_overdue", "no detection drill has been recorded",
                  "medium", c.raw("drills.json", {"drills": 0}), "run a benign drill in the lab (docs/incident-response.md#drills)")
        return
    last = max(drills, key=lambda x: str(x["action_at"]))
    t = time.mktime(time.strptime(str(last["action_at"])[:19], "%Y-%m-%dT%H:%M:%S")) - time.timezone
    ttd = last.get("ttd_seconds")
    c.metric("security_detection_drill_last_timestamp_seconds", t, "When the last detection drill acted")
    if ttd is not None:
        c.metric("security_detection_drill_ttd_seconds", float(ttd), "Time to detect in the last drill (alert received - action)")
    passed = last.get("result") == "pass" and ttd is not None and float(ttd) <= target
    c.metric("security_detection_drill_pass", 1 if passed else 0, "1 if the last drill detected within the target and followed the runbook")
    if now - t > max_age:
        c.finding("detection", asset, "detection.drill_overdue", f"the last detection drill is older than {d.get('drill_max_age', '90d')}",
                  "medium", c.raw("drills.json", {"last": last.get("id")}), "run a benign drill in the lab (docs/incident-response.md#drills)")
    elif not passed:
        c.finding("detection", asset, "detection.drill_failed", "the last detection drill did not detect within the target",
                  "high", c.raw("drills.json", {"last": last.get("id"), "ttd_seconds": ttd}),
                  "fix the pipeline stage that was slow or silent; repeat the drill")


def check_ruleset(c, d, cat, now):
    rel = str(cat.get("released", ""))
    asset = "detection-ruleset:catalog"
    try:
        t = time.mktime(time.strptime(rel[:10], "%Y-%m-%d")) - time.timezone
    except ValueError:
        c.gap(asset, "catalog has no released date")
        return
    c.ok(asset)
    age = (now - t) / 86400
    c.metric("security_detection_ruleset_age_days", round(age, 1), "Days since the detection rule content was last reviewed/released")
    c.metric("security_detection_ruleset_info", 1, "Detection catalog version", version=str(cat.get("version", "")))
    if age > dur(d.get("ruleset_max_age", "90d")) / 86400:
        c.finding("detection", asset, "detection.ruleset_stale", f"detection rules not reviewed for {age:.0f} days",
                  "medium", c.raw("ruleset.json", {"released": rel, "upstream": cat.get("upstream")}),
                  "review the catalog against upstream (falco-rules, ATT&CK); bump `released`")


def main():
    inst = spsdk.load_instance()
    c = spsdk.Collector("detection", VERSION)
    d = inst.get("detection") or {}
    now = time.time()
    data = os.environ.get("SP_DATA", "")
    cat = catalog()
    if not d:
        c.gap("detection-config:instance", "no `detection:` section in the instance")
    else:
        check_scope(c, d, inst)
        check_sensors(c, d)
        check_backstop(c, d)
        check_routing(c, d)
        if d.get("log_store"):
            store = HTTP(d["log_store"])
            check_sources(c, d, store)
            check_ruler(c, d, store, cat)
        else:
            c.gap("detection-ruler:log-store", "no detection.log_store configured")
        check_alert_history(c, d)
        check_verdicts(c, d, data, now)
        check_drills(c, d, data, now)
    check_ruleset(c, d, cat, now)
    c.write()


if __name__ == "__main__":
    main()
