"""Contract tests for the platform's OUTPUTS: metrics (names, labels: aggregates only), generated alert rules
(regression-only, routable, runbook anchors exist), slo-platform SLO values, the dashboard, the weekly digest."""
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path[:0] = [ROOT, os.path.join(ROOT, "sdk"), os.path.join(ROOT, "generators"), os.path.join(ROOT, "runner")]
import gen  # noqa: E402
import spsdk  # noqa: E402
from adapters import sinks  # noqa: E402

# Labels allowed on security_* metrics: aggregates and scopes only. Never an asset, address, port, CVE or finding id
# (those are attacker intelligence and stay in the private ledger).
ALLOWED_LABELS = {"collector", "layer", "severity", "status", "sli", "feed", "job", "site", "quantile", "version",
                  "cluster", "result", "kind", "store", "host", "owner", "sink", "dimension", "pillar", "function", "state"}
IPV4 = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
CAT = yaml.safe_load(open(os.path.join(ROOT, "generators", "sli-catalog.yaml")))


def check_metrics_text(tc, text):
    for name, labels, value in sinks.parse_text(text):
        tc.assertTrue(name.startswith("security_"), name)
        tc.assertLessEqual(set(labels) - ALLOWED_LABELS, set(), f"{name}: label not allowed")
        for v in labels.values():
            tc.assertIsNone(IPV4.search(v), f"{name}: address in a label value")


class Metrics(unittest.TestCase):
    def test_collector_metrics_from_every_fixture(self):
        for p in glob.glob(os.path.join(ROOT, "tests", "fixtures", "*.findings.json")):
            with self.subTest(fixture=os.path.basename(p)):
                check_metrics_text(self, spsdk.to_prom(json.load(open(p))))

    def test_ledger_and_runner_metrics(self):
        d = tempfile.mkdtemp()
        try:
            run = os.path.join(d, "run")
            os.makedirs(run)
            for p in glob.glob(os.path.join(ROOT, "tests", "fixtures", "*.findings.json")):
                shutil.copy(p, run)
            subprocess.run([sys.executable, os.path.join(ROOT, "core", "ledger.py"), "--run", run, "--data", d, "--latest", run],
                           check=True, capture_output=True)
            text = open(os.path.join(d, "metrics", "ledger.prom")).read()
            check_metrics_text(self, text)
            for s in CAT["slis"]:
                self.assertIn(f'security_sli_ok{{sli="{s["name"]}"}}', text)
                if "findings" in s["source"]:
                    self.assertIn(f'security_sli_new_total{{sli="{s["name"]}"}}', text)
            self.assertIn("# TYPE security_sli_new_total counter", text)
            out = subprocess.run([sys.executable, os.path.join(ROOT, "core", "digest.py"), "--data", d], check=True,
                                 capture_output=True, text=True).stdout.strip()
            md = open(out).read()
            for h in ("## SLIs", "## New findings", "## Fixed", "## Exceptions", "## Platform health"):
                self.assertIn(h, md)
        finally:
            shutil.rmtree(d)


class Generated(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp()
        gen.main(["--out", cls.d])
        cls.rules = yaml.safe_load(open(os.path.join(cls.d, "prometheus-rules.yaml")))
        cls.slos = yaml.safe_load(open(os.path.join(cls.d, "slo-platform-slos.yaml")))
        cls.dash = json.load(open(os.path.join(cls.d, "grafana-dashboard.json")))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d)

    def test_dist_is_up_to_date(self):
        for f in ("prometheus-rules.yaml", "grafana-dashboard.json", "slo-platform-slos.yaml", "grafana-dashboard.configmap.yaml"):
            self.assertEqual(open(os.path.join(ROOT, "dist", f)).read(), open(os.path.join(self.d, f)).read(),
                             f"dist/{f} is stale: run generators/gen.py")

    def test_rules_regression_only_and_routable(self):
        anchors = set(re.findall(r"^## ([a-z-]+)", open(os.path.join(ROOT, "docs", "runbooks.md")).read(), re.M))
        names = set()
        for g in self.rules["spec"]["groups"]:
            for r in g["rules"]:
                names.add(r["alert"])
                self.assertIn(r["labels"]["severity"], ("page", "ticket"))
                self.assertIn("by (namespace", r["expr"], f"{r['alert']}: keep the namespace label for routing")
                self.assertIn(r["annotations"]["runbook_url"].split("#")[1], anchors)
                if g["name"].endswith("regressions"):
                    self.assertIn("increase(", r["expr"], f"{r['alert']}: regression alerts fire on increases only")
        alerting = {s["name"] for s in CAT["slis"] if s.get("alert")}
        self.assertEqual({n for n in names if n.startswith("SecurityRegression_")}, {"SecurityRegression_" + s for s in alerting})
        self.assertIn("SecurityCollectorStale", names)
        pages = {r["labels"].get("sli") for g in self.rules["spec"]["groups"] for r in g["rules"] if r["labels"]["severity"] == "page"}
        self.assertEqual(pages, {"vuln_alertable", "unauth_network_services"})

    def test_promtool_if_available(self):
        if not shutil.which("promtool"):
            self.skipTest("promtool not installed")
        p = os.path.join(self.d, "groups.yaml")
        yaml.safe_dump({"groups": self.rules["spec"]["groups"]}, open(p, "w"))
        subprocess.run(["promtool", "check", "rules", p], check=True, capture_output=True)

    def test_slo_values_follow_slo_platform(self):
        self.assertEqual((self.slos["app"], self.slos["env"]), ("security-platform", "prod"))
        seen = set()
        for s in self.slos["slos"]:
            self.assertRegex(s["name"], r"^[a-z0-9]([-a-z0-9]{0,50}[a-z0-9])$")
            self.assertNotIn(s["name"], seen)
            seen.add(s["name"])
            kinds = [k for k in ("availability", "latency", "probe", "age", "bool", "ratio") if k in s]
            self.assertEqual(len(kinds), 1, s["name"])
            self.assertTrue(0 < s["objective"] < 100)
            if "age" in s:
                self.assertRegex(s["age"]["max"], r"^\d+[smhd]$")
            self.assertTrue(all(v not in ("page", "ticket") for k, v in s["severities"].items() if k != "absent"),
                            "SLO burn alerts stay silent: the platform alerts on regressions only")

    def test_dashboard_aggregates_only(self):
        for p in self.dash["panels"]:
            for t in p.get("targets", []):
                self.assertIn('namespace=~"$namespace"', t["expr"])
                for lab in re.findall(r"by \(([^)]*)\)", t["expr"]):
                    self.assertLessEqual({x.strip() for x in lab.split(",")} - ALLOWED_LABELS - {"namespace"}, set())


class CollectorSources(unittest.TestCase):
    def test_metric_labels_declared_in_collectors_are_allowed(self):
        for p in glob.glob(os.path.join(ROOT, "collectors", "*", "collector.py")):
            src = open(p).read()
            for call in re.findall(r"c\.metric\((.*?)\)\n", src, re.S):
                for lab in re.findall(r",\s*([a-z_]+)=", call):
                    with self.subTest(collector=p.split(os.sep)[-2], label=lab):
                        self.assertIn(lab, ALLOWED_LABELS)


if __name__ == "__main__":
    unittest.main()
