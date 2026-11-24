"""Collector `detection`: sources, ruler, verdicts, drills and rule age against a fake log store (no network)."""
import http.server
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
COL = os.path.join(ROOT, "collectors", "detection", "collector.py")


class FakeStore(http.server.BaseHTTPRequestHandler):
    sources = {}          # source -> {label value: count}
    rules = []            # loaded rule names

    def do_GET(self):  # noqa: N802
        u = urllib.parse.urlparse(self.path)
        if u.path == "/loki/api/v1/query":
            q = urllib.parse.parse_qs(u.query)["query"][0]
            src = q.split('source="')[1].split('"')[0]
            label = q.split("sum by (")[1].split(")")[0]
            res = [{"metric": {label: k}, "value": [time.time(), str(v)]} for k, v in self.sources.get(src, {}).items()]
            body = {"status": "success", "data": {"resultType": "vector", "result": res}}
        elif u.path == "/prometheus/api/v1/rules":
            body = {"status": "success", "data": {"groups": [{"name": "g", "rules": [{"name": n, "health": "ok"} for n in self.rules]}]}}
        else:
            self.send_response(404)
            self.end_headers()
            return
        out = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


def iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t))


class DetectionCollector(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeStore)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def run_collector(self, detection, files=None):
        d = tempfile.mkdtemp()
        data, run = os.path.join(d, "data"), os.path.join(d, "run")
        for rel, text in (files or {}).items():
            p = os.path.join(data, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as f:
                f.write(text)
        inst = os.path.join(d, "instance.json")
        with open(inst, "w") as f:
            json.dump({"detection": detection}, f)
        env = dict(os.environ, SP_INSTANCE=inst, SP_RUN_DIR=run, SP_DATA=data)
        p = subprocess.run([sys.executable, COL], env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        with open(os.path.join(run, "detection.findings.json")) as f:
            return json.load(f)

    def metric(self, doc, name, **labels):
        for m in doc["metrics"]:
            if m["name"] == name and all(m["labels"].get(k) == v for k, v in labels.items()):
                return m["value"]
        return None

    def test_silent_source_and_missing_rules(self):
        FakeStore.sources = {"auth": {"host-a": 12}, "k8s-audit": {"c1": 400}}
        FakeStore.rules = ["SecurityDetectionK8sPodExec"]
        now = time.time()
        doc = self.run_collector(
            {"log_store": {"url": f"http://127.0.0.1:{self.srv.server_port}"},
             "expected": {"auth": ["host-a", "host-b"], "k8s-audit": ["c1"]}},
            {"detections/drills/d1.yaml": json.dumps({"id": "d1", "action_at": iso(now - 3600), "ttd_seconds": 70, "result": "pass"}),
             "detections/verdicts.yaml": json.dumps({"verdicts": [
                 {"fired_at": iso(now - 100), "verdict": "false_positive"},
                 {"fired_at": iso(now - 200), "verdict": "true_positive"},
                 {"fired_at": iso(now - 300), "verdict": "drill"}]})})
        checks = {(f["check"], f["asset"]) for f in doc["findings"]}
        self.assertIn(("detection.source_silent", "log-source:auth/host-b"), checks)
        self.assertNotIn(("detection.source_silent", "log-source:auth/host-a"), checks)
        self.assertIn(("detection.ruler_incomplete", "detection-ruler:log-store"), checks)
        self.assertEqual(self.metric(doc, "security_detection_sources_live", source="auth"), 1)
        self.assertEqual(self.metric(doc, "security_detection_sources_expected", source="auth"), 2)
        self.assertEqual(self.metric(doc, "security_detection_false_positive_ratio"), 0.5)
        self.assertEqual(self.metric(doc, "security_detection_drill_pass"), 1)
        self.assertEqual(self.metric(doc, "security_detection_drill_ttd_seconds"), 70)
        self.assertIsNotNone(self.metric(doc, "security_detection_ruleset_age_days"))

    def test_store_down_is_a_gap_not_a_pass(self):
        doc = self.run_collector({"log_store": {"url": "http://127.0.0.1:9"}, "expected": {"auth": ["h"]}})
        gaps = {c["asset"]: c["status"] for c in doc["coverage"]}
        self.assertEqual(gaps.get("log-source:auth/h"), "gap")
        self.assertEqual(gaps.get("detection-ruler:log-store"), "gap")
        self.assertIn("detection.drill_overdue", {f["check"] for f in doc["findings"]})

    def test_slow_drill_fails(self):
        FakeStore.sources, FakeStore.rules = {}, []
        doc = self.run_collector({"log_store": {"url": f"http://127.0.0.1:{self.srv.server_port}"}, "ttd_target": "5m"},
                                 {"detections/drills/d.yaml": json.dumps({"id": "d", "action_at": iso(time.time() - 60),
                                                                          "ttd_seconds": 900, "result": "pass"})})
        self.assertIn("detection.drill_failed", {f["check"] for f in doc["findings"]})
        self.assertEqual(self.metric(doc, "security_detection_drill_pass"), 0)


if __name__ == "__main__":
    unittest.main()
