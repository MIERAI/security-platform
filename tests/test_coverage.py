"""Coverage semantics: an online-verified host with nothing open is covered (fully filtered), an unverified address
with nothing open stays a gap; human-approved, expiring coverage exceptions take a gap out of the SLI."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


class Exposure(unittest.TestCase):
    def test_verified_online_without_ports_is_covered(self):
        d = tempfile.mkdtemp()
        try:
            assets = os.path.join(d, "assets.json")
            json.dump([{"name": "a", "address": "192.0.2.1", "online": True, "attrs": {"online_verified": True}},
                       {"name": "b", "address": "192.0.2.2", "online": True, "attrs": {}}], open(assets, "w"))
            raw = os.path.join(d, "raw.json")
            json.dump({"hosts": {"192.0.2.1": {}, "192.0.2.2": {}}, "tools": {}}, open(raw, "w"))
            inst = os.path.join(d, "i.json")
            json.dump({"name": "t", "exposure": {"discovery": [{"type": "file", "path": assets}], "vantage": {"type": "local"}}},
                      open(inst, "w"))
            run = os.path.join(d, "run")
            subprocess.run([sys.executable, os.path.join(ROOT, "collectors", "exposure", "collector.py")], check=True, capture_output=True,
                           env=dict(os.environ, SP_INSTANCE=inst, SP_RUN_DIR=run, SP_EXPOSURE_RAW=raw))
            cov = {c["asset"]: c["status"] for c in json.load(open(os.path.join(run, "exposure.findings.json")))["coverage"]}
            self.assertEqual(cov["net-endpoint:a@192.0.2.1"], "ok")
            self.assertEqual(cov["host:b"], "gap")
        finally:
            shutil.rmtree(d)


class CoverageExceptions(unittest.TestCase):
    def test_gap_excepted_only_with_human_and_expiry(self):
        d = tempfile.mkdtemp()
        try:
            doc = {"schema_version": "1.0", "collector": {"name": "host", "version": "0.1.0"},
                   "run": {"started_at": "2099-01-01T00:00:00Z", "finished_at": "2099-01-01T00:00:00Z"},
                   "coverage": [{"asset": "host:x", "status": "gap", "reason": "no key"},
                                {"asset": "host:y", "status": "gap", "reason": "offline"}], "findings": []}
            r = os.path.join(d, "runs", "1")
            os.makedirs(r)
            json.dump(doc, open(os.path.join(r, "host.findings.json"), "w"))
            future = time.strftime("%Y-%m-%d", time.gmtime(time.time() + 86400 * 30))
            with open(os.path.join(d, "exceptions.yaml"), "w") as f:
                f.write("coverage_exceptions:\n"
                        f"  host|host:x: {{approved_by: someone, reason: waiting for a key, expires: '{future}'}}\n"
                        f"  host:y: {{reason: no approver, expires: '{future}'}}\n")
            subprocess.run([sys.executable, os.path.join(ROOT, "core", "ledger.py"), "--run", r, "--data", d], check=True,
                           capture_output=True)
            L = json.load(open(os.path.join(d, "ledger.json")))
            self.assertEqual(L["sli"]["collector_coverage_gaps"]["value"], 1)
            self.assertIn("security_coverage_gaps_excepted 1", open(os.path.join(d, "metrics", "ledger.prom")).read())
        finally:
            shutil.rmtree(d)


if __name__ == "__main__":
    unittest.main()
