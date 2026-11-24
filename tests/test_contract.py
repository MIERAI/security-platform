"""Contract tests: every collector must have a fixture that validates against the findings schema; the core must
reject unknown majors; consumers only use contract fields. Optional: SP_CONTRACT_RUN_DIR=<run dir> also validates a
real run (used by the instance, never committed)."""
import glob
import json
import os
import sys
import unittest

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path[:0] = [os.path.join(ROOT, "core"), os.path.join(ROOT, "sdk")]
import ocsf  # noqa: E402
import validate  # noqa: E402


class Contract(unittest.TestCase):
    def test_every_collector_has_valid_fixture(self):
        for d in sorted(glob.glob(os.path.join(ROOT, "collectors", "*", "collector.py"))):
            name = os.path.basename(os.path.dirname(d))
            with self.subTest(collector=name):
                self.assertTrue(os.path.exists(os.path.join(ROOT, "collectors", name, "VERSION")), "VERSION missing")
                fx = os.path.join(ROOT, "tests", "fixtures", f"{name}.findings.json")
                self.assertTrue(os.path.exists(fx), f"fixture missing for {name}")
                doc = json.load(open(fx))
                self.assertEqual(validate.validate_findings(doc), [])
                self.assertEqual(doc["collector"]["name"], name)

    def test_unknown_major_rejected(self):
        doc = json.load(open(os.path.join(ROOT, "tests", "fixtures", "host.findings.json")))
        doc["schema_version"] = "2.0"
        self.assertTrue(validate.validate_findings(doc))

    def test_minor_with_unknown_fields_accepted(self):
        doc = json.load(open(os.path.join(ROOT, "tests", "fixtures", "host.findings.json")))
        doc["schema_version"] = "1.7"
        doc["future_field"] = {"x": 1}
        doc["findings"][0]["future_field"] = 1
        self.assertEqual(validate.validate_findings(doc), [])

    def test_bad_finding_rejected(self):
        doc = json.load(open(os.path.join(ROOT, "tests", "fixtures", "host.findings.json")))
        doc["findings"][0]["severity"] = "urgent"
        del doc["findings"][0]["needs_human"]
        self.assertEqual(len(validate.validate_findings(doc)), 2)

    def test_ocsf_mapping(self):
        doc = json.load(open(os.path.join(ROOT, "tests", "fixtures", "vuln-intel.findings.json")))
        f = doc["findings"][0]
        e = dict(f, status="open", first_seen=f["observed_at"], last_seen=f["observed_at"], collector="vuln-intel")
        ev = ocsf.to_ocsf(e)
        self.assertEqual(ev["class_uid"], 2002)
        self.assertEqual(ev["severity_id"], 4)
        self.assertTrue(ev["vulnerabilities"][0]["is_exploit_available"])

    def test_real_run_if_given(self):
        d = os.environ.get("SP_CONTRACT_RUN_DIR")
        if not d:
            self.skipTest("SP_CONTRACT_RUN_DIR not set")
        for p in glob.glob(os.path.join(d, "*.findings.json")):
            with self.subTest(doc=os.path.basename(p)):
                self.assertEqual(validate.validate_findings(json.load(open(p))), [])


if __name__ == "__main__":
    unittest.main()
