"""Ledger lifecycle: open -> fixed only when covered; gap keeps state; reappearance = regression; exceptions need a
human + expiry; expired exceptions reopen."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.join(os.path.dirname(__file__), "..")
FX = os.path.join(ROOT, "tests", "fixtures", "host.findings.json")


def run(run_dir, data):
    subprocess.run([sys.executable, os.path.join(ROOT, "core", "ledger.py"), "--run", run_dir, "--data", data],
                   check=True, capture_output=True)
    return json.load(open(os.path.join(data, "ledger.json")))


class Ledger(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.d)

    def write_run(self, name, findings, gaps=()):
        doc = json.load(open(FX))
        doc["findings"] = findings
        doc["coverage"] = [{"asset": "host:host-a", "status": "ok"}] + [{"asset": g, "status": "gap", "reason": "x"} for g in gaps]
        r = os.path.join(self.d, "runs", name)
        os.makedirs(r)
        json.dump(doc, open(os.path.join(r, "host.findings.json"), "w"))
        return r

    def test_lifecycle(self):
        f = json.load(open(FX))["findings"][0]
        L = run(self.write_run("1", [f]), self.d)
        self.assertEqual(L["entries"][f["id"]]["status"], "open")
        L = run(self.write_run("2", [], gaps=["host:host-a"]), self.d)       # not covered -> unchanged
        self.assertEqual(L["entries"][f["id"]]["status"], "open")
        L = run(self.write_run("3", []), self.d)                              # covered and absent -> fixed
        self.assertEqual(L["entries"][f["id"]]["status"], "fixed")
        self.assertIsNotNone(L["entries"][f["id"]]["time_to_fix_days"])
        L = run(self.write_run("4", [f]), self.d)                             # back -> regression
        self.assertEqual(L["entries"][f["id"]]["status"], "open")
        self.assertEqual(L["entries"][f["id"]]["reopened_count"], 1)

    def test_exceptions_need_human_and_expiry(self):
        f = json.load(open(FX))["findings"][0]
        with open(os.path.join(self.d, "exceptions.yaml"), "w") as x:
            x.write(f"exceptions:\n  {f['id']}: {{reason: test, expires: '2000-01-01'}}\n")   # no approver -> ignored
        L = run(self.write_run("1", [f]), self.d)
        self.assertEqual(L["entries"][f["id"]]["status"], "open")
        with open(os.path.join(self.d, "exceptions.yaml"), "w") as x:
            x.write(f"exceptions:\n  {f['id']}: {{reason: test, approved_by: someone, expires: '2999-01-01'}}\n")
        L = run(self.write_run("2", [f]), self.d)
        self.assertEqual(L["entries"][f["id"]]["status"], "accepted")
        with open(os.path.join(self.d, "exceptions.yaml"), "w") as x:
            x.write(f"exceptions:\n  {f['id']}: {{reason: test, approved_by: someone, expires: '2001-01-01'}}\n")
        L = run(self.write_run("3", [f]), self.d)
        self.assertEqual(L["entries"][f["id"]]["status"], "open")
        self.assertTrue(L["entries"][f["id"]]["exception"]["expired"])


    def test_sli_new_counter_baseline_then_increments(self):
        f = json.load(open(FX))["findings"][0]            # ssh.password_auth_enabled -> SLI ssh_password_auth_hosts
        L = run(self.write_run("1", [f]), self.d)          # first sight = baseline, not "new"
        self.assertEqual(L["sli_new_total"]["ssh_password_auth_hosts"], 0)
        L = run(self.write_run("2", []), self.d)           # fixed
        L = run(self.write_run("3", [f]), self.d)          # back: entered the set again -> +1
        self.assertEqual(L["sli_new_total"]["ssh_password_auth_hosts"], 1)
        g = dict(f, id="ffffffffffff", asset="host:host-a/other")
        L = run(self.write_run("4", [f, g]), self.d)       # a second one -> +1; the standing one does not count
        self.assertEqual(L["sli_new_total"]["ssh_password_auth_hosts"], 2)
        prom = open(os.path.join(self.d, "metrics", "ledger.prom")).read()
        self.assertIn('security_sli_new_total{sli="ssh_password_auth_hosts"} 2', prom)

    def test_accepted_finding_can_be_fixed(self):
        f = json.load(open(FX))["findings"][0]
        with open(os.path.join(self.d, "exceptions.yaml"), "w") as x:
            x.write(f"exceptions:\n  {f['id']}: {{reason: test, approved_by: someone, expires: '2999-01-01'}}\n")
        L = run(self.write_run("1", [f]), self.d)
        self.assertEqual(L["entries"][f["id"]]["status"], "accepted")
        L = run(self.write_run("2", []), self.d)
        self.assertEqual(L["entries"][f["id"]]["status"], "fixed")


if __name__ == "__main__":
    unittest.main()
