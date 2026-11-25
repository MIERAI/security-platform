"""runner implementation switch (runner.implementations: python | go | shadow): argv of the Go binary, fallback to
Python when there is none, shadow runs on a copy whose outputs are diffed and never reach the real data."""
import glob
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path[:0] = [os.path.join(ROOT, "runner"), ROOT, os.path.join(ROOT, "sdk"), os.path.join(ROOT, "core")]
import runner  # noqa: E402

FX = os.path.join(ROOT, "tests", "fixtures", "host.findings.json")

# A stand-in for the Go `sp` binary: answers the version probe, records its argv, and implements `ledger merge` /
# `ledger track` by running the Python reference on the arguments it was given. MODE=mutate makes its merge differ
# (a due date on every entry = the LEDGER-D2 target, and one wrong status = a real difference); MODE=deviation changes
# one status only WITHOUT --reference-behaviour, as a known deviation's target behaviour does.
FAKE = r'''#!{python}
import json, os, subprocess, sys
ROOT, LOG, MODE = {root!r}, {log!r}, {mode!r}
a = sys.argv[1:]
if a[:2] == ["version", "--json"]:
    print(json.dumps({{"schema": "security-platform/version/v1", "go_subcommands": ["ledger", "version"]}}))
    sys.exit(0)
with open(LOG, "a") as f:
    f.write(json.dumps(a) + "\n")
def opt(name):
    return a[a.index(name) + 1] if name in a else None
print("fake go " + " ".join(a[:2]), file=sys.stderr)
if a[:2] == ["ledger", "merge"]:
    rc = subprocess.run([sys.executable, os.path.join(ROOT, "core", "ledger.py"), "--run", opt("--run"),
                         "--data", opt("--data"), "--latest", opt("--latest")]).returncode
    if MODE == "deviation" and "--reference-behaviour" not in a:
        p = os.path.join(opt("--data"), "ledger.json")
        led = json.load(open(p))
        led["entries"][sorted(led["entries"])[0]]["status"] = "fixed"
        json.dump(led, open(p, "w"))
    if MODE == "mutate":
        p = os.path.join(opt("--data"), "ledger.json")
        led = json.load(open(p))
        for i, e in enumerate(sorted(led["entries"])):
            led["entries"][e]["due_at"] = "2030-01-01T00:00:00Z"
            if i == 0:
                led["entries"][e]["status"] = "accepted"
        led["runs"][-1]["implementation"] = "go"
        json.dump(led, open(p, "w"))
    sys.exit(rc)
if a[:2] == ["ledger", "track"]:
    sys.exit(subprocess.run([sys.executable, os.path.join(ROOT, "core", "remediation.py"), "--data", opt("--data"),
                             "--instance", opt("--instance")] + (["--now", opt("--now")] if opt("--now") else [])).returncode)
sys.exit(2)
'''


class Impl(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.data = os.path.join(self.d, "data")
        os.makedirs(self.data)
        self.log = os.path.join(self.d, "fake-argv.log")

    def tearDown(self):
        shutil.rmtree(self.d)

    def fake(self, mode="pass"):
        p = os.path.join(self.d, "sp-go")
        with open(p, "w") as f:
            f.write(FAKE.format(python=sys.executable, root=os.path.abspath(ROOT), log=self.log, mode=mode))
        os.chmod(p, 0o755)
        return p

    def calls(self):
        return [json.loads(x) for x in open(self.log)] if os.path.exists(self.log) else []

    def instance(self, jobs=None, **runner_cfg):
        script = os.path.join(self.d, "collector.py")
        with open(script, "w") as f:
            f.write(f"import os,shutil; shutil.copy({FX!r}, os.path.join(os.environ['SP_RUN_DIR'], 'host.findings.json'))\n")
        jobs = jobs or {"host": {"type": "command", "collector": "host", "schedule": "* * * * *",
                                 "argv": [sys.executable, script]}}
        p = os.path.join(self.d, "instance.json")
        with open(p, "w") as f:
            json.dump({"name": "t", "runner": dict({"site": "hub", "role": "hub", "jobs": jobs}, **runner_cfg)}, f)
        return p

    def ledger(self):
        return json.load(open(os.path.join(self.data, "ledger.json")))

    def last_run_dir(self, job):
        return os.path.join(self.data, json.load(open(os.path.join(self.data, "state", "runner", f"{job}.json")))["last_run_dir"])

    def test_default_is_python(self):
        fake = self.fake()
        inst = self.instance(go_binary=fake)
        self.assertEqual(runner.main(["run", "--instance", inst, "--data", self.data, "host"]), 0)
        self.assertTrue(self.ledger()["entries"])
        self.assertEqual(self.calls(), [])                  # never probed nor run: python is the default

    def test_go_runs_only_go_with_the_contract_argv(self):
        fake = self.fake()
        inst = self.instance(implementations={"ledger": "go"}, go_binary=fake)
        self.assertEqual(runner.main(["run", "--instance", inst, "--data", self.data, "host"]), 0)
        (argv,) = self.calls()
        rd = self.last_run_dir("host")
        self.assertEqual(argv, ["ledger", "merge", "--run", rd, "--data", self.data, "--latest",
                                os.path.join(self.data, "latest"), "--instance", inst])
        self.assertIn("fake go ledger merge", open(os.path.join(rd, "ledger.log")).read())
        self.assertTrue(self.ledger()["entries"])
        self.assertFalse(glob.glob(os.path.join(rd, "shadow-*")))

    def test_go_without_binary_falls_back_to_python_and_logs_once(self):
        inst = self.instance(implementations={"ledger": "go"}, go_binary=os.path.join(self.d, "missing"))
        r = runner.Runner(inst, self.data)
        with mock.patch.object(runner, "log") as log:
            for _ in range(2):
                self.assertEqual(r.execute("host"), 0)
        msgs = [c.args[0] for c in log.call_args_list if "no Go sp binary" in c.args[0]]
        self.assertEqual(len(msgs), 1, msgs)
        self.assertTrue(self.ledger()["entries"])

    def test_not_the_go_binary_is_refused(self):
        # the tree's bin/sp is the Python CLI: it must fail the probe, never run as the ledger
        self.assertEqual(runner.probe_go(os.path.join(ROOT, "bin", "sp")), [])
        self.assertEqual(runner.probe_go(os.path.join(self.d, "missing")), [])
        self.assertEqual(runner.probe_go(self.fake()), ["ledger", "version"])

    def test_bad_config_is_logged_not_fatal(self):
        inst = self.instance(implementations={"ledger": "rust", "nope": "go"})
        with mock.patch.object(runner, "log") as log:
            r = runner.Runner(inst, self.data)
        self.assertEqual(r.impls, {})
        self.assertEqual(len(log.call_args_list), 2)

    def test_shadow_python_writes_go_is_diffed(self):
        fake = self.fake(mode="mutate")
        out = os.path.join(self.d, "sink", "m.prom")
        inst = self.instance(implementations={"ledger": "shadow"}, go_binary=fake,
                             sinks=[{"type": "textfile", "path": out}])
        self.assertEqual(runner.main(["tick", "--instance", inst, "--data", self.data]), 0)
        led = self.ledger()
        n = len(led["entries"])
        self.assertGreaterEqual(n, 1)
        # the real data is Python's: no due dates, no accepted entry, no go run record
        self.assertFalse([e for e in led["entries"].values() if "due_at" in e or e["status"] != "open"])
        self.assertNotIn("implementation", led["runs"][-1])
        argv, ref, _, _ = self.calls()      # the target run, then the attribution runs (reference behaviour)
        self.assertNotEqual(argv[argv.index("--data") + 1], self.data)     # a copy
        self.assertNotEqual(ref[ref.index("--data") + 1], argv[argv.index("--data") + 1])   # another copy
        self.assertIn("--now", argv)
        self.assertNotIn("--reference-behaviour", argv)
        self.assertEqual(ref[ref.index("--reference-behaviour") + 1], "LEDGER-D5")
        rd = self.last_run_dir("host")
        rep = json.load(open(os.path.join(rd, "shadow-ledger.json")))
        self.assertEqual((rep["python_rc"], rep["go_rc"]), (0, 0))
        # run_dir (relative to the data dir) is equal on both sides: the copy keeps the layout
        self.assertEqual(rep["unexplained"], 1, rep["differences"])
        self.assertEqual(rep["explained"], n)
        bad = [x for x in rep["differences"] if not x.get("explained")]
        self.assertRegex(bad[0]["path"], r"^entries\.[0-9a-f]{12}\.status$")
        self.assertEqual((bad[0]["python"], bad[0]["go"]), ('"open"', '"accepted"'))
        self.assertTrue(all(x["explained"] == "LEDGER-D2" for x in rep["differences"] if x.get("explained")))
        text = open(out).read()
        self.assertIn('security_impl_shadow_diffs{component="ledger",site="hub"} 1', text)
        self.assertIn(f'security_impl_shadow_explained_diffs{{component="ledger",site="hub"}} {n}', text)
        self.assertIn('security_impl_shadow_last_run_timestamp_seconds{component="ledger",site="hub"}', text)
        self.assertFalse(glob.glob(os.path.join(tempfile.gettempdir(), "sp-shadow-ledger-*")))

    def test_shadow_attributes_a_difference_the_reference_behaviour_removes(self):
        inst = self.instance(implementations={"ledger": "shadow"}, go_binary=self.fake(mode="deviation"))
        self.assertEqual(runner.main(["run", "--instance", inst, "--data", self.data, "host"]), 0)
        rep = json.load(open(os.path.join(self.last_run_dir("host"), "shadow-ledger.json")))
        self.assertEqual(rep["unexplained"], 0, rep["differences"])
        self.assertGreaterEqual(rep["explained"], 1)
        self.assertTrue(all(x["explained"] == "LEDGER-D5" for x in rep["differences"]), rep["differences"])

    def test_shadow_identical_implementation_has_no_diffs(self):
        inst = self.instance(implementations={"ledger": "shadow"}, go_binary=self.fake())
        for _ in range(2):          # second merge: previous ledger, fixes, runs[] of both sides
            self.assertEqual(runner.main(["run", "--instance", inst, "--data", self.data, "host"]), 0)
            rep = json.load(open(os.path.join(self.last_run_dir("host"), "shadow-ledger.json")))
            self.assertEqual((rep["unexplained"], rep["explained"]), (0, 0), rep["differences"])
            time.sleep(1.05)        # a new run directory (HHMMSS)

    def test_shadow_without_go_records_unavailable(self):
        inst = self.instance(implementations={"ledger": "shadow"}, go_binary=os.path.join(self.d, "missing"))
        self.assertEqual(runner.main(["run", "--instance", inst, "--data", self.data, "host"]), 0)
        st = json.load(open(os.path.join(self.data, "state", "runner", "shadow", "ledger.json")))
        self.assertFalse(st["go_available"])
        r = runner.Runner(inst, self.data)
        self.assertEqual(r.shadow_series(), [])

    def test_remediation_shadow_same_now_no_external_sync(self):
        fake = self.fake()
        inst = self.instance(implementations={"remediation": "shadow"}, go_binary=fake)
        self.assertEqual(runner.main(["run", "--instance", inst, "--data", self.data, "host"]), 0)
        inst = self.instance({"rem": {"type": "remediation", "schedule": "0 * * * *"}},
                             implementations={"remediation": "shadow"}, go_binary=fake)
        self.assertEqual(runner.main(["run", "--instance", inst, "--data", self.data, "rem"]), 0)
        (argv,) = self.calls()
        self.assertEqual(argv[:2], ["ledger", "track"])
        self.assertIn("--no-external-sync", argv)
        now = int(argv[argv.index("--now") + 1])
        items = json.load(open(os.path.join(self.data, "tracker", "items.json")))
        self.assertEqual(items["updated_at"], time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)))   # python got it too
        rep = json.load(open(os.path.join(self.last_run_dir("rem"), "shadow-remediation.json")))
        self.assertEqual((rep["unexplained"], rep["explained"]), (0, 0), rep["differences"])

    def test_reference_failure_attribution(self):
        spec = runner.COMPONENTS["ledger"]
        with open(os.path.join(self.d, "ledger.log"), "w") as f:
            f.write("Traceback (most recent call last):\n  ...\nKeyError: 'kind'\n")
        a = {"run_dir": self.d}
        self.assertEqual(runner.Runner.reference_failure(spec, a, 1), "LEDGER-D1")
        self.assertIsNone(runner.Runner.reference_failure(spec, a, 0))
        with open(os.path.join(self.d, "ledger.log"), "w") as f:
            f.write("PermissionError: data\n")
        self.assertIsNone(runner.Runner.reference_failure(spec, a, 1))

    def test_diff_helpers(self):
        out = []
        runner.jdiff({"a": 14, "b": [1, 2], "c": True}, {"a": 14.0, "b": [1], "c": 1}, "", out, "f")
        self.assertEqual([(x["path"], x["python"], x["go"]) for x in out], [("b[1]", "2", runner.ABSENT), ("c", "true", "1")])
        s, c = runner.prom_samples('# TYPE x gauge\nx{a="1"} 2\nhb 123\n', ("hb",))
        self.assertEqual((s, c), ({'x{a="1"}': "2"}, {"# TYPE x gauge"}))
        p, g = runner.norm_ledger({"updated_at": 1, "runs": [{"at": 1, "core": "a", "run_dir": "x"}]},
                                  {"updated_at": 2, "runs": [{"at": 2, "core": "b", "run_dir": "x", "implementation": "go"}]})
        self.assertEqual((p, g), ({"runs": [{"run_dir": "x"}]}, {"runs": [{"run_dir": "x"}]}))


if __name__ == "__main__":
    unittest.main()
