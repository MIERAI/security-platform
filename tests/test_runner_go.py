"""The Go runner (`sp runner`, internal/runner, docs/runner.md): the black-box conformance suite with NO expected
failures, and one data directory switched back and forth between the Go and the Python runner (both directions)
without losing or repeating a run. Skipped when no Go toolchain can build cmd/sp (go.mod names the version) or the
interpreter lacks PyYAML (the suite's reference parts read YAML). SP_SKIP_GO=1 skips it."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
EMIT = """#!/bin/sh
set -e
n=$(cat "$STATE/$JOB.n" 2>/dev/null || echo 0)
echo $((n + 1)) > "$STATE/$JOB.n"
case " $FAIL_RUNS " in *" $n "*) exit 3;; esac
cp "$DOC" "$SP_RUN_DIR/${SP_COLLECTOR_NAME:-$JOB}.findings.json"
"""
KEYS = ("runs_total", "failures_total", "last_rc", "last_note", "slot", "attempts", "done_slot")


def build_sp(out):
    if os.environ.get("SP_SKIP_GO"):
        raise unittest.SkipTest("SP_SKIP_GO set")
    go = shutil.which("go")
    if not go:
        raise unittest.SkipTest("no Go toolchain")
    try:
        import yaml  # noqa: F401
    except ImportError:
        raise unittest.SkipTest("PyYAML not installed")
    p = subprocess.run([go, "build", "-o", out, "./cmd/sp"], cwd=ROOT, capture_output=True, text=True, timeout=600)
    if p.returncode:
        raise unittest.SkipTest(f"cannot build cmd/sp: {p.stderr[-300:]}")
    return out


class GoRunner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="sp-go-runner-")
        cls.sp = build_sp(os.path.join(cls.tmp, "sp"))
        cls.env = dict({k: v for k, v in os.environ.items() if not k.startswith("SP_")}, SP_PY_HOME=ROOT,
                       SP_PYTHON=sys.executable, TZ="UTC", LC_ALL="C")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_conformance_without_expected_failures(self):
        for component, impl in (("runner", f"{self.sp} runner"), ("cli", os.path.join(ROOT, "conformance", "impl", "python", "cli"))):
            with self.subTest(component=component):
                p = subprocess.run([sys.executable, os.path.join(ROOT, "conformance", "run.py"), "--impl", f"{component}={impl}",
                                    "--component", component, "--require-all"], env=self.env, capture_output=True, text=True,
                                   timeout=900)
                self.assertEqual(p.returncode, 0, p.stdout[-4000:] + p.stderr[-2000:])
                self.assertIn("fail=0", p.stdout)
                self.assertIn("xfail=0", p.stdout)

    def runner(self, which):
        return [self.sp, "runner"] if which == "go" else [sys.executable, os.path.join(ROOT, "runner", "runner.py")]

    def setup_instance(self, d):
        os.makedirs(os.path.join(d, "emit"))
        emit = os.path.join(d, "emit.sh")
        with open(emit, "w") as f:
            f.write(EMIT)
        doc = os.path.join(ROOT, "tests", "fixtures", "host.findings.json")

        def job(name, schedule, **kw):
            env = {"JOB": name, "STATE": os.path.join(d, "emit"), "DOC": doc, "FAIL_RUNS": kw.pop("fail", "")}
            return dict({"type": "command", "collector": "host", "as": name, "argv": ["/bin/sh", emit],
                         "schedule": schedule, "env": env}, **kw)
        inst = {"name": "switch", "scorecard": {"enabled": False}, "runner": {"site": "hub", "role": "hub", "jobs": {
            "hourly": job("hourly", "0 * * * *", jitter="10m"),
            "flaky": job("flaky", "30 * * * *", retries=1, retry_delay="10m", fail="1 2 5"),
            "nightly": job("nightly", "30 3 * * *", max_delay="1h"),
            "quarter": job("quarter", "*/15 * * * *")}}}
        with open(os.path.join(d, "instance.json"), "w") as f:
            json.dump(inst, f)

    def tick(self, which, d, now):
        p = subprocess.run(self.runner(which) + ["tick", "--instance", os.path.join(d, "instance.json"), "--data",
                                                 os.path.join(d, "data"), "--now", str(now)],
                           env=self.env, capture_output=True, text=True, timeout=300)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertNotIn("cannot start", p.stderr)
        self.assertNotIn("Traceback", p.stderr)
        return p.stderr

    def states(self, d):
        sd = os.path.join(d, "data", "state", "runner")
        out = {}
        for n in sorted(os.listdir(sd)):
            if n.endswith(".json") and n != "sinks.json":
                with open(os.path.join(sd, n)) as f:
                    st = json.load(f)
                out[n[:-5]] = {k: st.get(k) for k in KEYS}
        return out

    def status(self, which, d, now):
        p = subprocess.run(self.runner(which) + ["status", "--instance", os.path.join(d, "instance.json"), "--data",
                                                 os.path.join(d, "data"), "--now", str(now)],
                           env=self.env, capture_output=True, text=True, timeout=120, check=True)
        return {k: v["due"] for k, v in json.loads(p.stdout).items()}

    def test_one_data_directory_switched_back_and_forth(self):
        """Three copies tick at the same fake instants: Python only, Go only, and alternating (P, G, P, G, ... and
        whole blocks of each). The alternating copy must match the Python-only copy after every tick (runs, failures,
        slots, retries), and both runners must read each other's files and agree on what is due."""
        dirs = {k: os.path.join(self.tmp, f"switch-{k}") for k in ("python", "go", "mixed")}
        for d in dirs.values():
            self.setup_instance(d)
        t0 = 1894060800          # 2030-01-08T00:00:00Z
        order = ["python", "go"] * 8 + ["go"] * 6 + ["python"] * 6 + ["go", "python"] * 4
        for i, which in enumerate(order):
            now = t0 + i * 900
            if 3 * 3600 <= now - t0 < 5 * 3600:        # host off: nightly's 03:30 slot is missed (max_delay 1h)
                continue
            self.tick("python", dirs["python"], now)
            self.tick("go", dirs["go"], now)
            self.tick(which, dirs["mixed"], now)
            sp, sm = self.states(dirs["python"]), self.states(dirs["mixed"])
            for job, st in sp.items():
                self.assertEqual(sm.get(job), st, f"tick {i} at {now} by {which}: {job}")
            self.assertEqual(self.states(dirs["go"]).keys() - {"nightly"}, sp.keys() - {"nightly"})
            due_p, due_g = self.status("python", dirs["mixed"], now), self.status("go", dirs["mixed"], now)
            self.assertEqual(due_p, due_g, f"status after tick {i} at {now}")
        with open(os.path.join(dirs["mixed"], "data", "state", "runner", "flaky.json")) as f:
            st = json.load(f)
        self.assertGreater(st["failures_total"], 0)
        self.assertGreater(st["runs_total"], st["failures_total"])


    def test_implementation_switch_like_the_python_runner(self):
        """runner.implementations (contract runner §7): the Go runner selects, falls back and shadows exactly as the
        Python runner: the same job results, shadow reports, shadow state and shadow metrics."""
        out = {}
        for which in ("python", "go"):
            d = os.path.join(self.tmp, f"impl-{which}")
            self.setup_instance(d)
            with open(os.path.join(d, "instance.json")) as f:
                inst = json.load(f)
            inst["runner"].update(go_binary=self.sp, implementations={"ledger": "shadow", "remediation": "go",
                                                                      "scorecard": "go"})
            inst["runner"]["jobs"] = {"quarter": inst["runner"]["jobs"]["quarter"],
                                      "remediation": {"type": "remediation", "schedule": "*/15 * * * *"}}
            with open(os.path.join(d, "instance.json"), "w") as f:
                json.dump(inst, f)
            log = self.tick(which, d, 1894060800)
            self.assertEqual(log.count("runner.implementations.scorecard: 'go' ignored"), 1, log)
            data = os.path.join(d, "data")
            with open(os.path.join(data, "state", "runner", "shadow", "ledger.json")) as f:
                sh = json.load(f)
            reports = [p for p, _, fs in os.walk(os.path.join(data, "runs")) for x in fs if x == "shadow-ledger.json"]
            with open(os.path.join(data, "metrics", "security-platform.prom")) as f:
                prom = [x.split(" ")[0] for x in f if x.startswith("security_impl_shadow")]
            out[which] = {"state": {k: sh.get(k) for k in ("component", "go_available", "unexplained", "python_rc", "go_rc")},
                          "reports": len(reports), "prom": prom, "states": self.states(d)}
        self.assertEqual(out["python"]["state"]["go_available"], True)
        self.assertEqual(out["python"], out["go"])


if __name__ == "__main__":
    unittest.main()
