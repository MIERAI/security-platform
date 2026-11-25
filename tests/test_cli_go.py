"""The Go `sp` (internal/cli) against the reference cli/sp.py: the cli conformance cases with NO expected failures,
and every command's output compared byte for byte on the same data directory - plain and on a terminal (colors).
The contract fixes only the machine-readable outputs and the parse-stable lines (contracts/cli/SPEC.md §2); this test
keeps the rest identical too, so a wording change is a decision made in both places. Skipped without a Go toolchain
that can build cmd/sp, or without PyYAML. SP_SKIP_GO=1 skips it."""
import json
import os
import pty
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(ROOT, "tests"))
from test_runner_go import build_sp  # noqa: E402


def iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def entry(i, check, sev, layer="host", status="open", first=None, **kw):
    now = time.time()
    e = {"id": i, "check": check, "layer": layer, "asset": f"host:node-{i[:3]}", "title": f"{check} on node {i[:3]}",
         "severity": sev, "status": status, "first_seen": first or iso(now - 3 * 86400), "last_seen": iso(now - 600),
         "fixed_at": None, "reopened_count": 0, "evidence": f"raw/host/{i}.json#x", "remediation": "", "needs_human": False,
         "collector": "host", "kind": "compliance"}
    e.update(kw)
    return e


def dump(obj, *path, **kw):
    with open(os.path.join(*path), "w") as f:
        json.dump(obj, f, **kw)


def read(*path):
    with open(os.path.join(*path)) as f:
        return f.read()


def data_dir(root):
    now = time.time()
    d = os.path.join(root, "data")
    os.makedirs(os.path.join(d, "tracker"))
    os.makedirs(os.path.join(d, "state", "runner"))
    os.makedirs(os.path.join(d, "latest"))
    os.makedirs(os.path.join(d, "scorecard"))
    os.chmod(d, 0o700)
    E = [entry("a1b2c3d4e5f6", "ssh.password_auth_enabled", "critical", first=iso(now - 3600), remediation="PasswordAuthentication no"),
         entry("a1b2c3000000", "vuln.cve-2099-0002", "high", layer="supply-chain", asset="image:registry.example/app:1.0",
               needs_human=True, reopened_count=2),
         entry("b00000000001", "k8s.pod.privileged", "high", layer="workload", title="Privileged pod " + "x" * 80),
         entry("b00000000002", "conformance.unknown_check", "medium", asset="host:" + "é" * 45),
         entry("b00000000003", "patch.pending", "low", status="fixed", fixed_at=iso(now - 3600)),
         entry("b00000000004", "macos.firewall_off", "info"),
         entry("b00000000005", "secret.file_readable", "critical", first=iso(now - 1800))]
    led = {"schema": "security-platform/ledger/v1", "entries": {e["id"]: e for e in E},
           "sli": {"patch_latency": {"ok": True, "value": 2}, "mfa": {"ok": False, "value": 0.25}}, "collectors": {"host": {}}}
    dump(led, d, "ledger.json", indent=1)
    items = {"items": {"a1b2c3d4e5f6": {"id": "a1b2c3d4e5f6", "status": "open", "overdue": True, "owner": "ops",
                                        "due_at": iso(now - 86400)},
                       "b00000000001": {"id": "b00000000001", "status": "open", "overdue": False, "owner": "unassigned",
                                        "due_at": "2030-01-31T23:30:00Z"}}}
    dump(items, d, "tracker", "items.json")
    dump({"overall": 61.25, "status": "FAIL", "threshold": 75,
               "dimensions": [{"id": "people", "score": 61.25}, {"id": "devices", "score": 80}, {"name": "network", "score": None}],
               "pillars": {"network": {"score": 80.0}, "people": 40}}, d, "scorecard", "latest.json")
    states = {"host": {"runs_total": 3, "last_rc": 0, "last_success": now - 7300, "done_slot": now - 7400, "last_duration": 12.5},
              "k8s": {"runs_total": 2, "last_rc": 3, "last_success": now - 90000, "last_note": "collector exited rc=3"},
              "remediation": {"runs_total": 9, "last_rc": 0, "last_success": now - 2820, "done_slot": now - 2880}}
    for n, s in states.items():
        dump(dict(s, schema="security-platform/runner-state/v1", job=n), d, "state", "runner", n + ".json")
    dump({"schema_version": "1.2", "collector": {"name": "host", "version": "1"}, "findings": [],
               "coverage": [{"asset": "host:a", "status": "gap", "reason": "ssh: timeout " + "y" * 120},
                            {"asset": "host:b", "status": "ok"}]}, d, "latest", "host.findings.json")
    inst = {"name": "diff", "hosts": [{"name": "this", "exec": {"type": "local"}}],
            "notify": [{"type": "file", "path": os.path.join(root, "out.txt")}],
            "runner": {"site": "hub", "role": "hub", "jobs": {
                "host": {"schedule": "15 2 * * *"}, "k8s": {"schedule": "45 2 * * *"},
                "remediation": {"type": "remediation", "schedule": "*/10 * * * *"}, "never": {"collector": "host", "schedule": "0 4 * * *"},
                "digest": {"type": "digest", "schedule": "0 9 * * 1"}}}}
    with open(os.path.join(d, "instance.json"), "w") as f:
        json.dump(inst, f)
    os.chmod(os.path.join(d, "instance.json"), 0o600)
    return d


class SameAsPython(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="sp-go-cli-")
        cls.sp = build_sp(os.path.join(cls.tmp, "sp"))
        cls.env = dict({k: v for k, v in os.environ.items() if not k.startswith("SP_") and k != "NO_COLOR"},
                       SP_PY_HOME=ROOT, SP_PYTHON=sys.executable, TZ="UTC", LC_ALL="C")
        cls.data = data_dir(cls.tmp)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def impl(self, which):
        return [self.sp] if which == "go" else [sys.executable, os.path.join(ROOT, "cli", "sp.py")]

    def run_both(self, args, env=None, tty=False):
        out = {}
        for which in ("python", "go"):
            e = dict(self.env, **(env or {}))
            if not tty:
                e["NO_COLOR"] = "1"
                p = subprocess.run(self.impl(which) + args, env=e, capture_output=True, text=True, timeout=120)
                out[which] = (p.returncode, p.stdout, p.stderr)
            else:
                out[which] = run_on_terminal(self.impl(which) + args, e)
        return out

    def assertSame(self, args, env=None, tty=False):
        for attempt in range(2):     # a minute boundary between the two runs changes an "ago": once more
            out = self.run_both(args, env, tty)
            if out["python"] == out["go"] or attempt:
                break
        self.assertEqual(out["python"], out["go"], f"sp {' '.join(args)} differs")
        return out["go"]

    def test_conformance_without_expected_failures(self):
        p = subprocess.run([sys.executable, os.path.join(ROOT, "conformance", "run.py"), "--impl",
                            f"cli={os.path.join(ROOT, 'conformance', 'impl', 'go', 'cli')}", "--component", "cli", "--require-all"],
                           env=dict(self.env, SP_GO_SP=self.sp), capture_output=True, text=True, timeout=900)
        self.assertEqual(p.returncode, 0, p.stdout[-4000:] + p.stderr[-2000:])
        self.assertIn("fail=0", p.stdout)
        self.assertIn("xfail=0", p.stdout)

    def test_findings(self):
        D = ["--data", self.data]
        for args in ([], ["--open"], ["--severity", "medium"], ["--json"], ["--ids"], ["--layer", "host"], ["--check", "ssh"],
                     ["--overdue", "--json"], ["--check", "nothing"], ["--open", "--severity", "high", "--ids"]):
            with self.subTest(args=args):
                rc, _, _ = self.assertSame(["findings"] + args + D)
                self.assertEqual(rc, 0)

    def test_status_explain_digest(self):
        D = ["--data", self.data]
        self.assertSame(["status"] + D)
        led = json.loads(read(self.data, "ledger.json"))
        for i in list(led["entries"]) + ["a1b2c3d4"]:
            with self.subTest(explain=i):
                self.assertSame(["explain", i] + D)
        for args in (["--daily"], ["--days", "30"], ["--days", "0"]):
            with self.subTest(digest=args):
                self.assertSame(["digest"] + args + D)
        self.assertSame(["notify", "--dry-run"] + D)
        self.assertSame(["notify", "--dry-run", "--days", "7"] + D)

    def test_on_a_terminal(self):
        D = ["--data", self.data]
        for args in (["status"], ["findings"], ["findings", "--open"], ["explain", "a1b2c3d4e5f6"], ["explain", "b00000000002"],
                     ["digest"]):
            with self.subTest(args=args):
                self.assertSame(args + D, tty=True)

    def test_doctor(self):
        rc, out, _ = self.assertSame(["doctor", "--data", self.data])
        self.assertIn("ready: sp run", out)
        bad = os.path.join(self.tmp, "bad")
        os.makedirs(bad, mode=0o755, exist_ok=True)
        os.chmod(bad, 0o755)
        with open(os.path.join(bad, "instance.yaml"), "w") as f:
            f.write("name: bad\nrunner:\n  jobs:\n    x: {collector: nope}\n    k: {collector: k8s}\n"
                    f"codehost:\n  - {{type: github, token_file: {bad}/missing.token}}\n")
        self.assertSame(["doctor", "--data", bad], env={"PATH": "/nonexistent"})
        self.assertSame(["doctor", "--data", bad], tty=True, env={"PATH": "/nonexistent"})

    def test_init(self):
        outs, files = {}, {}
        for which in ("python", "go"):
            d = os.path.join(self.tmp, "init-" + which, "lab")
            p = subprocess.run(self.impl(which) + ["init", d, "--name", "lab"], env=dict(self.env, NO_COLOR="1"),
                               capture_output=True, text=True, timeout=60)
            again = subprocess.run(self.impl(which) + ["init", d], env=dict(self.env, NO_COLOR="1"), capture_output=True,
                                   text=True, timeout=60)
            outs[which] = [(x.returncode, x.stdout.replace(d, "<D>"), x.stderr) for x in (p, again)]
            files[which] = {f: read(d, f) for f in ("instance.yaml", "exceptions.yaml", ".gitignore")}
            self.assertEqual(os.stat(d).st_mode & 0o777, 0o700)
            self.assertEqual(os.stat(os.path.join(d, "instance.yaml")).st_mode & 0o777, 0o600)
        self.assertEqual(outs["python"], outs["go"])
        self.assertEqual(files["python"], files["go"])

    def test_errors(self):
        self.assertSame(["status"])
        self.assertSame(["findings", "--data", os.path.join(self.tmp, "missing")])
        self.assertSame(["explain", "ffffffff", "--data", self.data])
        self.assertSame(["status", "--data", self.tmp, "--instance", os.path.join(self.tmp, "nope.yaml")])
        self.assertSame(["run", "nope", "--data", self.data])
        self.assertSame(["notify", "--data", os.path.join(self.tmp, "init-go", "lab")])


def run_on_terminal(argv, env):
    """Runs argv with a pseudo-terminal as stdout (colors on); stderr is a pipe."""
    master, slave = pty.openpty()
    p = subprocess.Popen(argv, env=env, stdout=slave, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
    os.close(slave)
    chunks = []
    while True:
        try:
            b = os.read(master, 65536)
        except OSError:
            break
        if not b:
            break
        chunks.append(b)
    err = p.stderr.read().decode()
    p.stderr.close()
    p.wait(timeout=60)
    os.close(master)
    return p.returncode, re.sub(r"\r\n", "\n", b"".join(chunks).decode()), err


if __name__ == "__main__":
    unittest.main()
