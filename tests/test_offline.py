"""Offline operation: a tick needs no network. Dependencies are installed once at deploy time (render.py env); the
wrapper never resolves packages; collectors that need the network fail on their own; errors reach the runner log."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path[:0] = [os.path.join(ROOT, "deploy")]
import render  # noqa: E402

FX = os.path.join(ROOT, "tests", "fixtures", "host.findings.json")

# Loaded by every Python process of the tick (PYTHONPATH): any connection attempt fails as if the host were offline,
# and is recorded, so the test can tell "blocked" from "never tried".
BLOCK = textwrap.dedent("""
    import errno, os, socket
    def _blocked(*a, **k):
        with open(os.environ["SP_TEST_NET_LOG"], "a") as f:
            f.write(repr(a[1:2]) + "\\n")
        raise OSError(errno.ENETUNREACH, "Network is unreachable (blocked by test)")
    socket.socket.connect = _blocked
    socket.socket.connect_ex = _blocked
    socket.getaddrinfo = lambda *a, **k: _blocked(None, a[0])
""")


class Offline(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.install = os.path.join(self.d, "install")
        os.makedirs(self.install)
        os.symlink(ROOT, os.path.join(self.install, "current"))
        self.data = os.path.join(self.d, "data")
        self.block = os.path.join(self.d, "block")
        os.makedirs(self.block)
        open(os.path.join(self.block, "sitecustomize.py"), "w").write(BLOCK)
        self.netlog = os.path.join(self.d, "net.log")
        self.fakebin = os.path.join(self.d, "bin")       # package managers that must never be called by a tick
        os.makedirs(self.fakebin)
        self.marker = os.path.join(self.d, "package-manager-called")
        for pm in ("uv", "pip", "pip3", "pipx"):
            p = os.path.join(self.fakebin, pm)
            open(p, "w").write(f"#!/bin/sh\necho \"$0 $*\" >> {self.marker}\nexit 1\n")
            os.chmod(p, 0o755)

    def tearDown(self):
        shutil.rmtree(self.d)

    def env(self):
        return dict(os.environ, PYTHONPATH=self.block, SP_TEST_NET_LOG=self.netlog)

    def job(self, code):
        p = os.path.join(self.d, f"job{len(os.listdir(self.d))}.py")
        open(p, "w").write(code)
        return {"type": "command", "collector": "host", "schedule": "* * * * *", "argv": [sys.executable, p]}

    def wrapper(self, instance, python=sys.executable):
        args = ["wrapper", "--install", self.install, "--instance", instance, "--data", self.data,
                "--path", f"{self.fakebin}:/usr/bin:/bin", "--shell", "/bin/sh"]
        out = subprocess.run([sys.executable, os.path.join(ROOT, "deploy", "render.py")] + args +
                             (["--python", python] if python else []), capture_output=True, text=True, check=True).stdout
        p = os.path.join(self.install, "tick.sh")
        open(p, "w").write(out)
        return p, out

    def test_tick_succeeds_with_the_network_down(self):
        sink = os.path.join(self.d, "sink", "m.prom")
        local = self.job(f"import os,shutil; shutil.copy({FX!r}, os.path.join(os.environ['SP_RUN_DIR'], 'host.findings.json'))\n")
        online = dict(self.job("import urllib.request; urllib.request.urlopen('https://pypi.org/simple/pyyaml/', timeout=5)\n"),
                      collector="vuln-intel")
        inst = os.path.join(self.d, "instance.json")
        json.dump({"name": "t", "runner": {"site": "hub", "role": "hub", "sinks": [{"type": "textfile", "path": sink}],
                                           "jobs": {"local": local, "online": online}}}, open(inst, "w"))
        tick, text = self.wrapper(inst)
        self.assertNotRegex(text, r"uv run|--with")
        self.assertIn("UV_OFFLINE=1", text)
        p = subprocess.run(["/bin/sh", tick], env=self.env(), capture_output=True, text=True, timeout=120)
        log = open(os.path.join(self.data, "state", "runner", "tick.log")).read()
        self.assertEqual(p.returncode, 0, log)
        self.assertFalse(os.path.exists(self.marker), "a tick called a package manager")
        self.assertTrue(os.path.exists(self.netlog), "the network-dependent job did not even try (test is broken)")
        st = lambda j: json.load(open(os.path.join(self.data, "state", "runner", f"{j}.json")))  # noqa: E731
        self.assertEqual(st("local")["last_rc"], 0, log)
        self.assertNotEqual(st("online")["last_rc"], 0)          # fails on its own ...
        self.assertTrue(json.load(open(os.path.join(self.data, "ledger.json")))["entries"])   # ... the rest goes on
        m = open(sink).read()
        self.assertIn("security_runner_tick_timestamp_seconds", m)
        self.assertIn('security_runner_job_failures_total{job="online",site="hub"} 1', m)
        self.assertIn("online: rc=", log)

    def test_errors_reach_the_log(self):
        inst = os.path.join(self.d, "instance.json")
        open(inst, "w").write("{not json")
        tick, _ = self.wrapper(inst)
        p = subprocess.run(["/bin/sh", tick], env=self.env(), capture_output=True, text=True, timeout=60)
        self.assertNotEqual(p.returncode, 0)
        log = open(os.path.join(self.data, "state", "runner", "tick.log")).read()
        self.assertIn("cannot start", log)
        self.assertIn("tick.sh: runner exited rc=78", log)

    def test_online_python_is_refused_and_triggers_log_somewhere(self):
        with self.assertRaises(SystemExit):
            render.main(["wrapper", "--install", self.install, "--instance", "i", "--data", self.data,
                         "--python", "/usr/bin/uv run -q --with pyyaml python3"])
        a = render.argparse.Namespace(install=self.install, instance="i", data=self.data, label="l", interval=900,
                                      log=None, nice=10, job_id=1)
        for out in (render.launchd(a), render.cron(a), render.systemd(a)):
            self.assertNotIn("/dev/null", out)
            self.assertIn(os.path.join(self.data, "state", "runner", "tick.log"), out)

    def test_env_is_built_once_and_used_offline(self):
        lock = os.path.join(self.d, "empty.lock")     # no third-party packages: building needs no index at all
        open(lock, "w").write("# nothing pinned\n")
        subprocess.run([sys.executable, os.path.join(ROOT, "deploy", "render.py"), "env", "--install", self.install,
                        "--lock", lock, "--installer", "pip", "--python", sys.executable], env=self.env(),
                       check=True, capture_output=True, timeout=300)
        py = os.path.join(self.install, "env", "bin", "python3")
        self.assertTrue(os.path.exists(py))
        inst = os.path.join(self.d, "instance.json")
        json.dump({"name": "t", "runner": {"site": "hub", "role": "site", "outbox": {"type": "local", "dir": os.path.join(self.d, "out")},
                                           "jobs": {}}}, open(inst, "w"))
        tick, text = self.wrapper(inst, python=None)          # default interpreter = the built environment
        self.assertIn(py, text)
        p = subprocess.run(["/bin/sh", tick], env=self.env(), capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, open(os.path.join(self.data, "state", "runner", "tick.log")).read())

    def test_lock_pins_exact_versions_with_hashes(self):
        lock = os.path.join(ROOT, "deploy", "requirements.lock")
        reqs = render.requirements(lock)
        self.assertTrue(reqs)
        text = open(lock).read()
        blocks = [b for b in text.split("\n") if b and not b.startswith((" ", "#"))]
        self.assertEqual(len(blocks), len(reqs), "every requirement is name==version")
        self.assertGreaterEqual(text.count("--hash=sha256:"), len(reqs))
        df = open(os.path.join(ROOT, "Dockerfile")).read()
        self.assertIn("--require-hashes -r deploy/requirements.lock", df, "the image installs the same lock")


if __name__ == "__main__":
    unittest.main()
