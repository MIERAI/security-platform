"""Host probes with their own time limits: the POSIX helper stops a slow command and reports it (no value, no leftover
process), the collector keeps every other check and turns only the unread ones into a narrow gap, a stopped script's
partial output is still used, and the ledger keeps a narrowly gapped finding unknown instead of fixing it."""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path[:0] = [ROOT, os.path.join(ROOT, "core"), os.path.join(ROOT, "sdk")]
import validate  # noqa: E402
from adapters import exec as ex  # noqa: E402
from spsdk import fid  # noqa: E402

PROFILES = os.path.join(ROOT, "collectors", "host", "profiles")
SHELLS = [s for s in ("/bin/sh", shutil.which("dash"), shutil.which("busybox") and "busybox-sh") if s]


def load_collector():
    spec = importlib.util.spec_from_file_location("hostcollector", os.path.join(ROOT, "collectors", "host", "collector.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def sh(shell, body, timeout=60):
    argv = ["busybox", "sh", "-s"] if shell == "busybox-sh" else [shell, "-s"]
    t = time.time()
    p = subprocess.run(argv, input=open(os.path.join(PROFILES, "probe.sh")).read() + body, capture_output=True,
                       text=True, timeout=timeout)
    return p.stdout, time.time() - t


class Helper(unittest.TestCase):
    def test_slow_command_is_stopped_and_reported(self):
        for shell in SHELLS:
            with self.subTest(shell=shell):
                out, took = sh(shell, "sp_probe a 5 'echo fast'\n"
                                      "sp_probe slow 1 'sleep 37 | cat; echo never'\n"
                                      "sp_lines listen 5 'echo listen=1; echo listen=2'\n"
                                      "sp_lines more 1 'sh -c \"sleep 38\"; echo listen=never'\n"
                                      "echo after=1\n")
                self.assertEqual(out.splitlines(), ["a=fast", "slow=unknown", "probe.timeout=slow", "listen=1",
                                                    "listen=2", "probe.timeout=more", "after=1"])
                self.assertLess(took, 15)
                ps = subprocess.run(["ps", "-A", "-o", "args="], capture_output=True, text=True).stdout
                self.assertNotIn("sleep 37", ps)   # the stopped command and its children are gone
                self.assertNotIn("sleep 38", ps)

    def test_limits_from_environment_and_stdin_untouched(self):
        # the profile arrives on stdin (sh -s): a probe reading stdin must not swallow the rest of the script
        # a limit that is not a number falls back to the default instead of "timed out at once"
        out, _ = sh("/bin/sh", "SP_PROBE_TIMEOUT=7\nsp_probe t 5 'echo $SP_PROBE_TIMEOUT'\nsp_probe r 5 'cat'\n"
                               "sp_probe x '' 'echo ok'\necho rest=1\n")
        self.assertEqual(out.splitlines(), ["t=7", "r=", "x=ok", "rest=1"])


class ExecPartial(unittest.TestCase):
    def test_partial_output_on_timeout(self):
        e = ex.executor({"type": "local"})
        t = time.time()
        rc, out, err = e.run(["sh", "-c", "echo a=1; sleep 39; echo b=2"], timeout=1, partial=True)
        self.assertEqual((rc, out, err), (124, "a=1\n", "timeout"))
        self.assertLess(time.time() - t, 8)
        self.assertNotIn("sleep 39", subprocess.run(["ps", "-A", "-o", "args="], capture_output=True, text=True).stdout)
        self.assertEqual(e.run(["sh", "-c", "echo a=1; sleep 5"], timeout=1)[:2], (124, ""))   # default: all or nothing


MAC = ("os.name=macOS 99.1 (X)\ndisk.filevault=off\nfw.app_firewall=on\nfw.stealth=on\nsip=on\ngatekeeper=on\n"
       "ssh.remote_login=off\npkg.auto_install_os=1\npkg.auto_security=1\nuptime_days=3\nlisten=127.0.0.1:5432 pg\n"
       "pkg.brew_outdated=2\n")


class Collector(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.m = load_collector()
        self.env = {k: os.environ.get(k) for k in ("SP_INSTANCE", "SP_RUN_DIR")}

    def tearDown(self):
        shutil.rmtree(self.d)
        for k, v in self.env.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)

    def run_host(self, rc, out, profile="macos"):
        inst = os.path.join(self.d, "instance.json")
        json.dump({"name": "t", "hosts": [{"name": "m", "exec": {"type": "local"}, "profile": profile}]}, open(inst, "w"))
        run = os.path.join(self.d, "run")
        os.environ.update(SP_INSTANCE=inst, SP_RUN_DIR=run)
        self.m.collect = lambda h: (rc, out, "timeout" if rc == 124 else "", self.m.script_for(h))
        self.m.main()
        doc = json.load(open(os.path.join(run, "host.findings.json")))
        self.assertEqual(validate.validate_findings(doc), [])
        return doc, {f["check"] for f in doc["findings"]}, {g["asset"]: g for g in doc["coverage"]}

    def test_timed_out_probe_is_a_narrow_gap(self):
        doc, checks, cov = self.run_host(0, MAC + "pkg.os_updates_pending=unknown\nprobe.timeout=pkg.os_updates_pending\n"
                                                  "probe.end=1\n")
        self.assertEqual(checks, {"macos.disk_filevault_off"})         # every other check still reports
        self.assertEqual(cov["host:m"]["status"], "ok")
        g = cov["host:m/os-updates"]
        self.assertEqual((g["status"], g["checks"]), ("gap", ["patch.os_updates_pending"]))
        self.assertIn("could not check", g["reason"])
        self.assertEqual(len(cov), 2)

    def test_complete_run_has_no_gap(self):
        doc, checks, cov = self.run_host(0, MAC + "pkg.os_updates_pending=4\nprobe.end=1\n")
        self.assertEqual(checks, {"macos.disk_filevault_off", "patch.os_updates_pending"})
        self.assertEqual(list(cov), ["host:m"])

    def test_script_stopped_keeps_partial_output(self):
        partial = "os.name=macOS 99.1 (X)\ndisk.filevault=off\nfw.app_firewall=off\nfw.stealth=on\nsip=on\n"
        doc, checks, cov = self.run_host(124, partial)
        self.assertEqual(checks, {"macos.disk_filevault_off", "macos.fw_app_firewall_off"})
        self.assertEqual(cov["host:m"]["status"], "ok")
        self.assertEqual(sorted(a for a, g in cov.items() if g["status"] == "gap"),
                         ["host:m/brew", "host:m/gatekeeper", "host:m/listeners", "host:m/os-updates"])
        self.assertIn("not reached", cov["host:m/gatekeeper"]["reason"])
        self.assertFalse([x for x in doc.get("metrics", []) if x["name"] == "security_host_wildcard_listeners"])

    def test_nothing_printed_is_still_a_host_gap(self):
        doc, checks, cov = self.run_host(124, "")
        self.assertEqual(list(cov), ["host:m"])
        self.assertEqual(cov["host:m"]["status"], "gap")

    def test_part_with_one_unread_key_reports_nothing(self):
        # ufw inactive and iptables ACCEPT, but nft timed out: "no host firewall" would be a guess
        out = ("fw.ufw=inactive\nfw.nft_input_policy=unknown\nprobe.timeout=fw.nft_input_policy\n"
               "fw.iptables_input_policy=ACCEPT\nsshd.passwordauthentication=yes\nprobe.end=1\n")
        doc, checks, cov = self.run_host(0, out, profile="linux")
        self.assertEqual(checks, {"ssh.password_auth_enabled"})
        self.assertEqual(cov["host:m/firewall"]["checks"], ["fw.host_firewall_off"])

    def test_every_profile_probe_is_known(self):
        informational = {"os.name", "uptime_days", "ssh.remote_login", "pkg.auto_install_os", "pkg.auto_security",
                         "disk.crypt_devices", "audit.auditd", "audit.fail2ban", "pkg.count"}
        for prof in ("linux", "macos", "termux", "busybox", "windows"):
            keys = self.m.planned(self.m.script_for({"profile": prof}))
            self.assertTrue(keys, prof)
            for k in keys:
                self.assertTrue(k in informational or self.m.narrow_gaps({k: "x"}), (prof, k))
        for prof in ("probe.ps1", "windows.ps1"):
            open(os.path.join(PROFILES, prof), "rb").read().decode("ascii")   # legacy code page remotely


class Ledger(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.n = 0

    def tearDown(self):
        shutil.rmtree(self.d)

    def finding(self, check):
        return {"id": fid("host", "host:m", check), "check": check, "layer": "host", "asset": "host:m", "title": check,
                "severity": "medium", "evidence": "raw/host/m.json", "remediation": "x", "needs_human": False,
                "owner": "platform", "observed_at": "2026-11-24T08:00:00Z", "kind": "compliance"}

    def run_ledger(self, findings, coverage):
        self.n += 1
        r = os.path.join(self.d, "runs", str(self.n))
        os.makedirs(r)
        d = {"schema_version": "1.2", "collector": {"name": "host", "version": "0.3.0"},
             "run": {"started_at": "2026-11-24T08:00:00Z", "finished_at": f"2026-11-2{4 + self.n}T09:00:00Z"},
             "coverage": coverage, "findings": findings}
        self.assertEqual(validate.validate_findings(d), [])
        json.dump(d, open(os.path.join(r, "host.findings.json"), "w"))
        subprocess.run([sys.executable, os.path.join(ROOT, "core", "ledger.py"), "--run", r, "--data", self.d],
                       check=True, capture_output=True)
        return {e["check"]: e for e in json.load(open(os.path.join(self.d, "ledger.json")))["entries"].values()}

    def test_narrow_gap_keeps_only_its_checks_unknown(self):
        ok = {"asset": "host:m", "status": "ok"}
        E = self.run_ledger([self.finding("patch.os_updates_pending"), self.finding("macos.disk_filevault_off")], [ok])
        self.assertEqual({k: e["status"] for k, e in E.items()},
                         {"patch.os_updates_pending": "open", "macos.disk_filevault_off": "open"})
        gap = {"asset": "host:m/os-updates", "status": "gap", "reason": "timed out", "checks": ["patch.os_updates_pending"]}
        E = self.run_ledger([], [ok, gap])
        self.assertEqual(E["patch.os_updates_pending"]["status"], "open")       # could not check: unknown, not fixed
        self.assertEqual(E["macos.disk_filevault_off"]["status"], "fixed")      # checked and gone: fixed
        E = self.run_ledger([], [ok])
        self.assertEqual(E["patch.os_updates_pending"]["status"], "fixed")


if __name__ == "__main__":
    unittest.main()
