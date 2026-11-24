"""Host software inventory and platform advisories: profile parsing, distro SBOM, kernel bucketing, Android / Apple /
MSRC / vendor-KEV matching, vendor headline extraction (candidates only), Windows argv quoting and the PowerShell
bootstrap (scripts of any length through stdin), and the ledger's time-to-know baseline."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path[:0] = [ROOT, os.path.join(ROOT, "collectors", "vuln-intel"), os.path.join(ROOT, "collectors", "host-sbom")]
from adapters import exec as ex  # noqa: E402
from adapters import feeds  # noqa: E402
import hostmatch  # noqa: E402

os.environ.setdefault("SP_RUN_DIR", tempfile.mkdtemp())
import importlib.util  # noqa: E402
_spec = importlib.util.spec_from_file_location("hostsbom", os.path.join(ROOT, "collectors", "host-sbom", "collector.py"))
hostsbom = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(hostsbom)


class Profiles(unittest.TestCase):
    def test_parse(self):
        out = "os.family=ubuntu\nos.version=24.04\nkernel.running=6.8.0-40-generic\n" \
              "pkg\tdeb\topenssl\t3.0.13-0ubuntu3.4\topenssl\t3.0.13-0ubuntu3.4\tamd64\n" \
              "pkg\tdeb\tlibssl3t64\t3.0.13-0ubuntu3.4\topenssl\t3.0.13-0ubuntu3.4\tamd64\r\n" \
              "pkg\twindows-program\tApp\t\t\t\t\n# comment=x\n"
        kv, pk = hostsbom.parse(out)
        self.assertEqual(kv["os.family"], "ubuntu")
        self.assertEqual([p["name"] for p in pk], ["openssl", "libssl3t64"])     # a package without version is dropped
        self.assertEqual(pk[1]["source_name"], "openssl")
        plat = hostsbom.platform({"name": "h", "profile": "linux", "exposed": True}, dict(kv, **{"firmware.build_ts": "86400"}), pk)
        self.assertTrue(plat["exposed"])
        self.assertEqual(plat["firmware"]["build_date"], "1970-01-02")

    def test_profiles_exist_and_ascii(self):
        for prof in ("linux.sh", "macos.sh", "termux.sh", "busybox.sh", "windows.ps1"):
            src = open(os.path.join(ROOT, "collectors", "host-sbom", "profiles", prof), "rb").read()
            src.decode("ascii")   # Windows decodes scripts with a legacy code page: ASCII only


class Matching(unittest.TestCase):
    def test_os_sbom(self):
        plat = {"os_family": "ubuntu", "os_version": "24.04"}
        pk = [{"ecosystem": "deb", "name": "libssl3t64", "version": "3.0.13-0ubuntu3.4", "source_name": "openssl",
               "source_version": "3.0.13-0ubuntu3.4", "arch": "amd64"}, {"ecosystem": "brew", "name": "x", "version": "1"}]
        cdx = hostmatch.os_sbom(plat, pk)
        self.assertEqual(cdx["components"][0], {"bom-ref": "os", "type": "operating-system", "name": "ubuntu", "version": "24.04"})
        self.assertEqual(len(cdx["components"]), 2)
        props = {p["name"]: p["value"] for p in cdx["components"][1]["properties"]}
        self.assertEqual(props["aquasecurity:trivy:SrcName"], "openssl")
        self.assertIsNone(hostmatch.os_sbom({"os_family": "macos"}, pk))

    def test_kernel_bucket(self):
        self.assertTrue(hostmatch.is_kernel_pkg("linux-image-6.8.0-40-generic"))
        self.assertTrue(hostmatch.is_kernel_pkg("bpftool", "linux"))
        self.assertTrue(hostmatch.is_kernel_pkg("linux-libc-dev", "linux"))
        self.assertFalse(hostmatch.is_kernel_pkg("linux-firmware", "linux-firmware"))
        self.assertFalse(hostmatch.is_kernel_pkg("openssl", "openssl"))
        run = "6.8.0-40-generic"
        self.assertTrue(hostmatch.kernel_running_pkg("linux-image-6.8.0-40-generic", run))
        self.assertTrue(hostmatch.kernel_running_pkg("linux-headers-6.8.0-40", run))
        self.assertFalse(hostmatch.kernel_running_pkg("linux-headers-6.8.0-45", run))
        self.assertFalse(hostmatch.kernel_running_pkg("linux-image-6.8.0-400-generic", run))

    def test_android(self):
        es = [{"spl": "2099-01-01", "versions": ["15"], "severity": "high", "aliases": []},
              {"spl": "2099-02-01", "versions": ["16", "16-qpr2"], "severity": "critical", "aliases": ["CVE-1"]},
              {"spl": "2099-02-05", "versions": ["SoCVersion"], "severity": "high", "aliases": []},
              {"spl": "2099-02-01", "versions": ["14"], "severity": "high", "aliases": []}]
        m = hostmatch.android_missed({"patch_level": "2099-01-01", "os_version": "16"}, es)
        self.assertEqual([(b["spl"], len(b["entries"])) for b in m], [("2099-02-01", 1), ("2099-02-05", 1)])
        self.assertIsNone(hostmatch.android_missed({"patch_level": ""}, es))

    def test_apple(self):
        rel = [{"product": "macOS", "version": v, "name": f"macOS X {v}", "date": "2099-01-01"} for v in ("26.7", "26.6.2", "27.1", "26.6.10")] \
            + [{"product": "iOS", "version": "26.9"}]
        self.assertEqual([r["version"] for r in hostmatch.apple_missed({"os_version": "26.6.2"}, rel)], ["26.6.10", "26.7"])

    def test_windows(self):
        msrc = {"products": {"Windows 11 Version 25H2 for x64-based Systems": [
            {"release": "2099-Jan", "date": "2099-01-10", "cve": "CVE-1", "fixed_build": "10.0.26200.100", "kb": "1", "exploited": False},
            {"release": "2099-Feb", "date": "2099-02-10", "cve": "CVE-2", "fixed_build": "10.0.26200.300", "kb": "2", "exploited": True},
            {"release": "2099-Feb", "date": "2099-02-10", "cve": "CVE-3", "fixed_build": "10.0.26100.900", "kb": "3", "exploited": False}]}}
        m, prod = hostmatch.windows_missed({"os_build": "10.0.26200.200", "os_version": "25H2", "arch": "AMD64"}, msrc)
        self.assertEqual(prod, "Windows 11 Version 25H2 for x64-based Systems")
        self.assertEqual([(x["release"], [i["cve"] for i in x["items"]]) for x in m], [("2099-Feb", ["CVE-2"])])
        self.assertIsNone(hostmatch.windows_missed({"os_build": "10.0.26200.1", "os_version": "99H9"}, msrc)[0])

    def test_vendor_kev(self):
        kev = {"CVE-1": {"vendor": "ExampleVendor", "date_added": "2099-03-01"},
               "CVE-2": {"vendor": "ExampleVendor", "date_added": "2098-01-01"}, "CVE-3": {"vendor": "Other", "date_added": "2099-03-01"}}
        got = hostmatch.vendor_kev({"firmware": {"build_date": "2099-01-01"}}, kev, ["examplevendor"])
        self.assertEqual([k["cve"] for k in got], ["CVE-1"])


class Feeds(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.d)

    def _cached(self, rel, body):
        p = os.path.join(self.d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "w").write(body)
        json.dump({"checked_at": time.time()}, open(p + ".meta.json", "w"))

    def test_apple_index_parse(self):
        self._cached("apple/index.html", "<table><tr><th>Name</th></tr>"
                     "<tr><td><a href=\"https://example.invalid/1\">macOS Example 26.7.1</a></td><td>macOS Example</td><td>28 Sep 2099</td></tr>"
                     "<tr><td>Safari 26.1This update has no published CVE entries.</td><td>x</td><td>01 Oct 2099</td></tr></table>")
        idx = feeds.load({"type": "apple-security-releases"}, self.d)["index"]
        self.assertEqual(idx[0], {"name": "macOS Example 26.7.1", "product": "macOS", "version": "26.7.1", "date": "2099-09-28",
                                  "url": "https://example.invalid/1"})
        self.assertEqual(idx[1]["name"], "Safari 26.1")

    def test_vendor_headlines_and_unreadable(self):
        import hashlib
        u1, u2 = "https://vendor-a.invalid/sec", "https://vendor-b.invalid/sec"
        self._cached(f"vendor/{hashlib.sha1(u1.encode()).hexdigest()[:12]}.html",
                     "<p>Security Advisories (Vulnerabilities and CVEs) April 15, 2099</p><p>Products</p><script>CVE-0</script>")
        self._cached(f"vendor/{hashlib.sha1(u2.encode()).hexdigest()[:12]}.html", "<p>Making sure you're not a bot!</p>")
        r = feeds.load({"type": "vendor-advisories", "sources": [{"name": "a", "url": u1}, {"name": "b", "url": u2}]}, self.d)
        self.assertEqual([i["date"] for i in r["index"]["a"]], ["April 15, 2099"])
        self.assertIn("bot challenge", r["errors"]["b"])


class WindowsExec(unittest.TestCase):
    def test_windows_quoting(self):
        calls = []
        e = ex.executor({"type": "ssh", "host": "h", "shell": "windows"})
        orig = ex._run
        ex._run = lambda cmd, stdin=None, timeout=120: calls.append(cmd) or (0, "", "")
        try:
            e.run(["python", "-c", "import sys;exec(sys.stdin.read())", '{"roots": ["C:\\\\Users\\\\x"]}'])
            ex.powershell(e, "x" * 20000)
        finally:
            ex._run = orig
        self.assertEqual(calls[0][-1], 'python -c "import sys;exec(sys.stdin.read())" "{\\"roots\\": [\\"C:\\\\Users\\\\x\\"]}"')
        self.assertLess(len(calls[1][-1]), 8191)       # the script goes through stdin, not the command line


class TimeToKnow(unittest.TestCase):
    def test_baseline_then_counted(self):
        d = tempfile.mkdtemp()
        try:
            def doc(findings):
                return {"schema_version": "1.0", "collector": {"name": "vuln-intel", "version": "0.3.0"},
                        "run": {"started_at": "2099-01-01T00:00:00Z", "finished_at": "2099-01-01T00:00:00Z"},
                        "coverage": [{"asset": "host:h", "status": "ok"}], "findings": findings}

            def f(check, adv):
                return {"id": f"{abs(hash(check)) % 16**12:012x}", "check": check, "layer": "host", "asset": "host:h",
                        "title": "t", "severity": "high", "evidence": "e", "remediation": "r", "needs_human": True,
                        "owner": "human", "observed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "kind": "vulnerability", "attributes": {"advisory": adv, "published_at": time.strftime("%Y-%m-%d", time.gmtime(time.time() - 86400))}}
            for i, fs in enumerate([[f("platform.a", "A")], [f("platform.a", "A"), f("platform.b", "B")]]):
                r = os.path.join(d, "runs", str(i))
                os.makedirs(r)
                json.dump(doc(fs), open(os.path.join(r, "vuln-intel.findings.json"), "w"))
                subprocess.run([sys.executable, os.path.join(ROOT, "core", "ledger.py"), "--run", r, "--data", d], check=True,
                               capture_output=True)
            L = json.load(open(os.path.join(d, "ledger.json")))
            byc = {e["check"]: e for e in L["entries"].values()}
            self.assertFalse(byc["platform.a"]["ttk_counted"])          # first inventory of the asset: baseline
            self.assertTrue(byc["platform.b"]["ttk_counted"])           # appeared later on a covered asset: counted
            self.assertGreater(byc["platform.b"]["time_to_know_hours"], 0)
            self.assertIn("security_time_to_know_hours", open(os.path.join(d, "metrics", "ledger.prom")).read())
        finally:
            shutil.rmtree(d)


if __name__ == "__main__":
    unittest.main()
