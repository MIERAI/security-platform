"""The `sp` command line and its plain-language texts: every check a collector can emit has an explanation, the
digest never carries asset details, and the commands work on a synthetic data directory."""
import contextlib
import glob
import io
import json
import os
import re
import sys
import tempfile
import time
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path[:0] = [os.path.join(ROOT, "cli"), ROOT]
import explanations  # noqa: E402
import sp  # noqa: E402


def emitted_checks():
    """Check names (or their static prefix for f-strings) passed to finding() by every collector."""
    out = set()
    for p in glob.glob(os.path.join(ROOT, "collectors", "*", "collector.py")):
        src = open(p).read()
        for m in re.finditer(r'(?:c\.finding|F)\(\s*"[a-z-]+",\s*[^,]+,\s*(f?)"([^"]+)"', src, re.S):
            name = m.group(2)
            out.add(name.split("{")[0] if m.group(1) else name)
    return out


class Explanations(unittest.TestCase):
    def test_every_emitted_check_is_explained(self):
        missing = [ch for ch in sorted(emitted_checks()) if not explanations.explain(ch).get("what")]
        self.assertEqual(missing, [], "add a plain-language entry to cli/explanations.py")

    def test_entries_are_complete_and_generic(self):
        for k, v in explanations.CHECKS.items():
            with self.subTest(check=k):
                self.assertTrue(all(v.get(f) for f in ("what", "why", "fix", "verify")))
                self.assertNotRegex(json.dumps(v), r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")


def data_dir():
    d = tempfile.mkdtemp()
    now = time.time()
    iso = lambda t: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))  # noqa: E731
    E = {
        "aaaaaaaaaaa1": dict(id="aaaaaaaaaaa1", check="ssh.password_auth_enabled", layer="identity",
                             asset="host:secret-db-7", title="sshd allows password login on 198.51.100.9", severity="high",
                             status="open", first_seen=iso(now - 3600), last_seen=iso(now), evidence="raw/host/x.json#a",
                             remediation="PasswordAuthentication no", needs_human=False, collector="host"),
        "bbbbbbbbbbb2": dict(id="bbbbbbbbbbb2", check="patch.pending", layer="host", asset="host:secret-db-7",
                             title="3 updates", severity="low", status="fixed", first_seen=iso(now - 9 * 86400),
                             last_seen=iso(now - 3600), fixed_at=iso(now - 3600), evidence="", remediation="",
                             needs_human=False, collector="host"),
        "ccccccccccc3": dict(id="ccccccccccc3", check="k8s.pod.privileged", layer="workload",
                             asset="k8s-workload:prod/payments/Deployment/api", title="privileged", severity="high",
                             status="open", first_seen=iso(now - 40 * 86400), last_seen=iso(now), evidence="",
                             remediation="", needs_human=False, collector="k8s"),
    }
    json.dump({"schema": "security-platform/ledger/v1", "entries": E, "sli": {"x": {"ok": True, "value": 0}},
               "collectors": {}}, open(os.path.join(d, "ledger.json"), "w"))
    os.makedirs(os.path.join(d, "tracker"))
    json.dump({"items": {"ccccccccccc3": {"id": "ccccccccccc3", "owner": "platform", "overdue": True,
                                          "due_at": iso(now - 86400), "status": "open"}}},
              open(os.path.join(d, "tracker", "items.json"), "w"))
    json.dump({"name": "acme", "runner": {"jobs": {"host": {"schedule": "0 1 * * *"}}},
               "notify": [{"type": "file", "path": os.path.join(d, "out.txt")}]},
              open(os.path.join(d, "instance.json"), "w"))
    return d


def run(*argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = sp.main(list(argv))
    return rc, buf.getvalue()


class Commands(unittest.TestCase):
    def setUp(self):
        self.d = data_dir()

    def test_findings_filters(self):
        rc, out = run("findings", "--data", self.d, "--open", "--severity", "high", "--ids")
        self.assertEqual(sorted(out.split()), ["aaaaaaaaaaa1", "ccccccccccc3"])
        rc, out = run("findings", "--data", self.d, "--overdue", "--ids")
        self.assertEqual(out.split(), ["ccccccccccc3"])
        rc, out = run("findings", "--data", self.d, "--check", "patch", "--json")
        self.assertEqual([e["status"] for e in json.loads(out)], ["fixed"])

    def test_explain_plain_language_and_exception_snippet(self):
        rc, out = run("explain", "--data", self.d, "aaaaaaa")   # a unique prefix is enough
        self.assertEqual(rc, 0)
        for s in ("What it means", "Why it matters", "How to fix", "How to verify", "approved_by", "aaaaaaaaaaa1:"):
            self.assertIn(s, out)

    def test_status(self):
        rc, out = run("status", "--data", self.d)
        self.assertIn("Overdue fixes: 1", out)
        self.assertIn("Fixed in the last 7 days: 1", out)

    def test_digest_has_no_asset_details(self):
        rc, out = run("digest", "--data", self.d, "--daily")
        self.assertIn("1 new, 1 fixed", out)
        self.assertIn("Overdue fixes: 1", out)
        for leak in ("secret-db-7", "198.51.100.9", "payments", "prod/"):
            self.assertNotIn(leak, out)

    def test_notify_file(self):
        rc, _ = run("notify", "--data", self.d)
        self.assertEqual(rc, 0)
        self.assertIn("Security", open(os.path.join(self.d, "out.txt")).read())

    def test_init_and_doctor(self):
        d = os.path.join(tempfile.mkdtemp(), "co")
        run("init", d, "--name", "co")
        self.assertEqual(os.stat(d).st_mode & 0o777, 0o700)
        self.assertEqual(os.stat(os.path.join(d, "instance.yaml")).st_mode & 0o777, 0o600)
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML")
        inst = yaml.safe_load(open(os.path.join(d, "instance.yaml")))
        self.assertEqual(inst["hosts"][0]["exec"], {"type": "local"})
        self.assertEqual(yaml.safe_load(open(os.path.join(d, "exceptions.yaml"))), {"exceptions": {}})
        rc, out = run("doctor", "--data", d)
        self.assertEqual(rc, 0, out)


if __name__ == "__main__":
    unittest.main()
