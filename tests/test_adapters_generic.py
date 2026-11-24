"""Adapters and collectors used by environments other than the first instance: static CIDR discovery, Gitea/Forgejo
code host (against an in-process fake API; no network)."""
import http.server
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path[:0] = [ROOT]
from adapters import discovery  # noqa: E402


class StaticDiscovery(unittest.TestCase):
    def test_targets_and_cidrs(self):
        r = discovery.discover({"type": "static", "targets": [{"name": "web", "address": "192.0.2.1"}],
                                "cidrs": ["192.0.2.0/29"], "exclude": ["192.0.2.6"]})
        self.assertEqual([d["address"] for d in r], ["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5"])
        self.assertEqual(r[0]["name"], "web")
        self.assertEqual(r[0]["attrs"], {})
        self.assertEqual(r[1]["attrs"], {"cidr": "192.0.2.0/29"})

    def test_single_address_cidr(self):
        self.assertEqual([d["address"] for d in discovery.discover({"type": "static", "cidrs": ["198.51.100.7/32"]})],
                         ["198.51.100.7"])

    def test_large_range_refused(self):
        with self.assertRaises(ValueError):
            discovery.discover({"type": "static", "cidrs": ["10.0.0.0/8"]})
        self.assertEqual(len(discovery.discover({"type": "static", "cidrs": ["10.0.0.0/22"], "max_hosts": 2000})), 1022)


REPOS = [
    {"full_name": "acme/app", "default_branch": "main", "private": False, "archived": False},
    {"full_name": "acme/lib", "default_branch": "main", "private": True, "archived": False},
    {"full_name": "acme/old", "default_branch": "main", "private": False, "archived": True},
]
ROUTES = {
    "/api/v1/orgs/acme/repos": REPOS,
    "/api/v1/repos/acme/app/branch_protections": [],
    "/api/v1/repos/acme/app/keys": [{"title": "ci", "read_only": False, "created_at": "2026-01-01T00:00:00Z"}],
    "/api/v1/repos/acme/lib/branch_protections": [{"rule_name": "main", "enable_push": False,
                                                   "required_approvals": 0}],
    "/api/v1/repos/acme/lib/keys": [],
}


class Fake(http.server.BaseHTTPRequestHandler):
    seen_auth = []

    def do_GET(self):  # noqa: N802
        Fake.seen_auth.append(self.headers.get("Authorization"))
        body = ROUTES.get(self.path.split("?")[0])
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        if "page=" in self.path and "page=1" not in self.path:
            body = []
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())

    def log_message(self, *a):
        pass


class Gitea(unittest.TestCase):
    def run_collector(self, token_mode=0o600):
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fake)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        d = tempfile.mkdtemp()
        tok = os.path.join(d, "token")
        open(tok, "w").write("t0ken\n")
        os.chmod(tok, token_mode)
        inst = os.path.join(d, "instance.json")
        json.dump({"name": "t", "codehost": [
            {"type": "github", "owner": "someone-else", "gh_user": "x"},
            {"type": "gitea", "url": f"http://127.0.0.1:{srv.server_port}", "owner": "acme", "token_file": tok}]},
            open(inst, "w"))
        env = dict(os.environ, SP_INSTANCE=inst, SP_RUN_DIR=d)
        subprocess.run([sys.executable, os.path.join(ROOT, "collectors", "codehost-gitea", "collector.py")], env=env,
                       check=True, capture_output=True)
        return json.load(open(os.path.join(d, "codehost-gitea.findings.json")))

    def test_findings(self):
        doc = self.run_collector()
        got = sorted((f["check"], f["asset"].split("/", 2)[-1], f["severity"]) for f in doc["findings"])
        self.assertEqual(got, [("repo.default_branch_unprotected", "acme/app", "high"),
                               ("repo.deploy_key_write", "acme/app/deploy-key/ci", "low"),
                               ("repo.protection_no_approvals", "acme/lib", "low")])
        self.assertEqual(sorted(x["status"] for x in doc["coverage"]), ["ok", "ok"])
        self.assertIn("token t0ken", Fake.seen_auth)
        self.assertNotIn("t0ken", json.dumps(doc))

    def test_loose_token_file_is_a_gap(self):
        doc = self.run_collector(0o644)
        self.assertEqual(doc["findings"], [])
        self.assertEqual([x["status"] for x in doc["coverage"]], ["gap"])


if __name__ == "__main__":
    unittest.main()
