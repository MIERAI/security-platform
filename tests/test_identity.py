"""People pillar: the identity adapter (GitHub with ETag cache through a fake gh, Tailscale ACL logic, local
credential metadata) and the provider-independent checks; the AI-agent collector's memory / audit / guard checks.
No test touches a real account; nothing here ever handles a real secret."""
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path[:0] = [ROOT, os.path.join(ROOT, "sdk"), os.path.join(ROOT, "collectors", "identity")]
from adapters import identity as idp  # noqa: E402

NOW = time.time()


def iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


FAKE_GH = r'''#!/usr/bin/env python3
import json, os, sys
a = sys.argv[1:]
log = os.environ["FAKE_GH_LOG"]
if a[:2] == ["auth", "token"]:
    print("gho_" + "x" * 36); sys.exit(0)
path = a[-1]
inm = next((a[i + 1] for i, x in enumerate(a) if x == "-H" and a[i + 1].startswith("If-None-Match")), None)
open(log, "a").write(json.dumps([path, bool(inm)]) + "\n")
R = json.load(open(os.environ["FAKE_GH_DATA"]))
if path not in R:
    print("HTTP/2.0 404 Not Found\r\n\r\n" + json.dumps({"message": "Not Found"})); sys.exit(1)
if inm:
    print("HTTP/2.0 304 Not Modified\r\nEtag: W/\"1\"\r\n\r\n"); sys.exit(1)
print("HTTP/2.0 200 OK\r\nEtag: W/\"1\"\r\nX-Oauth-Scopes: repo, read:org\r\n\r\n" + json.dumps(R[path]))
'''


class GitHubAdapter(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        bin_ = os.path.join(self.d, "bin")
        os.makedirs(bin_)
        with open(os.path.join(bin_, "gh"), "w") as f:
            f.write(FAKE_GH)
        os.chmod(os.path.join(bin_, "gh"), 0o755)
        data = {
            "/user": {"login": "alice", "type": "User", "two_factor_authentication": None, "created_at": "2020-01-01T00:00:00Z"},
            "/user/orgs": [{"login": "acme"}, {"login": "elsewhere"}],
            "/orgs/acme": {"two_factor_requirement_enabled": False},
            "/orgs/acme/outside_collaborators?per_page=100": [],
            "/orgs/acme/members?per_page=100": [{"login": "alice"}],
            "/user/repos?per_page=100&affiliation=owner": [
                {"full_name": "alice/app", "owner": {"login": "alice"}, "visibility": "public"},
                {"full_name": "alice/old", "owner": {"login": "alice"}, "visibility": "private", "archived": True}],
            "/repos/alice/app/collaborators?affiliation=direct&per_page=100": [
                {"login": "alice", "permissions": {"admin": True, "push": True, "pull": True}},
                {"login": "mallory", "permissions": {"push": True, "pull": True}}],
            "/repos/alice/app/keys": [{"title": "ci", "read_only": False, "created_at": "2020-01-01T00:00:00Z", "last_used": None}],
            "/repos/alice/app/actions/permissions/fork-pr-contributor-approval": {"approval_policy": "first_time_contributors"},
        }
        json.dump(data, open(os.path.join(self.d, "data.json"), "w"))
        self.env = {"PATH": bin_ + os.pathsep + os.environ["PATH"], "FAKE_GH_LOG": os.path.join(self.d, "log"),
                    "FAKE_GH_DATA": os.path.join(self.d, "data.json")}
        self.old = {k: os.environ.get(k) for k in self.env}
        os.environ.update(self.env)

    def tearDown(self):
        for k, v in self.old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(self.d)

    def collect(self):
        cfg = {"type": "github", "accounts": [{"gh_user": "alice"}], "repos_owner": "alice", "orgs": ["acme"],
               "expected_collaborators": ["alice"]}
        return idp.GitHub(cfg, cache_dir=os.path.join(self.d, "cache"), keyring=lambda s, a: {"created_at": iso(NOW - 200 * 86400)}).collect()

    def test_normalised_snapshot_and_scope(self):
        s = self.collect()
        self.assertEqual(s["accounts"][0]["mfa"], None)
        self.assertIn(("identity-mfa:github/alice", s["gaps"][0][1]), s["gaps"])
        self.assertEqual([o["id"] for o in s["orgs"]], ["acme"], "orgs outside `orgs:` are never read")
        cr = s["credentials"][0]
        self.assertEqual((cr["kind"], cr["scopes"]), ("oauth_token", ["repo", "read:org"]))
        self.assertNotIn("xxxx", json.dumps(s), "no token value in the snapshot")
        kinds = sorted(g["kind"] for g in s["grants"])
        self.assertEqual(kinds, ["collaborator", "collaborator", "deploy_key", "member"])
        self.assertEqual(s["policies"][0]["value"], "first_time_contributors")
        logged = [json.loads(l)[0] for l in open(self.env["FAKE_GH_LOG"])]
        self.assertFalse(any("elsewhere" in p for p in logged))

    def test_etag_cache_reuses_bodies(self):
        self.collect()
        open(self.env["FAKE_GH_LOG"], "w").close()
        s = self.collect()
        calls = [json.loads(l) for l in open(self.env["FAKE_GH_LOG"])]
        self.assertTrue(calls and all(conditional for _, conditional in calls), "second run sends If-None-Match everywhere")
        self.assertEqual(s["orgs"][0]["mfa_required"], False, "304 answers come from the cache")
        for p in os.listdir(os.path.join(self.d, "cache", "alice")):
            self.assertNotIn("gho_", open(os.path.join(self.d, "cache", "alice", p)).read())

    def test_checks(self):
        import collector
        s = self.collect()
        out = tempfile.mkdtemp()
        try:
            os.environ["SP_RUN_DIR"] = out
            import spsdk
            c = spsdk.Collector("identity", "test")
            collector.checks(c, s, {"providers": [{"type": "github", "expected_collaborators": ["alice"]}]}, NOW, "raw/x")
            got = sorted((f["check"], f["severity"]) for f in c.findings)
            self.assertEqual(got, [("identity.collaborator_unexpected", "high"), ("identity.deploy_key_unused", "low"),
                                   ("identity.fork_pr_approval_weak", "low"), ("identity.org_mfa_not_required", "medium"),
                                   ("identity.token_age_over_90d", "medium"), ("identity.token_classic_full_repo", "medium")])
        finally:
            shutil.rmtree(out)


class Checks(unittest.TestCase):
    def run_checks(self, snap, cfg=None):
        import collector
        import spsdk
        out = tempfile.mkdtemp()
        os.environ["SP_RUN_DIR"] = out
        try:
            c = spsdk.Collector("identity", "test")
            collector.checks(c, dict(idp.snapshot(), **snap), cfg or {}, NOW, "raw/x")
            return sorted(f["check"] for f in c.findings)
        finally:
            shutil.rmtree(out)

    def test_mfa_expiry_dormant_and_modes(self):
        got = self.run_checks({
            "accounts": [{"provider": "okta", "id": "bob", "mfa": False, "admin": True}, {"provider": "okta", "id": "eve", "mfa": True}],
            "credentials": [
                {"store": "s", "id": "soon", "kind": "pat_fine_grained", "created_at": iso(NOW - 86400), "expires_at": iso(NOW + 3 * 86400)},
                {"store": "s", "id": "gone", "kind": "api_key", "created_at": iso(NOW - 86400), "expires_at": iso(NOW - 86400)},
                {"store": "s", "id": "old-ssh", "kind": "ssh_key", "created_at": iso(NOW - 400 * 86400)},
                {"store": "s", "id": "young-ssh", "kind": "ssh_key", "created_at": iso(NOW - 100 * 86400)},
                {"store": "s", "id": "dev", "kind": "device_key", "last_used": iso(NOW - 90 * 86400)},
                {"store": "s", "id": "f", "kind": "token_file", "created_at": iso(NOW), "mode": "0o644"}],
            "policies": [{"provider": "tailscale", "resource": "identity-provider:tailscale", "name": "acl_allow_all", "value": True}]})
        self.assertEqual(got, ["identity.credential_expired", "identity.credential_file_readable", "identity.mfa_disabled",
                               "identity.overlay_acl_allow_all", "identity.overlay_device_dormant",
                               "identity.ssh_key_age_over_365d", "identity.token_expiring_soon"])

    def test_acl_allow_all(self):
        self.assertTrue(idp.acl_allows_all({"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}))
        self.assertTrue(idp.acl_allows_all({"grants": [{"src": ["*"], "dst": ["*"], "ip": ["*"]}]}))
        self.assertFalse(idp.acl_allows_all({"acls": [{"action": "accept", "src": ["group:admins"], "dst": ["*:*"]},
                                                      {"action": "accept", "src": ["*"], "dst": ["tag:web:443"]}]}))

    def test_future_providers_are_gaps(self):
        for t in ("google-workspace", "okta", "entra", "gitlab"):
            with self.assertRaises(NotImplementedError):
                idp.provider({"type": t}).collect()


class LocalCredentials(unittest.TestCase):
    def test_metadata_only(self):
        d = tempfile.mkdtemp()
        try:
            ssh = os.path.join(d, "ssh")
            os.makedirs(ssh)
            for n in ("id_a", "id_skip"):
                open(os.path.join(ssh, n), "w").write("PRIVATE-KEY-MATERIAL-NEVER-READ\n")
                open(os.path.join(ssh, n + ".pub"), "w").write("ssh-ed25519 AAAAexample comment\n")
            kc = os.path.join(d, "kc.yaml")
            open(kc, "w").write("users:\n- name: u1\n  user: {token: SECRET-TOKEN-VALUE}\n- name: u2\n  user: {exec: {command: /usr/bin/plugin}}\n")
            dc = os.path.join(d, "docker.json")
            json.dump({"auths": {"reg.example": {"auth": "SECRET-AUTH"}, "skip.example": {}}, "credsStore": "osxkeychain"}, open(dc, "w"))
            s = idp.local_credentials({"kubeconfigs": [kc], "ssh_dirs": [ssh], "docker_configs": [dc],
                                       "exclude": [os.path.join(ssh, "id_skip")], "exclude_registries": ["skip.example"]})
            text = json.dumps(s)
            for secret in ("PRIVATE-KEY-MATERIAL", "SECRET-TOKEN-VALUE", "SECRET-AUTH"):
                self.assertNotIn(secret, text)
            ids = sorted(c["id"] for c in s["credentials"])
            self.assertEqual(ids, ["kube:kc.yaml/u1", "kube:kc.yaml/u2", "registry:reg.example", "ssh:id_a"])
            kinds = {c["id"]: c["kind"] for c in s["credentials"]}
            self.assertEqual((kinds["kube:kc.yaml/u1"], kinds["kube:kc.yaml/u2"]), ("kube_token", "kube_exec"))
        finally:
            shutil.rmtree(d)


class AgentCollector(unittest.TestCase):
    def test_memory_audit_guard(self):
        d = tempfile.mkdtemp()
        try:
            home = os.path.join(d, "home")
            mem = os.path.join(home, "projects", "p", "memory")
            os.makedirs(mem)
            open(os.path.join(mem, "a.md"), "w").write("deploy token: ghp_" + "A" * 36 + "\n")
            open(os.path.join(mem, "b.md"), "w").write("密码=与管理界面相同\npassword: see the vault\n")
            tr = os.path.join(home, "projects", "p", "s1.jsonl")
            open(tr, "w").write("{}\n")
            settings = os.path.join(home, "settings.json")
            json.dump({"permissions": {"defaultMode": "default", "deny": ["Bash(rm:*)"], "allow": []}, "cleanupPeriodDays": 7},
                      open(settings, "w"))
            os.chmod(settings, 0o600)
            inst = os.path.join(d, "instance.json")
            json.dump({"agents": [{"type": "claude-code", "settings": [settings], "memory_dirs": [os.path.join(home, "projects")],
                                   "transcripts_dirs": [os.path.join(home, "projects")]}]}, open(inst, "w"))
            run = os.path.join(d, "run")
            subprocess.run([sys.executable, os.path.join(ROOT, "collectors", "agent-claude-code", "collector.py")],
                           env=dict(os.environ, SP_INSTANCE=inst, SP_RUN_DIR=run), check=True, capture_output=True)
            doc = json.load(open(os.path.join(run, "agent-claude-code.findings.json")))
            checks = sorted(f["check"] for f in doc["findings"])
            self.assertEqual(checks, ["agent.audit_trail_missing", "agent.memory_secret_suspect", "agent.no_credential_deny_rules"])
            self.assertIn("a.md", [f["asset"].rsplit("/", 1)[1] for f in doc["findings"] if f["check"] == "agent.memory_secret_suspect"])
            self.assertNotIn("AAAAAAAA", json.dumps(doc) + open(os.path.join(run, "raw", "agent-claude-code", "memory-scan.json")).read())
            cov = {g["asset"] for g in doc["coverage"] if g["status"] == "ok"}
            self.assertTrue({"agent-guard:claude-code", "agent-memory:claude-code", "agent-audit:claude-code"} <= cov)
            self.assertEqual(stat.S_IMODE(os.stat(settings).st_mode), 0o600)
        finally:
            shutil.rmtree(d)


if __name__ == "__main__":
    unittest.main()
