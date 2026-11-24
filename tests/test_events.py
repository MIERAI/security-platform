"""events: parsers (openssh / dropbear / sudo / macOS unified log), cursors and dedup, novel sources, file integrity,
code host snapshot diff, overlay audit mapping, the Loki push contract, at-least-once on push failure, token files,
and the runner's `events` job. No network: a local fake HTTP server plays Loki and the APIs."""
import http.server
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path[:0] = [os.path.join(ROOT, "events"), os.path.join(ROOT, "runner"), ROOT, os.path.join(ROOT, "sdk"), os.path.join(ROOT, "core")]
import ship  # noqa: E402

NOW = 1795600000.0   # 2026-11-25 UTC

LOGCAT = [
    "1795599000.100  10911 10911 W sshd    : type=1400 audit(0.0:1687915): avc:  granted  { execute } for name=\"sshd-session\"",
    "1795599000.200  10911 10911 I sshd-session: Accepted publickey for alice from 100.64.1.2 port 57121 ssh2: ED25519 SHA256:abc",
    "1795599001.000  10912 10912 I sshd-session: Failed password for invalid user admin from 203.0.113.9 port 4242 ssh2",
    "1795599002.000  10913 10913 I sshd-session: Invalid user test from 203.0.113.9 port 4243",
    "1795599003.000  10913 10913 I sshd-session: Connection closed by 203.0.113.9 port 4243",
]
JOURNAL = [
    "2026-11-24T20:20:03+09:00 node1 sshd-session[3353503]: Accepted publickey for bob from 192.0.2.7 port 57454 ssh2: ED25519 SHA256:x",
    "2026-11-24T20:20:04+09:00 node1 sudo[3353688]: bob :  PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/ls",
    "2026-11-24T20:20:05+09:00 node1 sudo[3353689]: eve : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/bin/sh",
    "2026-11-24T20:20:06+09:00 node1 sudo[3353690]: mallory : user NOT in sudoers ; TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/bin/sh",
]
DROPBEAR = [
    "Nov 24 19:17:01 router dropbear[8675]: Child connection from 198.51.100.4:51000",
    "Nov 24 19:17:02 router dropbear[8675]: Bad password attempt for 'root' from 198.51.100.4:51000",
    "Nov 24 19:17:03 router dropbear[8676]: Login attempt for nonexistent user from 198.51.100.4:51001",
    "Nov 24 19:17:04 router dropbear[8677]: Pubkey auth succeeded for 'root' with key md5 aa:bb from 192.168.1.5:40000",
    "Nov 24 19:17:05 router dropbear[8678]: Password auth succeeded for 'root' from [2001:db8::1]:40001",
    "Nov 24 19:17:06 router dropbear[8678]: Exit before auth (user 'root', 0 fails): Exited normally",
]
MACOS = [
    json.dumps({"timestamp": "2026-11-24 20:15:35.123456+0900", "processImagePath": "/usr/bin/sudo", "processID": 1,
                "eventMessage": "  carol : TTY=ttys001 ; PWD=/Users/carol ; USER=root ; COMMAND=/bin/ls"}),
    "Filtering the log data using \"process == sudo\"",
    json.dumps({"timestamp": "2026-11-24 20:15:35.200000+0900", "processImagePath": "/usr/bin/sudo", "eventMessage": "Retrieve Group by ID"}),
]


def events(parser, lines, opts=None):
    return [e for e in (ship.PARSERS[parser](ln, NOW, opts or {}) for ln in lines) if e]


class Parsers(unittest.TestCase):
    def test_logcat_openssh(self):
        evs = events("openssh", LOGCAT)
        self.assertEqual(len(evs), 4)                         # avc line dropped; "Connection closed" kept, no event
        self.assertEqual([e.get("event") for e in evs], ["ssh_login_success", "ssh_login_failure", "ssh_login_failure", None])
        self.assertEqual((evs[0]["user"], evs[0]["src_ip"], evs[0]["ts"]), ("alice", "100.64.1.2", 1795599000.2))
        self.assertEqual((evs[1]["user"], evs[1]["src_ip"]), ("admin", "203.0.113.9"))
        self.assertEqual(evs[2]["user"], "test")
        self.assertEqual(evs[0]["line"], LOGCAT[1])

    def test_journal_iso_and_sudo(self):
        evs = events("openssh", JOURNAL)
        self.assertEqual([e["event"] for e in evs], ["ssh_login_success", "sudo", "sudo_failure", "sudo_failure"])
        self.assertEqual([e["user"] for e in evs], ["bob", "bob", "eve", "mallory"])
        self.assertNotIn("src_ip", evs[1])
        self.assertEqual(evs[0]["ts"], 1795519203.0)

    def test_dropbear(self):
        evs = events("dropbear", DROPBEAR, {"utc_offset": "+08:00"})
        self.assertEqual(len(evs), 5)                         # "Exit before auth" dropped
        self.assertEqual([e.get("event") for e in evs],
                         [None, "ssh_login_failure", "ssh_login_failure", "ssh_login_success", "ssh_login_success"])
        self.assertEqual((evs[1]["user"], evs[1]["src_ip"]), ("root", "198.51.100.4"))
        self.assertEqual((evs[2]["user"], evs[2]["src_ip"]), ("", "198.51.100.4"))
        self.assertEqual(evs[3]["src_ip"], "192.168.1.5")
        self.assertEqual(evs[4]["src_ip"], "2001:db8::1")
        self.assertEqual(evs[1]["ts"], 1795519022.0)          # 2026-11-24 19:17:02 +08:00
        self.assertEqual(ship.split_addr("2001:db8::2:22"), "2001:db8::2")

    def test_bsd_year_rollover(self):
        jan = time.mktime(time.strptime("2026-01-01 00:00:05", "%Y-%m-%d %H:%M:%S"))
        e = ship.parse_syslog("Dec 31 23:59:59 h sshd[1]: Accepted publickey for a from 10.0.0.1 port 1 ssh2", jan, {})
        self.assertEqual(time.localtime(e["ts"]).tm_year, 2025)

    def test_macos(self):
        evs = events("macos-unified", MACOS)
        self.assertEqual(len(evs), 1)
        self.assertEqual((evs[0]["event"], evs[0]["user"]), ("sudo", "carol"))
        self.assertEqual(json.loads(evs[0]["line"])["process"], "sudo")


class FakeExec:
    def __init__(self, out, rc=0):
        self.out, self.rc, self.calls = out, rc, []

    def run(self, argv, stdin=None, timeout=120):
        self.calls.append(argv)
        out = self.out(argv) if callable(self.out) else self.out
        return self.rc, out, ""


class Command(unittest.TestCase):
    def collect(self, lines, state, now=NOW):
        fx = FakeExec("\n".join(lines) + "\n")
        cfg = {"name": "s", "host": "h1", "parser": "openssh", "argv": ["x", "--since", "{since_epoch}"]}
        with mock.patch.object(ship, "executor", return_value=fx):
            evs, new = ship.CommandSource(cfg, state, now).collect()
        return evs, new, fx

    def test_cursor_dedup_and_novel(self):
        evs, st, fx = self.collect(LOGCAT, {})
        self.assertEqual(fx.calls[0][2], f"{NOW - 3600:.3f}")         # first run: lookback 1h
        self.assertEqual(len(evs), 4)
        self.assertEqual(evs[0]["novel"], "false")                       # baseline run: never novel
        self.assertEqual(st["cursor"], 1795599003.0)
        evs2, st2, fx = self.collect(LOGCAT, st)
        self.assertEqual(evs2, [])                                       # nothing new
        self.assertEqual(fx.calls[0][2], "1795599003.000")
        more = LOGCAT + ["1795599010.000  1 1 I sshd-session: Accepted publickey for alice from 100.64.1.2 port 1 ssh2: k",
                         "1795599011.000  1 1 I sshd-session: Accepted publickey for alice from 100.64.9.9 port 2 ssh2: k"]
        evs3, st3, _ = self.collect(more, st2)
        self.assertEqual([e["novel"] for e in evs3], ["false", "true"])
        self.assertIn("100.64.9.9", st3["seen"]["h1|alice"])

    def test_same_second_lines(self):
        a = "Nov 24 10:00:00 h sshd[1]: Failed password for root from 10.0.0.1 port 1 ssh2"
        b = "Nov 24 10:00:00 h sshd[2]: Failed password for root from 10.0.0.2 port 1 ssh2"
        _, st, _ = self.collect([a], {"cursor": 0, "seen": {}})
        evs, _, _ = self.collect([a, b], st)
        self.assertEqual([e["src_ip"] for e in evs], ["10.0.0.2"])      # a already shipped, b same second: new

    def test_command_failure_raises(self):
        with mock.patch.object(ship, "executor", return_value=FakeExec("", rc=255)):
            with self.assertRaises(RuntimeError):
                ship.CommandSource({"name": "s", "argv": ["x"]}, {}, NOW).collect()


class FileIntegrity(unittest.TestCase):
    def test_baseline_then_change(self):
        content = {"v": "ssh-ed25519 AAAA one\n"}
        fx = FakeExec(lambda argv: content["v"])
        cfg = {"name": "k", "host": "h", "paths": [{"path": "~/.ssh/authorized_keys", "user": "u"}]}
        with mock.patch.object(ship, "executor", return_value=fx):
            evs, st = ship.FileIntegritySource(cfg, {}, NOW).collect()
            self.assertEqual(evs, [])
            evs, st = ship.FileIntegritySource(cfg, st, NOW).collect()
            self.assertEqual(evs, [])
            content["v"] = "ssh-ed25519 AAAA one\nssh-ed25519 BBBB two\n"
            evs, st = ship.FileIntegritySource(cfg, st, NOW).collect()
        self.assertEqual((evs[0]["event"], evs[0]["user"]), ("authorized_keys_changed", "u"))
        self.assertIn("(2 keys)", evs[0]["line"])
        self.assertNotIn("AAAA", evs[0]["line"])                         # no key material
        self.assertEqual(fx.calls[0][:2], ["sh", "-c"])


class Fake(http.server.BaseHTTPRequestHandler):
    routes, pushes, fail_push = {}, [], False

    def do_GET(self):
        r = self.routes.get(self.path.split("?")[0] if self.path.split("?")[0] in self.routes else self.path)
        if r is None:
            self.send_response(404); self.end_headers(); return  # noqa: E702
        code, body, headers = r
        if headers.get("ETag") and self.headers.get("If-None-Match") == headers["ETag"]:
            self.send_response(304); self.end_headers(); return  # noqa: E702
        self.send_response(code)
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())

    def do_POST(self):
        n = int(self.headers["Content-Length"])
        raw = self.rfile.read(n)
        if self.path == "/api/v2/oauth/token":
            ok = b"client_secret=sec" in raw
            self.send_response(200 if ok else 401)
            self.end_headers()
            self.wfile.write(json.dumps({"access_token": "short-lived"}).encode())
            return
        body = json.loads(raw)
        if Fake.fail_push:
            self.send_response(500); self.end_headers(); return  # noqa: E702
        Fake.pushes.append((self.headers.get("Authorization"), body))
        self.send_response(204)
        self.end_headers()

    def log_message(self, *a):
        pass


class Server(unittest.TestCase):
    def setUp(self):
        Fake.routes, Fake.pushes, Fake.fail_push = {}, [], False
        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fake)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.srv.server_port}"
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        self.srv.shutdown()
        shutil.rmtree(self.tmp)


class GitHub(Server):
    def snapshot_routes(self, keys, vis, hooks):
        Fake.routes.update({
            "/user": (200, {"login": "me"}, {}),
            "/user/keys": (200, keys, {"ETag": f'"k{len(keys)}"'}),
            "/user/gpg_keys": (404, None, {}),
            "/user/repos": (200, [{"full_name": "me/a", "visibility": vis, "owner": {"login": "me"}, "pushed_at": "2026"}], {}),
            "/repos/me/a/keys": (200, [], {}),
            "/repos/me/a/hooks": (200, hooks, {}),
            "/user/installations": (403, None, {}),
            "/users/me/events": (200, [{"id": "1", "type": "PushEvent"}], {}),
        })

    def run_src(self, state):
        cfg = {"name": "gh", "host": "me", "api": self.base, "token_env": "NOPE"}
        return ship.GitHubAccountSource(cfg, state, NOW).collect()

    def test_baseline_then_diff(self):
        self.snapshot_routes([{"id": 1, "title": "laptop", "key": "ssh-ed25519 AAAA"}], "private", [])
        evs, st = self.run_src({})
        self.assertEqual(evs, [])
        self.assertIn("/user/gpg_keys", st["unsupported"])                # 404: unsupported, not a failure
        self.assertIn("/user/installations", st["unsupported"])
        self.snapshot_routes([{"id": 1, "title": "laptop"}, {"id": 2, "title": "new", "key": "ssh-ed25519 BBBB"}], "public",
                             [{"id": 9, "events": ["push"], "active": True, "config": {"url": "https://hooks.example/x?secret=1", "secret": "****"}}])
        Fake.routes["/users/me/events"] = (200, [{"id": "7", "type": "PublicEvent", "repo": {"name": "me/a"}, "actor": {"login": "me"},
                                                  "created_at": "2026-11-24T10:00:00Z"}], {})
        evs, st = self.run_src(st)
        got = sorted(e["event"] for e in evs)
        self.assertEqual(got, ["hook_added", "repo_made_public", "repo_made_public", "ssh_key_added"])
        for e in evs:
            self.assertNotIn("BBBB", e["line"])
            self.assertNotIn("secret", e["line"])
        evs, st = self.run_src(st)                                        # same state: nothing new, PublicEvent remembered
        self.assertEqual(evs, [])

    def test_etag_cache(self):
        self.snapshot_routes([{"id": 1, "title": "a"}], "private", [])
        _, st = self.run_src({})
        cached = st["http_cache"]
        self.assertTrue(any(v.get("etag") for v in cached.values()))
        evs, _ = self.run_src(st)                                         # 304 answered from cache: same snapshot
        self.assertEqual(evs, [])


class Overlay(Server):
    def test_mapping_and_baseline(self):
        tok = os.path.join(self.tmp, "t")
        with open(tok, "w") as f:
            f.write("x")
        os.chmod(tok, 0o600)
        logs = {"logs": [
            {"eventGroupID": "g1", "type": "CREATE", "target": {"type": "NODE", "name": "n1"}, "actor": {"loginName": "a@x"}, "eventTime": "2026-11-24T10:00:00Z"},
            {"eventGroupID": "g2", "type": "UPDATE", "target": {"type": "NODE", "property": "KEY_EXPIRY_DISABLED"}, "new": True, "actor": {"loginName": "a@x"}},
            {"eventGroupID": "g3", "type": "UPDATE", "target": {"type": "TAILNET", "property": "ACL"}, "actor": {"loginName": "a@x"}},
            {"eventGroupID": "g4", "type": "CREATE", "target": {"type": "API_KEY"}, "actor": {"loginName": "a@x"}},
            {"eventGroupID": "g5", "type": "UPDATE", "target": {"type": "NODE", "property": "ENABLED_ROUTES"}, "new": ["0.0.0.0/0"]},
        ]}
        Fake.routes["/api/v2/tailnet/-/logging/configuration"] = (200, logs, {})
        cfg = {"name": "ts", "api": self.base, "token_file": tok}
        evs, st = ship.TailscaleAuditSource(cfg, {}, NOW).collect()
        self.assertEqual(evs, [])                                          # baseline
        evs, _ = ship.TailscaleAuditSource(cfg, {"cursor": NOW - 600}, NOW).collect()
        self.assertEqual([e["event"] for e in evs],
                         ["node_added", "node_key_expiry_disabled", "policy_changed", "auth_key_created", "exit_node_enabled"])
        evs, _ = ship.TailscaleAuditSource(cfg, st, NOW).collect()
        self.assertEqual(evs, [])                                          # dedup by id within the overlap
        with open(tok, "w") as f:
            f.write("sec")
        oc = {"name": "ts", "api": self.base, "oauth_client_id": "c", "oauth_client_secret_file": tok}
        self.assertEqual(ship.TailscaleAuditSource(oc, {}, NOW).token(), "short-lived")


class Push(Server):
    def write_cfg(self, token_mode=0o600):
        tok = os.path.join(self.tmp, "token")
        with open(tok, "w") as f:
            f.write("s3cr3t\n")
        os.chmod(tok, token_mode)
        logf = os.path.join(self.tmp, "auth.log")
        with open(logf, "w") as f:
            f.write("\n".join(JOURNAL) + "\n")
        cfg = {"loki": {"url": self.base + "/loki/api/v1/push", "token_file": tok},
               "sources": [{"name": "n1", "type": "command", "host": "node1", "parser": "openssh",
                            "lookback": "3650d", "argv": ["cat", logf]}]}
        p = os.path.join(self.tmp, "cfg.json")
        with open(p, "w") as f:
            json.dump(cfg, f)
        return p

    def test_contract(self):
        cfg = self.write_cfg()
        state = os.path.join(self.tmp, "state")
        self.assertEqual(ship.main(["--config", cfg, "--state", state, "--now", str(NOW), "--summary", os.path.join(self.tmp, "s.json")]), 0)
        auth, body = Fake.pushes[0]
        self.assertEqual(auth, "Bearer s3cr3t")
        s = body["streams"][0]
        self.assertEqual(s["stream"], {"source": "auth", "host": "node1"})
        ts, line, md = s["values"][0]
        self.assertTrue(ts.isdigit() and len(ts) == 19)
        self.assertEqual(md, {"event": "ssh_login_success", "user": "bob", "src_ip": "192.0.2.7", "novel": "false"})
        self.assertEqual(s["values"][1][2], {"event": "sudo", "user": "bob"})
        self.assertEqual(oct(os.stat(os.path.join(state, "n1.json")).st_mode & 0o777), "0o600")
        summ = json.load(open(os.path.join(self.tmp, "s.json")))
        self.assertEqual(summ["sources"]["n1"]["shipped"], 4)
        # a heartbeat per successful run: the source is alive even when nothing happened (separate push)
        hb = [v for _, b in Fake.pushes for st in b["streams"] for v in st["values"] if len(v) > 2 and v[2].get("event") == "heartbeat"]
        self.assertEqual(len(hb), 1)
        self.assertEqual(json.loads(hb[0][1]), {"heartbeat": "n1", "events": 4})

    def test_push_failure_keeps_cursor(self):
        cfg = self.write_cfg()
        state = os.path.join(self.tmp, "state")
        Fake.fail_push = True
        self.assertEqual(ship.main(["--config", cfg, "--state", state, "--now", str(NOW)]), 1)
        self.assertFalse(os.path.exists(os.path.join(state, "n1.json")))
        Fake.fail_push = False
        self.assertEqual(ship.main(["--config", cfg, "--state", state, "--now", str(NOW)]), 0)
        self.assertEqual(len(Fake.pushes[0][1]["streams"][0]["values"]), 4)    # resent in full

    def test_world_readable_token_refused(self):
        cfg = self.write_cfg(token_mode=0o644)
        self.assertEqual(ship.main(["--config", cfg, "--state", os.path.join(self.tmp, "st"), "--now", str(NOW)]), 1)
        self.assertEqual(Fake.pushes, [])

    def test_runner_job(self):
        import runner
        data = os.path.join(self.tmp, "data")
        logf = os.path.join(self.tmp, "auth.log")
        with open(logf, "w") as f:
            f.write("\n".join(JOURNAL) + "\n")
        inst = os.path.join(self.tmp, "instance.json")
        with open(inst, "w") as f:
            json.dump({"runner": {"site": "ws", "role": "site", "jobs": {"auth-events": {
                "type": "events", "schedule": "*/15 * * * *", "loki": {"url": self.base + "/loki/api/v1/push"},
                "sources": [{"name": "n1", "type": "command", "host": "node1", "parser": "openssh", "lookback": "3650d",
                             "argv": ["cat", logf]}]}}}}, f)
        r = runner.Runner(inst, data)
        self.assertEqual(r.execute("auth-events"), 0)
        st = r.load_state("auth-events")
        self.assertIn("n1: 4", st["last_note"])
        self.assertTrue(os.path.exists(os.path.join(data, "state", "events", "auth-events", "n1.json")))
        self.assertIsNone(Fake.pushes[0][0])                                  # no token configured: no header


if __name__ == "__main__":
    unittest.main()
