"""export: ticket sink (GitHub Issues against a fake API: idempotent, close / reopen / accepted risk, minimal body,
rate limits, dry run, public repository refused) and SIEM sinks (OCSF over HTTP with batching and retry, file,
stdout), driven by core/export.py, plus the runner job and metrics contract."""
import contextlib
import http.server
import io
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path[:0] = [os.path.join(ROOT, "core"), ROOT, os.path.join(ROOT, "sdk"), os.path.dirname(os.path.abspath(__file__))]
import export  # noqa: E402
from adapters import siem, tickets  # noqa: E402
from test_outputs import check_metrics_text  # noqa: E402

T0 = 1_800_000_000


def iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def entry(fid, sev="high", status="open", asset="host:web-1", check="ssh.password_auth", **kw):
    return dict({"id": fid, "check": check, "layer": "host", "asset": asset, "title": f"secret-ish title {fid}",
                 "severity": sev, "status": status, "first_seen": iso(T0), "last_seen": iso(T0), "fixed_at": None,
                 "evidence": f"runs/2027-01-15/host.raw.json#{fid}", "remediation": "do the private thing",
                 "needs_human": False, "owner": "platform", "kind": "compliance", "attributes": {},
                 "collector": "host", "collector_version": "0.1.0"}, **kw)


class FakeGitHub(http.server.BaseHTTPRequestHandler):
    """Just enough of the issues API: repo, list (labels filter, pagination), create, patch, comment."""
    state = {}

    @classmethod
    def reset(cls, private=True):
        cls.state = {"issues": {}, "next": 1, "calls": [], "private": private, "auth": set(), "limit_once": None}

    def _send(self, code, obj=None, headers=None):
        raw = json.dumps(obj).encode() if obj is not None else b""
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _handle(self, method):
        S = self.state
        S["auth"].add(self.headers.get("Authorization"))
        path, _, q = self.path.partition("?")
        S["calls"].append((method, path))
        if S["limit_once"] and method != "GET":
            code, hdr = S["limit_once"]
            S["limit_once"] = None
            return self._send(code, {"message": "rate limited"}, hdr)
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"null")
        parts = path.strip("/").split("/")          # repos/o/r[/issues[/n[/comments]]]
        if len(parts) == 3 and method == "GET":
            return self._send(200, {"private": S["private"]})
        if len(parts) == 4 and method == "GET":
            qs = dict(x.split("=", 1) for x in q.split("&") if x)
            per, page = int(qs.get("per_page", 30)), int(qs.get("page", 1))
            rows = [i for _, i in sorted(S["issues"].items()) if qs.get("labels") in [x["name"] for x in i["labels"]]]
            return self._send(200, rows[(page - 1) * per: page * per])
        if len(parts) == 4 and method == "POST":
            n = S["next"]
            S["next"] += 1
            S["issues"][n] = {"number": n, "title": body["title"], "body": body["body"], "state": "open",
                              "state_reason": None, "labels": [{"name": x} for x in body.get("labels", [])], "comments": []}
            return self._send(201, S["issues"][n])
        if len(parts) == 5 and method == "PATCH":
            i = S["issues"][int(parts[4])]
            for k in ("title", "body", "state", "state_reason"):
                if k in body:
                    i[k] = body[k]
            if "labels" in body:
                i["labels"] = [{"name": x} for x in body["labels"]]
            return self._send(200, i)
        if len(parts) == 6 and method == "POST":
            S["issues"][int(parts[4])]["comments"].append(body["body"])
            return self._send(201, {})
        return self._send(404, {})

    def do_GET(self):  # noqa: N802
        self._handle("GET")

    def do_POST(self):  # noqa: N802
        self._handle("POST")

    def do_PATCH(self):  # noqa: N802
        self._handle("PATCH")

    def log_message(self, *a):
        pass


def serve(handler):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class Base(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d)
        self.tok = os.path.join(self.d, "token")
        with open(os.open(self.tok, os.O_WRONLY | os.O_CREAT, 0o600), "w") as f:
            f.write("tok-123\n")


class Tickets(Base):
    def setUp(self):
        super().setUp()
        FakeGitHub.reset()
        self.srv = serve(FakeGitHub)
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)
        self.cfg = {"type": "github", "repo": "org/sec", "token_file": self.tok, "write_interval": 0,
                    "api_url": f"http://127.0.0.1:{self.srv.server_port}"}
        self.slept = []

    def sync(self, entries, **cfg):
        c = dict(self.cfg, **cfg)
        b = tickets.backend(c, sleep=self.slept.append)
        return tickets.sync(b, entries, c)

    def issues(self):
        return FakeGitHub.state["issues"]

    def test_lifecycle_idempotent_close_reopen_accept(self):
        E = {"a": entry("a", "critical"), "b": entry("b", "high", asset="host:web-2"), "c": entry("c", "medium"),
             "f": entry("f", "high", status="fixed")}
        n = self.sync(E)
        self.assertEqual((n["created"], n["below_threshold"]), (2, 1), "high and above only; fixed never opened")
        self.assertEqual(len(self.issues()), 2)
        self.assertIn("Bearer tok-123", FakeGitHub.state["auth"])
        calls = len(FakeGitHub.state["calls"])
        n = self.sync(E)                                        # rerun: nothing changes
        self.assertEqual((n["created"], n["updated"], n["unchanged"]), (0, 0, 2))
        self.assertTrue(all(m == "GET" for m, _ in FakeGitHub.state["calls"][calls:]), "idempotent: reads only")
        # lost local state is irrelevant: identity is the marker in the body (no local mapping file exists at all)
        a = next(i for i in self.issues().values() if "finding=a " in i["body"])
        self.assertEqual({x["name"] for x in a["labels"]}, {"security-platform", "severity:critical"})
        # a human label survives; fixed -> closed completed
        a["labels"].append({"name": "team-x"})
        E["a"] = entry("a", "critical", status="fixed")
        n = self.sync(E)
        self.assertEqual(n["closed"], 1)
        self.assertEqual((a["state"], a["state_reason"]), ("closed", "completed"))
        self.assertIn("team-x", {x["name"] for x in a["labels"]})
        # regression -> reopened with one comment
        E["a"] = entry("a", "critical", reopened_count=1)
        n = self.sync(E)
        self.assertEqual(n["reopened"], 1)
        self.assertEqual(a["state"], "open")
        self.assertEqual(len(a["comments"]), 1)
        self.assertIn("regression", a["comments"][0])
        self.assertEqual(self.sync(E)["reopened"], 0)
        # accepted risk -> closed as not planned, labelled; expired exception -> reopened saying so
        E["a"] = entry("a", "critical", status="accepted", exception={"approved_by": "lead", "expires": "2027-06-01"})
        self.sync(E)
        self.assertEqual((a["state"], a["state_reason"]), ("closed", "not_planned"))
        self.assertIn("accepted-risk", {x["name"] for x in a["labels"]})
        E["a"] = entry("a", "critical", exception={"approved_by": "lead", "expires": "2027-01-01", "expired": True})
        self.sync(E)
        self.assertEqual(a["state"], "open")
        self.assertNotIn("accepted-risk", {x["name"] for x in a["labels"]})
        self.assertIn("exception expired", a["comments"][-1])
        # a ticket closed by hand is reopened while the ledger has the finding open
        b = next(i for i in self.issues().values() if "finding=b " in i["body"])
        b["state"], b["state_reason"] = "closed", "completed"
        self.assertEqual(self.sync(E)["reopened"], 1)
        # severity dropped below the threshold: still managed, still closes when fixed
        E["b"] = entry("b", "low", asset="host:web-2", status="fixed")
        self.assertEqual(self.sync(E)["closed"], 1)
        self.assertEqual(len(self.issues()), 2, "never a duplicate")

    def test_body_minimal_by_default_and_configurable(self):
        self.sync({"a": entry("a", "critical")}, evidence_url="https://evidence.example.internal/{evidence}")
        i = self.issues()[1]
        self.assertNotIn("secret-ish", i["body"] + i["title"], "the finding title is not exported by default")
        self.assertNotIn("private thing", i["body"], "nor the remediation text")
        for want in ("`ssh.password_auth`", "`host:web-1`", "critical", iso(T0),
                     "(https://evidence.example.internal/runs/2027-01-15/host.raw.json#a)"):
            self.assertIn(want, i["body"])
        self.assertEqual(i["title"], "[critical] ssh.password_auth on host:web-1")
        FakeGitHub.reset()
        self.sync({"a": entry("a", "critical")}, fields=["control", "severity", "remediation"], title="finding",
                  labels={"severity_prefix": ""})
        i = self.issues()[1]
        self.assertIn("private thing", i["body"])
        self.assertNotIn("host:web-1", i["body"])
        self.assertEqual(i["title"], "[critical] secret-ish title a")
        self.assertEqual([x["name"] for x in i["labels"]], ["security-platform"])
        with self.assertRaises(ValueError):
            tickets.render(entry("a"), {"fields": ["evidence_content"]})

    def test_accepted_created_only_on_request(self):
        E = {"x": entry("x", status="accepted", exception={"approved_by": "lead", "expires": "2027-06-01"})}
        self.assertEqual(self.sync(E)["created"], 0)
        self.assertEqual(self.sync(E, create_accepted=True)["created"], 1)
        i = self.issues()[1]
        self.assertEqual((i["state"], i["state_reason"]), ("closed", "not_planned"))
        self.assertIn("approved by lead", self.sync(E, fields=["control", "exception"], create_accepted=True) and
                      self.issues()[1]["body"])

    def test_dry_run_writes_nothing(self):
        n = self.sync({"a": entry("a"), "b": entry("b")}, dry_run=True)
        self.assertEqual((n["created"], n["dry_run"]), (2, True))
        self.assertEqual(self.issues(), {})
        self.assertTrue(all(m == "GET" for m, _ in FakeGitHub.state["calls"]))

    def test_public_repository_refused(self):
        FakeGitHub.reset(private=False)
        with self.assertRaises(PermissionError):
            self.sync({"a": entry("a")})
        self.assertEqual(self.issues(), {})

    def test_token_file_must_be_private(self):
        os.chmod(self.tok, 0o644)
        with self.assertRaises(PermissionError):
            tickets.backend(self.cfg)

    def test_rate_limits(self):
        # secondary limit with Retry-After within max_wait: waits, retries, succeeds
        FakeGitHub.state["limit_once"] = (403, {"Retry-After": "7"})
        self.assertEqual(self.sync({"a": entry("a")})["created"], 1)
        self.assertIn(7.0, self.slept)
        # budget gone for longer than max_wait: stops cleanly, the rest is deferred; next run catches up
        FakeGitHub.state["limit_once"] = (403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(int(time.time()) + 3600)})
        n = self.sync({"a": entry("a"), "b": entry("b"), "c": entry("c")})
        self.assertTrue(n.get("rate_limited"))
        self.assertEqual(n["created"], 0)
        n = self.sync({"a": entry("a"), "b": entry("b"), "c": entry("c")})
        self.assertEqual((n["created"], n["unchanged"]), (2, 1))
        # per-run write budget and pacing between writes
        self.slept.clear()
        n = self.sync({k: entry(k) for k in "defg"}, max_writes=2, write_interval=0.5)
        self.assertEqual((n["created"], n["deferred"]), (2, 2))
        self.assertTrue(any(0 < s <= 0.5 for s in self.slept), "writes are paced")
        self.assertEqual(len(self.issues()), 5)

    def test_duplicate_tickets_closed(self):
        self.sync({"a": entry("a")})
        dup = dict(self.issues()[1], number=2, comments=[])
        self.issues()[2] = dup
        FakeGitHub.state["next"] = 3
        n = self.sync({"a": entry("a")})
        self.assertEqual(n["duplicates"], 1)
        self.assertEqual((self.issues()[1]["state"], self.issues()[2]["state"]), ("open", "closed"))

    def test_future_backend_is_explicit(self):
        with self.assertRaises(NotImplementedError):
            tickets.backend({"type": "jira"})


class Collector(http.server.BaseHTTPRequestHandler):
    got, fail = [], []

    def do_POST(self):  # noqa: N802
        raw = self.rfile.read(int(self.headers["Content-Length"]))
        if Collector.fail:
            code = Collector.fail.pop(0)
            self.send_response(code)
            self.send_header("Retry-After", "1")
            self.end_headers()
            return
        Collector.got.append((self.headers.get("Authorization"), self.headers.get("Content-Type"), raw))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a):
        pass


class Siem(Base):
    def setUp(self):
        super().setUp()
        Collector.got, Collector.fail = [], []
        self.srv = serve(Collector)
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)
        self.url = f"http://127.0.0.1:{self.srv.server_port}/ingest"

    def test_http_batches_retry_and_auth(self):
        evs = [(str(i), {"n": i}) for i in range(5)]
        done, slept = [], []
        Collector.fail = [503, 429]
        siem.http({"url": self.url, "token_file": self.tok, "batch_size": 2}, evs, done.extend, sleep=slept.append)
        self.assertEqual(done, ["0", "1", "2", "3", "4"])
        self.assertEqual(len(Collector.got), 3)
        self.assertEqual(slept, [1.0, 1.0], "Retry-After honoured")
        auth, ctype, raw = Collector.got[0]
        self.assertEqual((auth, ctype), ("Bearer tok-123", "application/x-ndjson"))
        self.assertEqual([json.loads(x) for x in raw.decode().splitlines()], [{"n": 0}, {"n": 1}])
        Collector.got = []
        siem.http({"url": self.url, "format": "json", "wrap": "event", "auth_scheme": "Token", "token_file": self.tok},
                  evs[:2], lambda ids: None)
        auth, ctype, raw = Collector.got[0]
        self.assertEqual((auth, json.loads(raw)), ("Token tok-123", [{"event": {"n": 0}}, {"event": {"n": 1}}]))

    def test_http_permanent_failure_keeps_unsent(self):
        done = []
        Collector.fail = [400]
        with self.assertRaises(RuntimeError) as cm:
            siem.http({"url": self.url, "batch_size": 1}, [("a", {}), ("b", {})], done.extend, sleep=lambda s: None)
        self.assertNotIn("tok", str(cm.exception))
        self.assertEqual(done, [])

    def test_file_and_stdout(self):
        p = os.path.join(self.d, "out", "findings.jsonl")
        done = []
        siem.file({"path": p, "max_bytes": 5}, [("a", {"x": 1})], done.extend)
        siem.file({"path": p, "max_bytes": 5}, [("b", {"x": 2})], done.extend)
        self.assertEqual(oct(os.stat(p).st_mode & 0o777), "0o600")
        self.assertEqual(open(p).read(), '{"x":2}\n')
        self.assertEqual(open(p + ".1").read(), '{"x":1}\n', "rotated past max_bytes")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            siem.stdout({}, [("c", {"y": 1})], done.extend)
        self.assertEqual((buf.getvalue(), done), ('{"y":1}\n', ["a", "b", "c"]))

    def test_changes_mode_activity_and_state(self):
        E = {"a": entry("a"), "b": entry("b", "low"), "f": entry("f", status="fixed")}
        evs, dig = export.siem_events(E, {}, {})
        self.assertEqual([f for f, _ in evs], ["a", "b"], "a finding this sink never saw open is not 'closed'")
        a = dict(evs)["a"]
        self.assertEqual((a["class_uid"], a["activity_id"], a["type_uid"], a["finding_info"]["uid"]), (2003, 1, 200301, "a"))
        sent = dict(dig)
        self.assertEqual(export.siem_events(E, {}, sent)[0], [], "unchanged: nothing to send")
        E["a"] = entry("a", status="fixed")
        E["b"] = entry("b", "medium")
        evs, _ = export.siem_events(E, {}, sent)
        self.assertEqual({f: e["activity_name"] for f, e in evs}, {"a": "Close", "b": "Update"})
        self.assertEqual(len(export.siem_events(E, {"mode": "all"}, sent)[0]), 3)
        self.assertEqual([f for f, _ in export.siem_events(E, {"min_severity": "high"}, {})[0]], [])


class Driver(Base):
    """core/export.py end to end: every sink runs, state survives, metrics contract, failures counted."""

    def setUp(self):
        super().setUp()
        FakeGitHub.reset()
        Collector.got, Collector.fail = [], []
        for h in (FakeGitHub, Collector):
            s = serve(h)
            self.addCleanup(s.server_close)
            self.addCleanup(s.shutdown)
            setattr(self, h.__name__, s)
        self.data = os.path.join(self.d, "data")
        os.makedirs(self.data)
        json.dump({"entries": {"a": entry("a", "critical"), "b": entry("b", "low")}},
                  open(os.path.join(self.data, "ledger.json"), "w"))
        self.inst = os.path.join(self.d, "instance.json")
        self.out = os.path.join(self.d, "siem.jsonl")
        json.dump({"export": {
            "tickets": [{"type": "github", "repo": "org/sec", "token_file": self.tok, "write_interval": 0,
                         "api_url": f"http://127.0.0.1:{self.FakeGitHub.server_port}"}],
            "siem": [{"type": "http", "url": f"http://127.0.0.1:{self.Collector.server_port}/x", "token_file": self.tok,
                      "retries": 0},
                     {"type": "file", "path": self.out, "name": "shipper"}]}}, open(self.inst, "w"))

    def run_export(self, *extra):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = export.main(["--data", self.data, "--instance", self.inst, "--now", str(T0)] + list(extra))
        return rc, err.getvalue()

    def test_end_to_end(self):
        rc, log = self.run_export("--dry-run")
        self.assertEqual(rc, 0, log)
        self.assertEqual((FakeGitHub.state["issues"], Collector.got, os.path.exists(self.out)), ({}, [], False))
        Collector.fail = [500]                                         # the http sink fails once ...
        rc, log = self.run_export()
        self.assertEqual(rc, 1)
        self.assertEqual(len(FakeGitHub.state["issues"]), 1, "... the others still ran")
        self.assertEqual(len(open(self.out).read().splitlines()), 2)
        prom = open(os.path.join(self.data, "metrics", "export.prom")).read()
        check_metrics_text(self, prom)
        self.assertIn('security_export_consecutive_failures{sink="siem-http-0"} 1', prom)
        self.assertIn('security_export_items{result="created",sink="tickets-github-0"} 1', prom)
        rc, log = self.run_export()                                    # retried: only the failed sink sends
        self.assertEqual(rc, 0, log)
        self.assertEqual(len(Collector.got), 1)
        self.assertEqual(len(open(self.out).read().splitlines()), 2, "file sink: nothing new")
        prom = open(os.path.join(self.data, "metrics", "export.prom")).read()
        self.assertIn('security_export_consecutive_failures{sink="siem-http-0"} 0', prom)
        self.assertIn('security_export_failures_total{sink="siem-http-0"} 1', prom)
        for p in os.listdir(os.path.join(self.data, "state", "export")):
            self.assertEqual(os.stat(os.path.join(self.data, "state", "export", p)).st_mode & 0o077, 0)

    def test_runner_job_and_metrics_pickup(self):
        import runner
        self.assertTrue(hasattr(runner.Runner, "job_export"))
        src = open(os.path.join(ROOT, "runner", "runner.py")).read()
        self.assertIn('"export.prom"', src)


if __name__ == "__main__":
    unittest.main()
