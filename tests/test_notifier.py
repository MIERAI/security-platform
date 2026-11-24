"""Notifier adapters against in-process fake endpoints: payload shapes, 0600 secrets, errors without secrets, and the
runner's `notify` job end to end (a file notifier)."""
import http.server
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.parse

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path[:0] = [ROOT]
from notifier import notifiers  # noqa: E402

TOKEN = "123456:SECRET-bot-token"


class Sink(http.server.BaseHTTPRequestHandler):
    got = []
    status = 200

    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers["Content-Length"]))
        Sink.got.append((self.path, self.headers["Content-Type"], body))
        self.send_response(Sink.status)
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *a):
        pass


def secret_file(value, mode=0o600):
    d = tempfile.mkdtemp()
    p = os.path.join(d, "s")
    open(p, "w").write(value + "\n")
    os.chmod(p, mode)
    return p


class Notifiers(unittest.TestCase):
    def setUp(self):
        Sink.got, Sink.status = [], 200
        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Sink)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.shutdown)
        self.base = f"http://127.0.0.1:{self.srv.server_port}"

    def test_telegram(self):
        notifiers.send({"type": "telegram", "token_file": secret_file(TOKEN), "chat_id": 42, "api": self.base},
                       "Security today\nOpen: 1 high")
        path, ctype, body = Sink.got[0]
        self.assertEqual(path, f"/bot{TOKEN}/sendMessage")
        q = urllib.parse.parse_qs(body.decode())
        self.assertEqual(q["chat_id"], ["42"])
        self.assertIn("1 high", q["text"][0])

    def test_error_does_not_leak_the_token(self):
        Sink.status = 401
        with self.assertRaises(RuntimeError) as cm:
            notifiers.send({"type": "telegram", "token_file": secret_file(TOKEN), "chat_id": 1, "api": self.base}, "x")
        self.assertEqual(str(cm.exception), "HTTP 401")
        with self.assertRaises(RuntimeError) as cm:
            notifiers.send({"type": "telegram", "token_file": secret_file(TOKEN), "chat_id": 1,
                            "api": "http://127.0.0.1:9"}, "x")
        self.assertNotIn("SECRET", str(cm.exception))

    def test_secret_files_must_be_private(self):
        with self.assertRaises(PermissionError):
            notifiers.send({"type": "telegram", "token_file": secret_file(TOKEN, 0o644), "chat_id": 1}, "x")

    def test_webhook_formats(self):
        url = secret_file(self.base + "/hook/T0K")
        notifiers.send({"type": "webhook", "url_file": url}, "a\nb")
        notifiers.send({"type": "webhook", "url_file": url, "format": "json"}, "a\nb")
        notifiers.send({"type": "webhook", "url_file": url, "format": "text"}, "a\nb")
        self.assertEqual(json.loads(Sink.got[0][2]), {"text": "a\nb"})
        self.assertEqual(json.loads(Sink.got[1][2]), {"title": "a", "text": "b"})
        self.assertEqual((Sink.got[2][1], Sink.got[2][2]), ("text/plain; charset=utf-8", b"a\nb"))

    def test_exec(self):
        d = tempfile.mkdtemp()
        notifiers.send({"type": "exec", "argv": ["sh", "-c", f"cat > {d}/o"]}, "hello")
        self.assertEqual(open(f"{d}/o").read(), "hello")
        with self.assertRaises(RuntimeError):
            notifiers.send({"type": "exec", "argv": ["false"]}, "x")


class RunnerJob(unittest.TestCase):
    def test_notify_job(self):
        d = tempfile.mkdtemp()
        out = os.path.join(d, "summary.txt")
        json.dump({"name": "acme", "notify": [{"type": "file", "path": out}],
                   "runner": {"site": "hub", "role": "hub", "jobs": {"notify": {"type": "notify", "schedule": "0 8 * * *"}}}},
                  open(os.path.join(d, "instance.json"), "w"))
        json.dump({"entries": {}, "sli": {}, "collectors": {}}, open(os.path.join(d, "ledger.json"), "w"))
        r = subprocess.run([sys.executable, os.path.join(ROOT, "runner", "runner.py"), "run", "notify", "--instance",
                            os.path.join(d, "instance.json"), "--data", d], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("All clear.", open(out).read())


if __name__ == "__main__":
    unittest.main()
