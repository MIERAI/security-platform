"""Threat-intel automation: conditional GET (ETag -> 304), the OSV adapter and the deterministic OSV range matcher."""
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
import zipfile

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path[:0] = [ROOT, os.path.join(ROOT, "collectors", "vuln-intel")]
from adapters import feeds  # noqa: E402
import osvmatch  # noqa: E402

HITS = []


class H(http.server.BaseHTTPRequestHandler):
    body = b"payload"

    def do_GET(self):
        HITS.append(self.headers.get("If-None-Match"))
        if self.headers.get("If-None-Match") == '"v1"':
            self.send_response(304)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("ETag", '"v1"')
        self.send_header("Content-Length", str(len(self.body)))
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, *a):
        pass


class ConditionalGet(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_port}/feed"

    def tearDown(self):
        self.srv.shutdown()
        shutil.rmtree(self.d)

    def test_etag_304_and_max_age(self):
        HITS.clear()
        p = os.path.join(self.d, "f")
        _, t1 = feeds.fetch(self.url, p, max_age_h=0)
        self.assertEqual(open(p, "rb").read(), b"payload")
        time.sleep(0.01)
        _, t2 = feeds.fetch(self.url, p, max_age_h=0)          # revalidate: 304, age refreshed, content kept
        self.assertEqual(HITS, [None, '"v1"'])
        self.assertGreater(t2, t1)
        self.assertEqual(open(p, "rb").read(), b"payload")
        feeds.fetch(self.url, p, max_age_h=24)                  # fresh enough: no request at all
        self.assertEqual(len(HITS), 2)


ADV = {"id": "GO-2099-0001", "aliases": ["CVE-2099-1"], "published": "2099-01-02T00:00:00Z", "modified": "x",
       "database_specific": {"severity": "CRITICAL"},
       "affected": [{"package": {"ecosystem": "Go", "name": "example.com/lib"},
                     "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.4.2"},
                                                              {"introduced": "2.0.0"}, {"fixed": "2.1.0"}]}]}]}


class OSV(unittest.TestCase):
    def test_ranges(self):
        ev = ADV["affected"][0]["ranges"][0]["events"]
        for v, want in [("v1.0.0", True), ("v1.4.1", True), ("v1.4.2", False), ("v1.9.0", False), ("v2.0.0", True),
                        ("v2.0.9-rc.1", True), ("v2.1.0", False), ("v2.1.0-rc.1", True)]:
            self.assertEqual(osvmatch.in_range(v, ev), want, v)
        self.assertFalse(osvmatch.in_range("1.5.0", [{"introduced": "1.0.0"}, {"last_affected": "1.4.0"}]))

    def test_adapter_and_match(self):
        d = tempfile.mkdtemp()
        try:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as z:
                z.writestr("GO-2099-0001.json", json.dumps(ADV))
                z.writestr("GO-2099-0002.json", json.dumps(dict(ADV, id="GO-2099-0002", withdrawn="2099-02-01")))
            p = os.path.join(d, "osv", "Go", "all.zip")
            os.makedirs(os.path.dirname(p))
            open(p, "wb").write(buf.getvalue())
            json.dump({"checked_at": time.time()}, open(p + ".meta.json", "w"))
            idx = feeds.load({"type": "osv", "ecosystems": ["Go"]}, d)["index"]
            self.assertEqual([a["id"] for a in idx["Go"]["example.com/lib"]], ["GO-2099-0001"])   # withdrawn dropped
            cdx = {"components": [{"purl": "pkg:golang/example.com/lib@v1.3.0"}, {"purl": "pkg:golang/example.com/lib@v2.1.0"},
                                  {"purl": "pkg:deb/debian/openssl@3.0"}]}
            hits = osvmatch.match(osvmatch.components(cdx), idx)
            self.assertEqual([(h[2], h[3]["id"]) for h in hits], [("v1.3.0", "GO-2099-0001")])
            self.assertEqual(osvmatch.fixed_version(hits[0][3]), "1.4.2")
        finally:
            shutil.rmtree(d)


if __name__ == "__main__":
    unittest.main()
