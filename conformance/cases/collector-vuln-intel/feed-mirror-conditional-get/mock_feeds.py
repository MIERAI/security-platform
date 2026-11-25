#!/usr/bin/env python3
"""A fake vulnerability-feed server (KEV, EPSS, OSV, ... mirrors) for the conformance suite. Test tool, stdlib only.
Writes its port to --port-file; every request is appended to --log as "<METHOD> <path> inm=<If-None-Match or ->".

--routes FILE: {"<path>": {"file": "<payload file next to the routes file>" | "body": "<text>", "etag": "...",
                           "status": N}}. A request whose If-None-Match equals the route's etag gets 304; a route with
`status` answers that status with no body; unknown paths get 404; methods other than GET get 405."""
import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def handler(routes, base, log):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def record(self):
            with open(log, "a") as f:
                f.write(f"{self.command} {self.path} inm={self.headers.get('If-None-Match') or '-'}\n")

        def reply(self, code, body=b"", headers=None):
            self.send_response(code)
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            self.record()
            r = routes.get(self.path)
            if r is None:
                return self.reply(404, b"not found")
            if r.get("status"):
                return self.reply(r["status"], b"unavailable")
            if r.get("etag") and self.headers.get("If-None-Match") == r["etag"]:
                return self.reply(304, headers={"ETag": r["etag"]})
            body = open(os.path.join(base, r["file"]), "rb").read() if "file" in r else r["body"].encode()
            return self.reply(200, body, {"ETag": r["etag"]} if r.get("etag") else None)

        def other(self):
            self.record()
            self.reply(405, b"read-only mirror")

        do_POST = do_PUT = do_DELETE = do_PATCH = other
    return H


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port-file", required=True)
    ap.add_argument("--routes", required=True)
    ap.add_argument("--log", required=True)
    a = ap.parse_args()
    routes = json.load(open(a.routes))
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler(routes, os.path.dirname(a.routes), a.log))
    with open(a.port_file + ".tmp", "w") as f:
        f.write(str(srv.server_address[1]))
    os.replace(a.port_file + ".tmp", a.port_file)
    srv.serve_forever()


if __name__ == "__main__":
    main()
