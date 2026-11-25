#!/usr/bin/env python3
"""A fake of the HTTP services the events shipper talks to (test tool, stdlib only): a Loki push endpoint, the
GitHub REST API of the github-account source and the Tailscale configuration-log API with its OAuth token endpoint.
Writes its port to --port-file; everything it records goes next to that file (the case's sandbox):

  pushed/NNNN.json   every accepted push body, byte for byte (NNNN counts from 0001)
  loki-fail          while this file exists, pushes are answered 500 and not recorded
  api.json           the API routes, read on every request: {"<path[?query]>": [status, body, {headers}] |
                     {"redirect": "<path>"}}; a path with its query is looked up first, then without it. A route
                     with an ETag header answers 304 to a matching If-None-Match.
  leak/auth.txt      the Authorization header of any request that reached this server under the host name
                     "localhost" (a redirect target): credentials that followed a redirect to another host
  mutations.log      any method other than GET, and any POST but the push and the token exchange
"""
import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PUSH = "/loki/api/v1/push"
TOKEN = "/api/v2/oauth/token"


class H(BaseHTTPRequestHandler):
    root = "."
    port = 0
    pushes = 0

    def log_message(self, *a):
        pass

    def path_of(self, name):
        return os.path.join(self.root, name)

    def reply(self, code, body=None, headers=None):
        data = b"" if body is None else json.dumps(body).encode()
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def mutation(self):
        with open(self.path_of("mutations.log"), "a") as f:
            f.write(f"{self.command} {self.path}\n")

    def leaked(self):
        if self.headers.get("Host", "").startswith("localhost") and self.headers.get("Authorization"):
            os.makedirs(self.path_of("leak"), exist_ok=True)
            with open(self.path_of("leak/auth.txt"), "a") as f:
                f.write(self.headers["Authorization"] + "\n")

    def do_GET(self):
        self.leaked()
        try:
            routes = json.load(open(self.path_of("api.json")))
        except OSError:
            routes = {}
        r = routes.get(self.path) or routes.get(self.path.split("?")[0])
        if r is None:
            return self.reply(404, {"message": "Not Found"})
        if isinstance(r, dict) and "redirect" in r:
            return self.reply(302, None, {"Location": f"http://localhost:{self.port}{r['redirect']}"})
        code, body, headers = (r + [{}])[:3]
        if headers.get("ETag") and self.headers.get("If-None-Match") == headers["ETag"]:
            return self.reply(304)
        self.reply(code, body, headers)

    def do_POST(self):
        self.leaked()
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if self.path == TOKEN:
            return self.reply(200, {"access_token": "short-lived-conformance"})
        if self.path != PUSH:
            self.mutation()
            return self.reply(405, {"message": "read-only"})
        if os.path.exists(self.path_of("loki-fail")):
            return self.reply(500, {"message": "store unavailable"})
        H.pushes += 1
        os.makedirs(self.path_of("pushed"), exist_ok=True)
        with open(self.path_of(f"pushed/{H.pushes:04d}.json"), "wb") as f:
            f.write(raw)
        self.reply(204)

    def do_PUT(self):
        self.mutation()
        self.reply(405)

    do_PATCH = do_DELETE = do_PUT


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port-file", required=True)
    a = ap.parse_args()
    H.root = os.path.dirname(os.path.abspath(a.port_file))
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    H.port = srv.server_address[1]
    with open(a.port_file + ".tmp", "w") as f:
        f.write(str(H.port))
    os.replace(a.port_file + ".tmp", a.port_file)
    srv.serve_forever()


if __name__ == "__main__":
    main()
