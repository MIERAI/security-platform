#!/usr/bin/env python3
"""A fake code host REST API (GitHub- and Gitea-shaped), test tool, stdlib only. Writes its port to --port-file.

Routes come from a JSON fixture read on EVERY request (--fixture; the harness stages it, rendered, after the service has
started): {"token": "...", "routes": {"/path": ROUTE}}, matched on the path without the query. ROUTE is one of
  {"status": 200, "body": ..., "headers": {...}}           one answer
  {"items": [...], "page_size": N}                         a list served in pages: page size = min(per_page or limit
                                                           (default 30), N); Link rel="next"/"last" and X-Total-Count
  {"redirect": "/other/path"}                              302 to http://localhost:<port>/other/path (another host name)
An unknown path is 404 {"message": "Not Found"}. With "token", a request without "Authorization: token|Bearer <token>"
is 401. Records, next to the port file (names starting with .svc-, which the suite's write check ignores):
  .svc-<name>-requests.log     "METHOD PATH auth=yes|no" per request
  .svc-<name>-mutations.log    any request that is not GET/HEAD (a read-only collector never creates it)
  .svc-<name>-leaks/auth.txt   the Authorization header of every request that arrived under the host name localhost
"""
import argparse
import json
import os
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def make_handler(fixture, base):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def record(self, name, line):
            p = base + name
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "a") as f:
                f.write(line + "\n")

        def reply(self, code, body, headers=None):
            b = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(b)

        def mutate(self):
            self.record("-mutations.log", f"{self.command} {self.path}")
            self.reply(405, {"message": "read-only fake"})

        do_POST = do_PUT = do_PATCH = do_DELETE = mutate

        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            auth = self.headers.get("Authorization") or ""
            host = (self.headers.get("Host") or "").split(":")[0]
            self.record("-requests.log", f"{self.command} {self.path} auth={'yes' if auth else 'no'}")
            if host == "localhost" and auth:
                self.record("-leaks/auth.txt", auth)
            try:
                with open(fixture) as f:
                    fx = json.load(f)
            except (OSError, ValueError):
                return self.reply(503, {"message": "fixture not staged yet"})
            u = urllib.parse.urlsplit(self.path)
            tok = fx.get("token")
            if tok and auth not in (f"token {tok}", f"Bearer {tok}"):
                return self.reply(401, {"message": "Bad credentials"})
            r = (fx.get("routes") or {}).get(u.path)
            if r is None:
                return self.reply(404, {"message": "Not Found"})
            if "redirect" in r:
                port = self.server.server_address[1]
                self.send_response(302)
                self.send_header("Location", f"http://localhost:{port}{r['redirect']}")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return None
            if "items" in r:
                return self.page(u, r)
            return self.reply(r.get("status", 200), r.get("body"), r.get("headers"))

        def page(self, u, r):
            q = dict(urllib.parse.parse_qsl(u.query))
            size = min(int(q.get("per_page") or q.get("limit") or 30), int(r.get("page_size", 100)))
            page = int(q.get("page") or 1)
            items = r["items"]
            last = max(1, -(-len(items) // size))
            headers = {"X-Total-Count": str(len(items))}
            links = []
            if page < last:
                links.append(f'<{self.link(u, q, page + 1)}>; rel="next"')
                links.append(f'<{self.link(u, q, last)}>; rel="last"')
            if links:
                headers["Link"] = ", ".join(links)
            return self.reply(200, items[(page - 1) * size:page * size], headers)

        def link(self, u, q, page):
            port = self.server.server_address[1]
            return f"http://127.0.0.1:{port}{u.path}?" + urllib.parse.urlencode(dict(q, page=str(page)))

    return H


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixture", required=True)
    ap.add_argument("--port-file", required=True)
    a = ap.parse_args()
    base = a.port_file[:-len(".port")] if a.port_file.endswith(".port") else a.port_file
    srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(a.fixture, base))
    with open(a.port_file + ".tmp", "w") as f:
        f.write(str(srv.server_address[1]))
    os.replace(a.port_file + ".tmp", a.port_file)
    srv.serve_forever()


if __name__ == "__main__":
    main()
