#!/usr/bin/env python3
"""A fake of the code host (GitHub REST) and overlay network (Tailscale API v2) endpoints the identity collector reads.
Test tool, stdlib only. Writes its port to --port-file; answers from --data (routes), logs every request to --log as
"<METHOD> <path?query> auth=<yes|no> inm=<yes|no>" (never a header value).

Route value: {"body": ..., "status": 200, "headers": {...}, "paginate": true, "rate_limited": true}. A route is looked up
by path+query, then without its page parameter, then by path alone. GitHub routes need the conformance token (see fake_gh.py), /api/v2/... routes the
Tailscale API key of --data or the access token this mock issues at POST /api/v2/oauth/token. Lists of a `paginate`
route are served `page_size` at a time with Link: rel="next" (servers may cap per_page; clients must follow Link).
Every answer carries an ETag; a matching If-None-Match gets 304. Only GET (and the OAuth token POST) exist here.
"""
import argparse
import hashlib
import json
import os
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

GH_TOKEN = "gho_" + "conformanceCanary" + "0" * 19
TS_ACCESS = "ts-conformance-access-canary-1c4f"
RESET = 4102444800      # 2100-01-01T00:00:00Z


def handler(data, log):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def reply(self, code, body, headers=None):
            b = b"" if body is None else json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def record(self):
            with open(log, "a") as f:
                f.write(f"{self.command} {self.path} auth={'yes' if self.headers.get('Authorization') else 'no'} "
                        f"inm={'yes' if self.headers.get('If-None-Match') else 'no'}\n")

        def authorized(self, path):
            auth = self.headers.get("Authorization") or ""
            if path.startswith("/api/v2/"):
                return auth in ("Bearer " + data.get("tailscale_key", "-"), "Bearer " + TS_ACCESS)
            return auth.endswith(" " + GH_TOKEN)

        def do_POST(self):
            self.record()
            n = int(self.headers.get("Content-Length") or 0)
            form = dict(urllib.parse.parse_qsl(self.rfile.read(n).decode()))
            if self.path == "/api/v2/oauth/token" and form.get("client_secret") == data.get("tailscale_oauth_secret"):
                return self.reply(200, {"access_token": TS_ACCESS, "token_type": "Bearer", "expires_in": 3600})
            return self.reply(405 if self.path != "/api/v2/oauth/token" else 401, {"message": "refused"})

        def do_PUT(self):
            self.record()
            self.reply(405, {"message": "read-only mock"})

        do_PATCH = do_DELETE = do_PUT

        def do_GET(self):
            self.record()
            u = urllib.parse.urlsplit(self.path)
            q = dict(urllib.parse.parse_qsl(u.query))
            routes = data["routes"]
            unpaged = urllib.parse.urlencode([(k, v) for k, v in urllib.parse.parse_qsl(u.query) if k != "page"])
            r = routes.get(self.path) or routes.get(u.path + ("?" + unpaged if unpaged else "")) or routes.get(u.path)
            if not self.authorized(u.path):
                return self.reply(401, {"message": "Requires authentication"})
            if r is None:
                return self.reply(404, {"message": "Not Found"})
            headers = dict(r.get("headers") or {})
            if not u.path.startswith("/api/v2/"):
                headers.setdefault("X-OAuth-Scopes", data.get("scopes", ""))
                if data.get("token_expiration"):
                    headers.setdefault("GitHub-Authentication-Token-Expiration", data["token_expiration"])
            if r.get("rate_limited"):
                headers.update({"X-RateLimit-Limit": "5000", "X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(RESET)})
                return self.reply(403, {"message": "API rate limit exceeded for user ID 1."}, headers)
            body, status = r.get("body"), r.get("status", 200)
            if r.get("paginate") and isinstance(body, list):
                size, page = data.get("page_size", 2), int(q.get("page", "1"))
                if page * size < len(body):
                    nq = dict(q, page=str(page + 1))
                    nxt = f"http://{self.headers['Host']}{u.path}?{urllib.parse.urlencode(nq)}"
                    headers["Link"] = f'<{nxt}>; rel="next"'
                body = body[(page - 1) * size:page * size]
            etag = 'W/"' + hashlib.sha1(json.dumps(body, sort_keys=True).encode()).hexdigest()[:16] + '"'
            if status == 200:
                headers["ETag"] = etag
                if self.headers.get("If-None-Match") == etag:
                    return self.reply(304, None, headers)
            self.reply(status, body, headers)
    return H


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port-file", required=True)
    ap.add_argument("--data", required=True)
    ap.add_argument("--log", required=True)
    a = ap.parse_args()
    data = json.load(open(a.data))
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler(data, a.log))
    with open(a.port_file + ".tmp", "w") as f:
        f.write(str(srv.server_address[1]))
    os.replace(a.port_file + ".tmp", a.port_file)
    srv.serve_forever()


if __name__ == "__main__":
    main()
