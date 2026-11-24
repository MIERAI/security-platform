"""A tiny in-memory Kubernetes API (secrets, configmaps; list with label selectors; create; server-side apply;
delete) over plain HTTP, with bearer-token authentication and per-token permissions, for the inbox tests."""
import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class FakeKube:
    def __init__(self, tokens):
        """tokens: {token: {"user": name, "verbs": {(resource, verb), ...}}}"""
        self.tokens, self.objects, self.calls = tokens, {}, []
        fk = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def reply(self, code, obj):
                body = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def handle_any(self, method):
                u = urllib.parse.urlparse(self.path)
                parts = u.path.strip("/").split("/")      # api v1 namespaces ns res [name]
                ns, res, name = parts[3], parts[4], (parts[5] if len(parts) > 5 else None)
                tok = (self.headers.get("Authorization") or "")[7:]
                who = fk.tokens.get(tok)
                verb = {"GET": "get" if name else "list", "POST": "create", "PATCH": "patch", "DELETE": "delete"}[method]
                fk.calls.append((who and who["user"], method, res, name))
                if not who:
                    return self.reply(401, {"message": "Unauthorized"})
                if (res, verb) not in who["verbs"]:
                    return self.reply(403, {"message": f"forbidden: {verb} {res}"})
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n)) if n else None
                store = fk.objects.setdefault((ns, res), {})
                if method == "GET" and name:
                    return self.reply(200, store[name]) if name in store else self.reply(404, {"message": "NotFound"})
                if method == "GET":
                    sel = dict(urllib.parse.parse_qsl(u.query)).get("labelSelector", "")
                    want = dict(x.split("=", 1) for x in sel.split(",") if x)
                    items = [o for o in store.values()
                             if all((o["metadata"].get("labels") or {}).get(k) == v for k, v in want.items())]
                    return self.reply(200, {"items": items})
                if method == "POST":
                    if body["metadata"]["name"] in store:
                        return self.reply(409, {"message": "AlreadyExists"})
                    body["metadata"]["creationTimestamp"] = f"2026-01-01T00:00:{len(fk.calls):02d}Z"
                    store[body["metadata"]["name"]] = body
                    return self.reply(201, body)
                if method == "PATCH":
                    store[name] = body
                    return self.reply(200, body)
                if method == "DELETE":
                    return self.reply(200, store.pop(name)) if name in store else self.reply(404, {"message": "NotFound"})

            def do_GET(self):
                self.handle_any("GET")

            def do_POST(self):
                self.handle_any("POST")

            def do_PATCH(self):
                self.handle_any("PATCH")

            def do_DELETE(self):
                self.handle_any("DELETE")

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
