#!/usr/bin/env python3
"""A fake of the read APIs the detection collector calls: Loki (instant query, ruler rules), Prometheus (instant
query on ALERTS) and Alertmanager (status with the configuration). Test tool, stdlib only.

usage: mock_obs.py --config SCENARIO.json [--token-file FILE] --port-file FILE
Scenario: {"sources": {source: {label value: lines}}, "rules": [{"name", "health"}], "am_original": "<yaml>",
           "alerts": {severity: minutes}, "fail": [path answered 503], "require_token": false (log-store paths)}
Next to the port file it writes .svc-obs-requests.log (method, path, query of every request),
.svc-obs-mutations.log (any method but GET: a read-only client never sends one; answered 405) and
.svc-obs-token-seen (a request carried exactly "Bearer <content of --token-file>"; the value is never written)."""
import argparse
import json
import os
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def handler(scenario, token_file, out):
    def log(name, line):
        with open(os.path.join(out, name), "a") as f:
            f.write(line + "\n")

    def token_ok(header):
        try:
            with open(token_file) as f:
                return header == "Bearer " + f.read().strip()
        except (OSError, TypeError):
            return False

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def reply(self, code, obj):
            b = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def mutate(self):
            log(".svc-obs-mutations.log", f"{self.command} {self.path}")
            self.reply(405, {"error": "read-only"})

        do_POST = do_PUT = do_PATCH = do_DELETE = mutate

        def do_GET(self):  # noqa: N802
            u = urllib.parse.urlparse(self.path)
            q = urllib.parse.parse_qs(u.query).get("query", [""])[0]
            log(".svc-obs-requests.log", f"GET {u.path} {q}")
            auth = self.headers.get("Authorization")
            if token_file and auth and token_ok(auth):
                open(os.path.join(out, ".svc-obs-token-seen"), "w").close()
            if scenario.get("require_token") and u.path.startswith(("/loki/", "/prometheus/")) and not token_ok(auth):
                return self.reply(401, {"status": "error", "error": "unauthorized"})
            if u.path in scenario.get("fail", []):
                return self.reply(503, {"status": "error"})
            if u.path == "/loki/api/v1/query":
                src = q.split('source="')[1].split('"')[0]
                label = q.split("sum by (")[1].split(")")[0]
                res = [{"metric": {label: k}, "value": [time.time(), str(v)]}
                       for k, v in scenario.get("sources", {}).get(src, {}).items()]
                return self.reply(200, {"status": "success", "data": {"resultType": "vector", "result": res}})
            if u.path == "/prometheus/api/v1/rules":
                return self.reply(200, {"status": "success", "data": {"groups": [{"name": "security", "rules": scenario.get("rules", [])}]}})
            if u.path == "/api/v1/query":
                res = [{"metric": {"severity": k}, "value": [time.time(), str(v)]} for k, v in scenario.get("alerts", {}).items()]
                return self.reply(200, {"status": "success", "data": {"resultType": "vector", "result": res}})
            if u.path == "/api/v2/status":
                return self.reply(200, {"cluster": {"status": "ready"}, "config": {"original": scenario.get("am_original", "")}})
            self.reply(404, {"status": "error"})
    return H


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--token-file")
    ap.add_argument("--port-file", required=True)
    a = ap.parse_args()
    with open(a.config) as f:
        scenario = json.load(f)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler(scenario, a.token_file, os.path.dirname(os.path.abspath(a.port_file))))
    with open(a.port_file + ".tmp", "w") as f:
        f.write(str(srv.server_address[1]))
    os.replace(a.port_file + ".tmp", a.port_file)
    srv.serve_forever()


if __name__ == "__main__":
    main()
