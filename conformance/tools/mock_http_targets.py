#!/usr/bin/env python3
"""HTTP targets for the exposure conformance cases (test tool, stdlib only), on 127.0.0.1 only: one HTTP service
that answers like an unauthenticated Prometheus + Loki (fingerprints), and two sockets that accept a connection and
close it (a non-HTTP service: telnet, a database). Ports: --port-file (HTTP), <port-file without .port>.closed1 and
.closed2. Every request is logged to <base>.requests as "METHOD PATH"; a method other than GET/HEAD (a probe must
never send one) also creates <base>.MUTATION."""
import argparse
import json
import os
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROUTES = {"/": (200, "text/html", "<html><body>hello</body></html>"),
          "/metrics": (200, "text/plain", "# HELP up up\nup 1\n"),
          "/api/v1/status/buildinfo": (200, "application/json", json.dumps({"status": "success", "data": {"version": "2.53.0"}})),
          "/api/v1/status/flags": (200, "application/json", json.dumps({"status": "success", "data": {
              "web.enable-admin-api": "false", "web.enable-remote-write-receiver": "false", "storage.tsdb.path": "/x"}})),
          "/loki/api/v1/labels": (200, "application/json", json.dumps({"status": "success", "data": []})),
          "/v1/traces": (405, "text/plain", "method not allowed")}


def handler(base):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def log(self):
            with open(base + ".requests", "a") as f:
                f.write(f"{self.command} {self.path}\n")

        def do_GET(self):
            self.log()
            code, ctype, body = ROUTES.get(self.path, (404, "text/plain", "not found"))
            b = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Server", "mock-target")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def mutate(self):
            self.log()
            open(base + ".MUTATION", "a").write(f"{self.command} {self.path}\n")
            self.send_response(405)
            self.end_headers()

        do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = mutate
    return H


def closer(sock):
    while True:
        c, _ = sock.accept()
        c.close()


def closed_sockets(below, n=2, attempts=500):
    """n listening sockets on ports below `below`, in increasing order: the order of the open ports nmap reports, and so
    of the findings, is then the same on every run (closed1 < closed2 < the HTTP service)."""
    kept, spare = [], []
    for _ in range(attempts):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        (kept if s.getsockname()[1] < below else spare).append(s)
        if len(kept) == n:
            break
    for s in spare:
        s.close()
    if len(kept) < n:
        for s in kept:
            s.close()
        return None
    return sorted(kept, key=lambda s: s.getsockname()[1])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port-file", required=True)
    a = ap.parse_args()
    base = a.port_file[:-len(".port")] if a.port_file.endswith(".port") else a.port_file
    while True:
        srv = ThreadingHTTPServer(("127.0.0.1", 0), handler(base))
        socks = closed_sockets(srv.server_address[1])
        if socks:
            break
        srv.server_close()
    for extra, s in zip(("closed1", "closed2"), socks):
        s.listen(16)
        threading.Thread(target=closer, args=(s,), daemon=True).start()
        with open(f"{base}.{extra}", "w") as f:
            f.write(str(s.getsockname()[1]))
    with open(a.port_file + ".tmp", "w") as f:
        f.write(str(srv.server_address[1]))
    os.replace(a.port_file + ".tmp", a.port_file)
    srv.serve_forever()


if __name__ == "__main__":
    main()
