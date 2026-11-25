#!/usr/bin/env python3
"""A fake notification receiver (incoming webhook, chat bot API) for the cli conformance cases. Test tool, stdlib only.
Records every request as one JSON line {"method", "path", "content_type", "user_agent", "body"} in --record and answers
200, or 500 when the path contains "fail". Writes its port to --port-file."""
import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def handler(record):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode("utf-8", "replace")
            with open(record, "a") as f:
                f.write(json.dumps({"method": "POST", "path": self.path, "content_type": self.headers.get("Content-Type"),
                                    "user_agent": self.headers.get("User-Agent"), "body": body}) + "\n")
            code = 500 if "fail" in self.path else 200
            b = b'{"ok": true}' if code == 200 else b'{"ok": false}'
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
    return H


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--record", required=True)
    ap.add_argument("--port-file", required=True)
    a = ap.parse_args()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler(a.record))
    with open(a.port_file + ".tmp", "w") as f:
        f.write(str(srv.server_address[1]))
    import os
    os.replace(a.port_file + ".tmp", a.port_file)
    srv.serve_forever()


if __name__ == "__main__":
    main()
