#!/usr/bin/env python3
"""A fake of the three Google endpoints the cloud collector's GCP flow calls (STS token exchange, IAM credentials
generateAccessToken, Resource Manager getIamPolicy). Test tool, stdlib only. Writes its port to --port-file.
Projects whose id contains "cond" return the service account's grants as time-bound (conditional) bindings, exactly as
Google does: the real role with a `condition` at policy version 3, a synthetic "<role>_withcond_<hash>" role otherwise.
Projects whose id contains "over" also grant roles/editor."""
import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SA = "serviceAccount:a@p.iam.gserviceaccount.com"
ACCESS = "ya29.conformance-access-token"


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

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
        if self.path == "/sts":
            return self.reply(200, {"access_token": "federated-conformance-token", "expires_in": 3600})
        if self.path.endswith(":generateAccessToken"):
            return self.reply(200, {"accessToken": ACCESS, "expireTime": "2999-01-01T00:00:00Z"})
        if self.path.endswith(":getIamPolicy"):
            if self.headers.get("Authorization") != "Bearer " + ACCESS:
                return self.reply(401, {"error": {"code": 401, "status": "UNAUTHENTICATED", "message": "bad token"}})
            roles = ["roles/viewer", "roles/iam.securityReviewer"] + (["roles/editor"] if "over" in self.path else [])
            bindings = [{"role": r, "members": [SA]} for r in roles] + [{"role": "roles/owner", "members": ["user:x"]}]
            if "cond" in self.path:
                v3 = (json.loads(body or "{}").get("options") or {}).get("requestedPolicyVersion") == 3
                cond = {"title": "expires", "expression": 'request.time < timestamp("2999-01-01T00:00:00Z")'}
                bindings = [dict(b, condition=cond) if v3 else dict(b, role=b["role"] + "_withcond_0123abcd")
                            for b in bindings if b["role"] != "roles/viewer"] + [b for b in bindings if b["role"] == "roles/viewer"]
            return self.reply(200, {"bindings": bindings})
        self.reply(404, {})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port-file", required=True)
    a = ap.parse_args()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    with open(a.port_file + ".tmp", "w") as f:
        f.write(str(srv.server_address[1]))
    import os
    os.replace(a.port_file + ".tmp", a.port_file)
    srv.serve_forever()


if __name__ == "__main__":
    main()
