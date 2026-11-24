#!/usr/bin/env python3
"""A LOCAL MOCK of the GCP and Azure token/authorisation endpoints the cloud adapter talks to (stdlib only).

It validates the platform's FLOW, not the real clouds' behaviour: the token exchange and impersonation calls are shaped
like Google's (sts.googleapis.com/v1/token, iamcredentials generateAccessToken, cloudresourcemanager getIamPolicy) and
Microsoft's (Entra /{tenant}/oauth2/v2.0/token with a client assertion, ARM roleAssignments), and they enforce what the
real services enforce for these flows: the OIDC token's RS256 signature (against the issuer's JWKS), issuer, expiry
and audience; which federated subject may impersonate which service account / use which app registration; and the
role bindings / assignments a scenario declares. Error bodies follow the services' formats.

usage: cloudmock.py --port 18090 --config scenario.json
"""
import argparse
import base64
import hashlib
import json
import secrets
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CFG, JWKS, TOKENS = {}, {}, {}           # TOKENS: opaque token -> {"kind", "sub", "sa"/"oid", "exp"}
SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


def b64(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jwks(issuer):
    if issuer not in JWKS:
        with urllib.request.urlopen(issuer.rstrip("/") + "/jwks", timeout=10) as r:
            JWKS[issuer] = {k["kid"]: k for k in json.load(r)["keys"]}
    return JWKS[issuer]


def verify_jwt(tok, issuers):
    """-> claims, or raise ValueError(reason). RS256 PKCS#1 v1.5 verification with Python integers."""
    try:
        h, p, s = tok.split(".")
        head, claims = json.loads(b64(h)), json.loads(b64(p))
    except ValueError:
        raise ValueError("malformed token")
    if claims.get("iss") not in issuers:
        raise ValueError(f"issuer {claims.get('iss')} is not trusted")
    key = jwks(claims["iss"]).get(head.get("kid"))
    if head.get("alg") != "RS256" or not key:
        raise ValueError("unsupported key or algorithm")
    n, e = int.from_bytes(b64(key["n"]), "big"), int.from_bytes(b64(key["e"]), "big")
    k = (n.bit_length() + 7) // 8
    em = pow(int.from_bytes(b64(s), "big"), e, n).to_bytes(k, "big")
    digest = SHA256_DIGEST_INFO + hashlib.sha256(f"{h}.{p}".encode()).digest()
    if em != b"\x00\x01" + b"\xff" * (k - len(digest) - 3) + b"\x00" + digest:
        raise ValueError("invalid signature")
    if float(claims.get("exp", 0)) <= time.time():
        raise ValueError("token expired")
    return claims


def aud_list(c):
    a = c.get("aud")
    return a if isinstance(a, list) else [a]


def unsigned_jwt(claims):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()  # noqa: E731
    return f"{enc({'alg': 'none', 'typ': 'JWT'})}.{enc(claims)}.mock"


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

    def body(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if "json" in (self.headers.get("Content-Type") or ""):
            return json.loads(raw or b"{}")
        return dict(urllib.parse.parse_qsl(raw.decode()))

    def bearer(self, kind):
        tok = (self.headers.get("Authorization") or "").removeprefix("Bearer ")
        t = TOKENS.get(tok)
        if not t or t["kind"] != kind or t["exp"] <= time.time():
            return None
        return t

    def gerr(self, code, status, msg):
        self.reply(code, {"error": {"code": code, "status": status, "message": msg}})

    # ---- GCP -------------------------------------------------------------------------------------------------
    def gcp_sts(self):
        g, f = CFG["gcp"], self.body()
        prov = g["providers"].get(f.get("audience", ""))
        if not prov:
            return self.reply(400, {"error": "invalid_target", "error_description": "The target service indicated by the "
                                    "\"audience\" parameters is invalid."})
        try:
            c = verify_jwt(f.get("subject_token", ""), [prov["issuer"]])
        except ValueError as e:
            return self.reply(400, {"error": "invalid_grant", "error_description": f"ID Token issued by the provider is invalid: {e}"})
        if not set(aud_list(c)) & set(prov["allowed_audiences"]):
            return self.reply(400, {"error": "invalid_grant", "error_description":
                                    f"The audience in ID Token {aud_list(c)} does not match the expected audience."})
        tok = "fed." + secrets.token_urlsafe(24)
        TOKENS[tok] = {"kind": "gcp-fed", "sub": c["sub"], "exp": time.time() + 3600}
        self.reply(200, {"access_token": tok, "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                         "token_type": "Bearer", "expires_in": 3600})

    def gcp_generate(self, sa):
        t = self.bearer("gcp-fed")
        if not t:
            return self.gerr(401, "UNAUTHENTICATED", "Request had invalid authentication credentials.")
        accounts = CFG["gcp"]["service_accounts"]
        if sa not in accounts:
            return self.gerr(404, "NOT_FOUND", f"Service account projects/-/serviceAccounts/{sa} does not exist.")
        if t["sub"] not in accounts[sa]["subjects"]:
            return self.gerr(403, "PERMISSION_DENIED", "Permission 'iam.serviceAccounts.getAccessToken' denied on resource "
                             "(or it may not exist).")
        life = int(str(self.body().get("lifetime", "3600s")).rstrip("s"))
        tok = "ya29.mock-" + secrets.token_urlsafe(24)
        TOKENS[tok] = {"kind": "gcp", "sa": sa, "exp": time.time() + life}
        self.reply(200, {"accessToken": tok, "expireTime": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + life))})

    def gcp_policy(self, project):
        t = self.bearer("gcp")
        if not t:
            return self.gerr(401, "UNAUTHENTICATED", "Request had invalid authentication credentials.")
        p = CFG["gcp"]["projects"].get(project)
        if not p or not any(f"serviceAccount:{t['sa']}" in b["members"] for b in p["bindings"]):
            return self.gerr(403, "PERMISSION_DENIED", f"The caller does not have permission on project {project}")
        self.reply(200, {"version": 1, "etag": "BwX=", "bindings": p["bindings"]})

    # ---- Azure -----------------------------------------------------------------------------------------------
    def azure_token(self, tenant):
        f = self.body()
        app = CFG["azure"]["tenants"].get(tenant, {}).get(f.get("client_id", ""))
        if not app:
            return self.reply(400, {"error": "unauthorized_client", "error_description":
                                    f"AADSTS700016: Application with identifier '{f.get('client_id')}' was not found in the directory."})
        try:
            c = verify_jwt(f.get("client_assertion", ""), [app["issuer"]])
        except ValueError as e:
            code = "AADSTS700024" if "expired" in str(e) else "AADSTS700211"
            return self.reply(400, {"error": "invalid_client", "error_description": f"{code}: Client assertion is invalid: {e}"})
        if app["audience"] not in aud_list(c):
            return self.reply(400, {"error": "invalid_client", "error_description":
                                    "AADSTS700212: No matching federated identity record found for presented assertion audience."})
        if c.get("sub") != app["subject"]:
            return self.reply(400, {"error": "invalid_client", "error_description":
                                    "AADSTS70021: No matching federated identity record found for presented assertion."})
        exp = time.time() + 3600
        tok = unsigned_jwt({"oid": app["oid"], "tid": tenant, "aud": "https://management.azure.com", "exp": int(exp)})
        TOKENS[tok] = {"kind": "azure", "oid": app["oid"], "exp": exp}
        self.reply(200, {"token_type": "Bearer", "expires_in": 3600, "access_token": tok})

    def azure_assignments(self, sub):
        t = self.bearer("azure")
        if not t:
            return self.reply(401, {"error": {"code": "InvalidAuthenticationToken", "message": "The access token is invalid."}})
        s = CFG["azure"]["subscriptions"].get(sub, {})
        roles = s.get("assignments", {}).get(t["oid"])
        if roles is None:
            return self.reply(403, {"error": {"code": "AuthorizationFailed", "message": "The client does not have "
                                              "authorization to perform action 'Microsoft.Authorization/roleAssignments/read'."}})
        self.reply(200, {"value": [{"id": f"/subscriptions/{sub}/providers/Microsoft.Authorization/roleAssignments/{i}",
                                    "properties": {"principalId": t["oid"], "scope": f"/subscriptions/{sub}",
                                                   "roleDefinitionId": f"/subscriptions/{sub}/providers/Microsoft.Authorization/roleDefinitions/{r}"}}
                                   for i, r in enumerate(roles)]})

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/gcp/sts/v1/token":
            return self.gcp_sts()
        if path.startswith("/gcp/iamcredentials/v1/projects/-/serviceAccounts/") and path.endswith(":generateAccessToken"):
            return self.gcp_generate(urllib.parse.unquote(path.split("/serviceAccounts/")[1].rsplit(":", 1)[0]))
        if path.startswith("/gcp/crm/v1/projects/") and path.endswith(":getIamPolicy"):
            return self.gcp_policy(path.split("/projects/")[1].rsplit(":", 1)[0])
        if path.startswith("/azure/login/") and path.endswith("/oauth2/v2.0/token"):
            return self.azure_token(path.split("/")[3])
        self.reply(404, {"error": "not found"})

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path.startswith("/azure/arm/subscriptions/") and path.endswith("/providers/Microsoft.Authorization/roleAssignments"):
            return self.azure_assignments(path.split("/")[4])
        if path == "/health":
            return self.reply(200, {"ok": True})
        self.reply(404, {"error": "not found"})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=18090)
    ap.add_argument("--config", required=True)
    a = ap.parse_args()
    CFG.update(json.load(open(a.config)))
    ThreadingHTTPServer(("127.0.0.1", a.port), H).serve_forever()


if __name__ == "__main__":
    main()
