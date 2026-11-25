"""Cloud posture: the credential adapter (short-lived only, refresh, self-verification, failure modes), the engines'
and native imports' output contracts (Prowler OCSF for AWS/GCP/Azure, ScoutSuite, Security Hub ASFF, SCC, Defender),
classification into pillars and generic controls, de-duplication across sources, the ledger lifecycle and the
scorecard's cloud dimension (not applicable without cloud accounts). Fakes only: no network, no real account."""
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import unittest.mock
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path[:0] = [ROOT, os.path.join(ROOT, "sdk"), os.path.join(ROOT, "collectors", "cloud"), os.path.join(ROOT, "scorecard")]
import importlib.util  # noqa: E402

from adapters import cloud  # noqa: E402
import controls  # noqa: E402
import engines  # noqa: E402

_spec = importlib.util.spec_from_file_location("cloud_collector", os.path.join(ROOT, "collectors", "cloud", "collector.py"))
collector = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(collector)
FX = os.path.join(ROOT, "tests", "fixtures", "cloud")
FAKE_SECRET = "fake-secret-" + "s" * 20
FAKE_SESSION = "fake-session-" + "t" * 40


def jwt(**claims):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()  # noqa: E731
    return f"{enc({'alg': 'RS256', 'kid': 'k'})}.{enc(claims)}.c2ln"


def fx(name):
    return json.load(open(os.path.join(FX, name)))


# ---- a fake STS + IAM (AWS Query API) ----------------------------------------------------------------------------
class FakeAWS(BaseHTTPRequestHandler):
    state = {}

    def log_message(self, *a):
        pass

    def xml(self, code, body):
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/xml")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def err(self, code, c, msg):
        self.xml(code, f"<ErrorResponse><Error><Code>{c}</Code><Message>{msg}</Message></Error></ErrorResponse>")

    def creds(self):
        exp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 3600))
        return (f"<Credentials><AccessKeyId>ASIAFAKE{len(self.state['calls']):08d}</AccessKeyId><SecretAccessKey>{FAKE_SECRET}"
                f"</SecretAccessKey><SessionToken>{FAKE_SESSION}</SessionToken><Expiration>{exp}</Expiration></Credentials>")

    def do_POST(self):
        st = self.state
        f = dict(urllib.parse.parse_qsl(self.rfile.read(int(self.headers["Content-Length"])).decode()))
        act = f["Action"]
        st["calls"].append((act, "Authorization" in self.headers))
        if act == "AssumeRoleWithWebIdentity":
            if st.get("deny"):
                return self.err(403, "AccessDenied", "Not authorized to perform sts:AssumeRoleWithWebIdentity")
            if st.get("expired"):
                return self.err(400, "ExpiredTokenException", "Token expired: current date/time must be before expiration")
            st["role"] = f["RoleArn"].split("/")[-1]
            return self.xml(200, f"<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult>{self.creds()}"
                                 "</AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>")
        if "Authorization" not in self.headers or FAKE_SECRET in self.headers["Authorization"]:
            return self.err(403, "IncompleteSignature", "missing or bad signature")
        if act == "AssumeRole":
            st["role"] = f["RoleArn"].split("/")[-1]
            return self.xml(200, f"<AssumeRoleResponse><AssumeRoleResult>{self.creds()}</AssumeRoleResult></AssumeRoleResponse>")
        if act == "GetCallerIdentity":
            return self.xml(200, f"<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:sts::111122223333:"
                                 f"assumed-role/{st['role']}/security-platform</Arn><Account>111122223333</Account>"
                                 "</GetCallerIdentityResult></GetCallerIdentityResponse>")
        if act == "GetRole":
            if st.get("missing_role"):
                return self.err(404, "NoSuchEntity", f"The role with name {f['RoleName']} cannot be found.")
            return self.xml(200, "<GetRoleResponse><GetRoleResult><Role/></GetRoleResult></GetRoleResponse>")
        if act == "ListAttachedRolePolicies":
            m = "".join(f"<member><PolicyArn>{p}</PolicyArn></member>" for p in st["attached"])
            return self.xml(200, f"<R><ListAttachedRolePoliciesResult><AttachedPolicies>{m}</AttachedPolicies></ListAttachedRolePoliciesResult></R>")
        if act == "GetPolicy":
            return self.xml(200, "<R><GetPolicyResult><Policy><DefaultVersionId>v1</DefaultVersionId></Policy></GetPolicyResult></R>")
        if act == "GetPolicyVersion":
            doc = urllib.parse.quote(json.dumps(st["docs"][f["PolicyArn"]]))
            return self.xml(200, f"<R><GetPolicyVersionResult><PolicyVersion><Document>{doc}</Document></PolicyVersion></GetPolicyVersionResult></R>")
        if act == "ListRolePolicies":
            return self.xml(200, "<R><ListRolePoliciesResult><PolicyNames>" + "".join(
                f"<member>{n}</member>" for n in st.get("inline", {})) + "</PolicyNames></ListRolePoliciesResult></R>")
        if act == "GetRolePolicy":
            doc = urllib.parse.quote(json.dumps(st["inline"][f["PolicyName"]]))
            return self.xml(200, f"<R><GetRolePolicyResult><PolicyDocument>{doc}</PolicyDocument></GetRolePolicyResult></R>")
        self.err(400, "InvalidAction", act)


class FakeAWSServer:
    def __enter__(self):
        FakeAWS.state = {"calls": [], "attached": ["arn:aws:iam::aws:policy/SecurityAudit",
                                                   "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"], "docs": {}}
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeAWS)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        return self

    def __exit__(self, *a):
        self.srv.shutdown()


def aws_cfg(url, tokfile, **kw):
    return dict(dict(provider="aws", account_id="111122223333", role_arn="arn:aws:iam::111122223333:role/audit",
                     audience="sts.amazonaws.com", endpoint_url=url, regions=["eu-west-1"],
                     identity_token={"type": "file", "path": tokfile}), **kw)


class Adapter(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.tok = os.path.join(self.d, "token")
        open(self.tok, "w").write(jwt(sub="scanner", aud="sts.amazonaws.com", exp=int(time.time()) + 7200))

    def tearDown(self):
        shutil.rmtree(self.d)

    def test_sigv4_matches_the_aws_documentation_example(self):
        h = cloud.sigv4("GET", "https://example.amazonaws.com/", "us-east-1", "service", None,
                        {"AccessKeyId": "AKIDEXAMPLE", "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"},
                        now=1440938160)   # 20150830T123600Z, test suite case get-vanilla
        self.assertTrue(h["Authorization"].endswith(
            "Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"), h["Authorization"])

    def test_long_lived_keys_refused(self):
        for k in ("access_key_id", "secret_access_key", "client_secret", "private_key"):
            with self.subTest(k=k), self.assertRaisesRegex(cloud.CloudAuthError, "long-lived"):
                cloud.provider(dict(provider="aws", account_id="1", **{k: "x"}))

    def test_token_prechecks(self):
        with self.assertRaisesRegex(cloud.CloudAuthError, "expired"):
            cloud.precheck_token(jwt(aud="a", exp=int(time.time()) - 5), "a")
        with self.assertRaisesRegex(cloud.CloudAuthError, "audience mismatch"):
            cloud.precheck_token(jwt(aud="wrong", exp=int(time.time()) + 600), "sts.amazonaws.com")
        self.assertEqual(cloud.precheck_token(jwt(aud=["x", "a"], exp=int(time.time()) + 600), "a")["aud"], ["x", "a"])
        with self.assertRaisesRegex(cloud.CloudAuthError, "not a JWT"):
            cloud.precheck_token("opaque", None)

    def test_web_identity_chain_selfcheck_and_refresh(self):
        with FakeAWSServer() as s:
            now = [time.time()]
            p = cloud.provider(aws_cfg(s.url, self.tok, chain_role_arn="arn:aws:iam::111122223333:role/target",
                                       external_id="ext-1"), clock=lambda: now[0])
            c1 = p.credentials()
            self.assertEqual([a for a, _ in FakeAWS.state["calls"]], ["AssumeRoleWithWebIdentity", "AssumeRole"])
            self.assertFalse(FakeAWS.state["calls"][0][1], "web identity call is unsigned")
            self.assertTrue(FakeAWS.state["calls"][1][1], "chained AssumeRole is SigV4-signed")
            self.assertIs(p.credentials(), c1, "cached in memory")
            now[0] = c1["expires"] - cloud.REFRESH_MARGIN + 1     # inside the refresh margin -> renewed before expiry
            self.assertIsNot(p.credentials(), c1)
            self.assertEqual(p.refreshes, 2)
            perm = p.permissions()
            self.assertEqual(perm["write_capable"], [])
            self.assertEqual(perm["grants"], FakeAWS.state["attached"])

    def test_write_capable_policies_detected(self):
        self.assertEqual(cloud.write_actions({"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject", "ec2:Describe*"]}]}), [])
        self.assertEqual(cloud.write_actions({"Statement": {"Effect": "Allow", "Action": "*"}}), ["*"])
        self.assertEqual(cloud.write_actions({"Statement": [{"Effect": "Allow", "Action": ["s3:PutObject", "iam:*"]},
                                                            {"Effect": "Deny", "Action": "ec2:TerminateInstances"}]}),
                         ["iam:*", "s3:PutObject"])
        with FakeAWSServer() as s:
            FakeAWS.state["attached"].append("arn:aws:iam::aws:policy/AdministratorAccess")
            FakeAWS.state["docs"]["arn:aws:iam::aws:policy/AdministratorAccess"] = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
            FakeAWS.state["inline"] = {"ok": {"Statement": [{"Effect": "Allow", "Action": "s3:List*"}]},
                                       "bad": {"Statement": [{"Effect": "Allow", "Action": "s3:DeleteBucket"}]}}
            perm = cloud.provider(aws_cfg(s.url, self.tok)).permissions()
            self.assertEqual(perm["write_capable"], ["arn:aws:iam::aws:policy/AdministratorAccess", "inline:bad"])

    def test_failure_modes_are_reasons(self):
        cases = {"deny": "AccessDenied", "expired": "ExpiredToken", "missing_role": "does not exist"}
        for flag, want in cases.items():
            with self.subTest(flag=flag), FakeAWSServer() as s:
                FakeAWS.state[flag] = True
                with self.assertRaisesRegex(cloud.CloudAuthError, want):
                    cloud.provider(aws_cfg(s.url, self.tok)).permissions()
        with self.assertRaisesRegex(cloud.CloudAuthError, "unreachable"):
            cloud.provider(aws_cfg("http://127.0.0.1:9", self.tok)).credentials()
        with self.assertRaisesRegex(cloud.CloudAuthError, "identity token unavailable"):
            cloud.provider(aws_cfg("http://127.0.0.1:9", os.path.join(self.d, "missing"))).credentials()

    def test_engine_env_holds_no_secret_and_strips_ambient_keys(self):
        with FakeAWSServer() as s:
            p = cloud.provider(aws_cfg(s.url, self.tok))
            tmp = os.path.join(self.d, "run")
            os.mkdir(tmp, 0o700)
            env, args = p.engine_env(tmp)
            self.assertEqual(args, {"profile": "security-platform", "regions": ["eu-west-1"]})
            files = [os.path.join(tmp, f) for f in os.listdir(tmp)]
            for f in files:
                self.assertNotIn(FAKE_SECRET, open(f).read())
                self.assertEqual(os.stat(f).st_mode & 0o077, 0, f)
            self.assertNotIn("AWS_ACCESS_KEY_ID", env)
            base = cloud.clean_env({"AWS_ACCESS_KEY_ID": "x", "AWS_SECRET_ACCESS_KEY": "y", "AZURE_CLIENT_SECRET": "z",
                                    "GOOGLE_APPLICATION_CREDENTIALS": "k.json", "PATH": "/bin"})
            self.assertEqual(base, {"PATH": "/bin"})
            # the credential_process callback: temporary credentials on stdout, never on disk
            cmd = open(env["AWS_CONFIG_FILE"]).read().split("credential_process = ", 1)[1].splitlines()[0]
            out = json.loads(subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True).stdout)
            self.assertEqual(out["Version"], 1)
            self.assertEqual(out["SessionToken"], FAKE_SESSION)
            self.assertTrue(out["Expiration"].endswith("Z"))
            for f in os.listdir(tmp):
                self.assertNotIn(FAKE_SESSION, open(os.path.join(tmp, f)).read())

    def test_gcp_and_azure_env_are_keyless(self):
        g = cloud.provider(dict(provider="gcp", project_id="p-1", workload_identity_provider="projects/1/locations/global/"
                                "workloadIdentityPools/x/providers/y", service_account="a@p-1.iam.gserviceaccount.com",
                                identity_token={"type": "file", "path": self.tok}))
        env, args = g.engine_env(self.d)
        conf = json.load(open(env["GOOGLE_APPLICATION_CREDENTIALS"]))
        self.assertEqual(conf["type"], "external_account")
        self.assertEqual(conf["audience"], "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/x/providers/y")
        self.assertTrue(conf["service_account_impersonation_url"].endswith("a@p-1.iam.gserviceaccount.com:generateAccessToken"))
        self.assertEqual(conf["credential_source"], {"file": self.tok})
        a = cloud.provider(dict(provider="azure", subscription_id="s-1", tenant_id="t", client_id="c",
                                identity_token={"type": "file", "path": self.tok}))
        env, args = a.engine_env(self.d)
        self.assertEqual(env["AZURE_FEDERATED_TOKEN_FILE"], self.tok)
        self.assertNotIn("AZURE_CLIENT_SECRET", env)
        self.assertEqual(args, {"subscriptions": ["s-1"]})


# ---- GCP / Azure token flows against fakes -------------------------------------------------------------------------
ADC_REFRESH = "adc-refresh-" + "r" * 30          # fake values: the tests assert they never leave the adapter
ADC_USER_TOKEN = "ya29.user-" + "u" * 30


class FakeIdP(BaseHTTPRequestHandler):
    calls, minted = [], 0
    instances = []           # (name, zone, state, internal, external) served by the asset and compute fakes

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
            f = dict(urllib.parse.parse_qsl(body))
            aud = json.loads(base64.urlsafe_b64decode(f["subject_token"].split(".")[1] + "==")).get("aud")
            if aud != "gcp-aud":
                return self.reply(400, {"error": "invalid_grant", "error_description": "audience does not match"})
            return self.reply(200, {"access_token": "fed", "expires_in": 3600})
        if self.path == "/oauth2":          # ADC: authorized_user refresh token -> user access token
            f = dict(urllib.parse.parse_qsl(body))
            FakeIdP.calls.append(("oauth2", f.get("grant_type")))
            if f.get("grant_type") != "refresh_token" or f.get("client_id") != "adc-client" or f.get("client_secret") != "adc-client":
                return self.reply(401, {"error": "invalid_client", "error_description": "The OAuth client was not found."})
            if f.get("refresh_token") != ADC_REFRESH:
                return self.reply(400, {"error": "invalid_grant", "error_description": "Token has been expired or revoked."})
            return self.reply(200, {"access_token": ADC_USER_TOKEN, "expires_in": 3599, "token_type": "Bearer"})
        if ":generateAccessToken" in self.path:
            FakeIdP.calls.append(("generate", self.headers.get("Authorization", "").removeprefix("Bearer ")))
            if "denied" in self.path:
                return self.reply(403, {"error": {"code": 403, "status": "PERMISSION_DENIED", "message": "denied"}})
            if "nobody" in self.path:
                return self.reply(404, {"error": {"code": 404, "status": "NOT_FOUND", "message": "Service account does not exist."}})
            FakeIdP.minted += 1
            return self.reply(200, {"accessToken": f"ya29.x{FakeIdP.minted}", "expireTime": "2999-01-01T00:00:00Z"})
        if self.path.endswith(":getIamPolicy"):
            FakeIdP.calls.append(("getIamPolicy", self.headers.get("Authorization", "").removeprefix("Bearer ")))
            sa = "serviceAccount:a@p.iam.gserviceaccount.com"
            roles = ["roles/viewer", "roles/iam.securityReviewer"] + (["roles/editor"] if "over" in self.path else [])
            bindings = [{"role": r, "members": [sa]} for r in roles] + [{"role": "roles/owner", "members": ["user:x"]}]
            if "cond" in self.path:     # time-bound grants, as Google returns them: real role only at policy version 3
                v3 = (json.loads(body or "{}").get("options") or {}).get("requestedPolicyVersion") == 3
                cond = {"title": "expires", "expression": 'request.time < timestamp("2999-01-01T00:00:00Z")'}
                bindings = [dict(b, condition=cond) if v3 else dict(b, role=b["role"] + "_withcond_0123abcd")
                            for b in bindings if b["role"] != "roles/viewer"] + [b for b in bindings if b["role"] == "roles/viewer"]
            return self.reply(200, {"bindings": bindings})
        if self.path.endswith("/oauth2/v2.0/token"):
            f = dict(urllib.parse.parse_qsl(body))
            if f["client_id"] != "app":
                return self.reply(400, {"error": "unauthorized_client", "error_description": "AADSTS700016: Application not found"})
            return self.reply(200, {"access_token": jwt(oid="obj-1", exp=int(time.time()) + 3600), "expires_in": 3600})
        self.reply(404, {})

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = dict(urllib.parse.parse_qsl(u.query))
        if u.path.startswith(("/asset/", "/compute/")):
            FakeIdP.calls.append(("list", self.headers.get("Authorization", "").removeprefix("Bearer "), u.path, q))
            if "/projects/forbidden" in u.path:
                return self.reply(403, {"error": {"code": 403, "status": "PERMISSION_DENIED", "message": "caller lacks permission"}})
            page = int(q.get("pageToken", "0"))
            rows = FakeIdP.instances[page * 2:page * 2 + 2]       # two per page: exercises pagination
            nxt = {"nextPageToken": str(page + 1)} if len(FakeIdP.instances) > page * 2 + 2 else {}
            if u.path.startswith("/asset/"):
                assert q.get("assetTypes") == "compute.googleapis.com/Instance", q
                return self.reply(200, dict(nxt, results=[{
                    "name": f"//compute.googleapis.com/projects/p/zones/{z}/instances/{n}", "displayName": n,
                    "assetType": "compute.googleapis.com/Instance", "location": z, "state": st,
                    "additionalAttributes": {"internalIPs": i, "externalIPs": e}} for n, z, st, i, e in rows]))
            items = {}
            for n, z, st, i, e in rows:
                items.setdefault(f"zones/{z}", {"instances": []})["instances"].append({
                    "name": n, "status": st, "networkInterfaces": [
                        {"networkIP": ip, "accessConfigs": [{"natIP": x} for x in e] if k == 0 else []} for k, ip in enumerate(i)]})
            items["zones/empty-zone"] = {"warning": {"code": "NO_RESULTS_ON_PAGE"}}
            return self.reply(200, dict(nxt, items=items))
        sub = self.path.split("/")[3]
        roles = ["acdd72a7-3385-48ef-bd42-f606fba81ae7", "39bc4728-0917-49c7-9d2c-d95423bc2eb4"]
        if sub == "over":
            roles.append("8e3af657-a8ff-443c-a75c-2fe8c4bcb635")
        self.reply(200, {"value": [{"properties": {"roleDefinitionId": f"/x/roleDefinitions/{r}"}} for r in roles]})


class GcpAzure(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeIdP)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.srv.server_address[1]}"
        cls.d = tempfile.mkdtemp()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        shutil.rmtree(cls.d)

    def gcp(self, project="p", sa="a@p.iam.gserviceaccount.com", aud="gcp-aud"):
        t = os.path.join(self.d, f"t-{aud}")
        open(t, "w").write(jwt(sub="scanner", aud=aud, exp=int(time.time()) + 600))
        return cloud.provider(dict(provider="gcp", project_id=project, workload_identity_provider="projects/1/x", service_account=sa,
                                   identity_token={"type": "file", "path": t}, sts_url=self.url + "/sts",
                                   iamcredentials_url=self.url + "/iam", resourcemanager_url=self.url + "/crm"))

    def test_gcp_flow(self):
        p = self.gcp()
        self.assertEqual(p.permissions()["write_capable"], [])
        self.assertEqual(self.gcp(project="over").permissions()["write_capable"], ["roles/editor"])
        # a time-bound (conditional) grant: judged by its real role, read at IAM policy version 3
        p = self.gcp(project="cond").permissions()
        self.assertEqual((p["write_capable"], p["conditional"]), ([], ["roles/iam.securityReviewer"]))
        self.assertEqual(self.gcp(project="cond-over").permissions()["write_capable"], ["roles/editor"])
        with self.assertRaisesRegex(cloud.CloudAuthError, "audience does not match"):
            self.gcp(aud="wrong").credentials()
        with self.assertRaisesRegex(cloud.CloudAuthError, "PERMISSION_DENIED"):
            self.gcp(sa="denied@p.iam.gserviceaccount.com").credentials()

    def test_azure_flow(self):
        t = os.path.join(self.d, "az")
        open(t, "w").write(jwt(sub="scanner", aud="api://AzureADTokenExchange", exp=int(time.time()) + 600))
        base = dict(provider="azure", tenant_id="t", client_id="app", identity_token={"type": "file", "path": t},
                    authority_host=self.url + "/login", arm_url=self.url + "/arm")
        p = cloud.provider(dict(base, subscription_id="ro"))
        self.assertEqual(p.permissions(), {"principal": "obj-1", "method": "subscription role assignments",
                                           "grants": ["Reader", "Security Reader"], "write_capable": []})
        self.assertEqual(cloud.provider(dict(base, subscription_id="over")).permissions()["write_capable"], ["Owner"])
        with self.assertRaisesRegex(cloud.CloudAuthError, "AADSTS700016"):
            cloud.provider(dict(base, subscription_id="ro", client_id="other")).credentials()


# ---- GCP with the operator's Application Default Credentials (source: adc) + discovery gcp ------------------------
FAKE_PROWLER_GCP = r'''#!/usr/bin/env python3
import json, os, sys
a = sys.argv[1:]
out = a[a.index("-o") + 1]
os.makedirs(out, exist_ok=True)
cfgdir = os.environ.get("CLOUDSDK_CONFIG", "")
json.dump({"argv": a, "env": {k: v for k, v in os.environ.items() if k.startswith(("GOOGLE_", "CLOUDSDK_"))},
           "gcloud_config_files": os.listdir(cfgdir) if os.path.isdir(cfgdir) else None},
          open(os.environ["FAKE_ENGINE_LOG"], "w"))
json.dump(json.load(open(os.environ["FAKE_PROWLER_FIXTURE"])), open(os.path.join(out, "scan.ocsf.json"), "w"))
'''


class GcpAdc(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeIdP)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.srv.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        self.d = tempfile.mkdtemp()
        FakeIdP.calls, FakeIdP.instances = [], []
        self.adc = self.write_adc("adc.json")

    def tearDown(self):
        shutil.rmtree(self.d)

    def write_adc(self, name, mode=0o600, **kw):
        p = os.path.join(self.d, name)
        d = dict({"type": "authorized_user", "client_id": "adc-client", "client_secret": "adc-client",
                  "refresh_token": ADC_REFRESH, "account": "operator@example.com"}, **kw)
        with open(os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode), "w") as f:
            json.dump(d, f)
        os.chmod(p, mode)
        return p

    def cfg(self, project="p", sa="a@p.iam.gserviceaccount.com", **kw):
        return dict(dict(provider="gcp", project_id=project, source="adc", service_account=sa, adc_file=self.adc,
                         oauth_token_url=self.url + "/oauth2", iamcredentials_url=self.url + "/iam",
                         resourcemanager_url=self.url + "/crm"), **kw)

    def test_adc_impersonates_and_self_checks(self):
        p = cloud.provider(self.cfg())          # no workload_identity_provider / identity_token needed
        self.assertEqual(p.credentials()["access_token"], "ya29.x" + str(FakeIdP.minted))
        self.assertEqual(p.identity(), {"principal": "serviceAccount:a@p.iam.gserviceaccount.com", "account": "p",
                                        "source": "adc"})
        self.assertEqual(p.permissions()["write_capable"], [])
        self.assertEqual(cloud.provider(self.cfg(project="over")).permissions()["write_capable"], ["roles/editor"])
        # the user's token is used for impersonation ONLY; everything else runs as the service account
        self.assertIn(("generate", ADC_USER_TOKEN), FakeIdP.calls)
        self.assertTrue(all(c[1].startswith("ya29.x") for c in FakeIdP.calls if c[0] == "getIamPolicy"))
        # nothing of the ADC is kept in the provider (only the impersonated token is cached)
        kept = json.dumps(vars(p), default=str)
        self.assertNotIn(ADC_REFRESH, kept)
        self.assertNotIn(ADC_USER_TOKEN, kept)
        # the default workload_identity source still needs its keys
        with self.assertRaisesRegex(cloud.CloudAuthError, "workload_identity_provider missing"):
            cloud.provider({k: v for k, v in self.cfg().items() if k != "source"})
        with self.assertRaisesRegex(cloud.CloudAuthError, "source 'keyfile' unknown"):
            cloud.provider(self.cfg(source="keyfile"))

    def test_adc_location(self):
        cfg = {k: v for k, v in self.cfg().items() if k != "adc_file"}
        with unittest.mock.patch.dict(os.environ, {"GOOGLE_APPLICATION_CREDENTIALS": self.adc}):
            self.assertEqual(cloud.adc_path(cfg), (self.adc, "GOOGLE_APPLICATION_CREDENTIALS"))
            self.assertTrue(cloud.provider(cfg).credentials()["access_token"].startswith("ya29.x"))
        gdir = os.path.join(self.d, "gcloud")
        os.mkdir(gdir)
        shutil.copy(self.adc, os.path.join(gdir, "application_default_credentials.json"))
        env = {k: v for k, v in os.environ.items() if k != "GOOGLE_APPLICATION_CREDENTIALS"}
        with unittest.mock.patch.dict(os.environ, dict(env, CLOUDSDK_CONFIG=gdir), clear=True):
            self.assertEqual(cloud.adc_path(cfg)[1], "the gcloud default location")
            self.assertTrue(cloud.provider(cfg).credentials()["access_token"].startswith("ya29.x"))
        with unittest.mock.patch.dict(os.environ, dict(env, HOME=self.d), clear=True):
            self.assertEqual(cloud.adc_path(cfg)[0], os.path.join(self.d, ".config", "gcloud", "application_default_credentials.json"))

    def test_adc_failure_modes_are_reasons(self):
        cases = [
            (dict(adc_file=os.path.join(self.d, "absent.json")), "no application default credentials \\(adc_file\\)"),
            (dict(adc_file=self.write_adc("revoked.json", refresh_token="other")), "invalid_grant.*gcloud auth application-default login"),
            (dict(adc_file=self.write_adc("key.json", type="service_account")), "service-account key file is a long-lived"),
            (dict(adc_file=self.write_adc("ext.json", type="external_account")), "type 'external_account' not supported"),
            (dict(adc_file=self.write_adc("open.json", mode=0o644)), "readable by group/others"),
            (dict(adc_file=self.write_adc("partial.json", refresh_token="")), "incomplete"),
            (dict(sa="denied@p.iam.gserviceaccount.com"), "HTTP 403 PERMISSION_DENIED.*serviceAccountTokenCreator"),
            (dict(sa="nobody@p.iam.gserviceaccount.com"), "HTTP 404 NOT_FOUND.*does not exist"),
            (dict(oauth_token_url="http://127.0.0.1:9/token"), "unreachable"),
        ]
        for kw, want in cases:
            with self.subTest(want=want), self.assertRaisesRegex(cloud.CloudAuthError, want) as cm:
                cloud.provider(self.cfg(**kw)).identity()
            self.assertNotIn(ADC_REFRESH, str(cm.exception))
            self.assertNotIn(self.d, str(cm.exception), "reasons name the ADC source, not its path")
        with self.assertRaisesRegex(cloud.CloudAuthError, "engine_auth 'file' unknown"):
            cloud.provider(self.cfg(engine_auth="file"))

    def test_engine_gets_the_service_account_never_the_adc(self):
        tmp = os.path.join(self.d, "run")
        os.mkdir(tmp, 0o700)
        p = cloud.provider(self.cfg())
        p.credentials()
        env, args = p.engine_env(tmp)
        self.assertEqual(args, {"projects": ["p"], "gcp_source": "adc", "engine_auth": "access_token"})
        self.assertEqual(env["CLOUDSDK_AUTH_ACCESS_TOKEN"], "ya29.x" + str(FakeIdP.minted), "a fresh SA token (full lifetime)")
        self.assertNotIn("GOOGLE_APPLICATION_CREDENTIALS", env)
        self.assertEqual(os.listdir(env["CLOUDSDK_CONFIG"]), [], "gcloud config dir: empty, the operator's ADC invisible")
        self.assertEqual(os.stat(env["CLOUDSDK_CONFIG"]).st_mode & 0o077, 0)
        for root, _, files in os.walk(tmp):
            self.assertEqual(files, [], "nothing written")
        self.assertFalse(any(ADC_REFRESH in v or ADC_USER_TOKEN in v for v in env.values()))
        env, args = cloud.provider(self.cfg(engine_auth="impersonate")).engine_env(tmp)
        self.assertEqual(env["GOOGLE_APPLICATION_CREDENTIALS"], self.adc, "the operator's own file; nothing copied")
        self.assertNotIn("CLOUDSDK_AUTH_ACCESS_TOKEN", env)
        self.assertEqual(args["impersonate_service_account"], "a@p.iam.gserviceaccount.com")
        # ScoutSuite can only use google.auth.default(): it would scan as the operator -> not run (a gap, with a reason)
        run = engines.scoutsuite(p, env, args, {}, tmp)
        self.assertFalse(run.ok)
        self.assertIn("scoutsuite cannot act as the audit service account", run.reason)

    def test_collector_scan_with_adc(self):
        fake = os.path.join(self.d, "prowler")
        open(fake, "w").write(FAKE_PROWLER_GCP)
        os.chmod(fake, 0o755)
        logs = {}
        for mode in ("access_token", "impersonate"):
            acct = self.cfg(project="acme-readonly", sa="a@p.iam.gserviceaccount.com", engine_auth=mode,
                            engines=["prowler", "scoutsuite"])
            inst = os.path.join(self.d, f"inst-{mode}.json")
            json.dump({"cloud": {"accounts": [acct], "engines": {"prowler": {"path": fake}, "scoutsuite": {"path": fake}}}},
                      open(inst, "w"))
            run = os.path.join(self.d, "runs", mode)
            log = logs[mode] = os.path.join(self.d, f"engine-{mode}.json")
            env = dict(os.environ, SP_INSTANCE=inst, SP_RUN_DIR=run, FAKE_ENGINE_LOG=log,
                       FAKE_PROWLER_FIXTURE=os.path.join(FX, "prowler-gcp.ocsf.json"),
                       GOOGLE_APPLICATION_CREDENTIALS="/ambient/admin-key.json", CLOUDSDK_AUTH_ACCESS_TOKEN="ambient-token")
            subprocess.run([sys.executable, os.path.join(ROOT, "collectors", "cloud", "collector.py")], env=env,
                           check=True, capture_output=True)
            doc = json.load(open(os.path.join(run, "cloud.findings.json")))
            cov = {c["asset"]: (c["status"], c.get("reason", "")) for c in doc["coverage"]}
            self.assertEqual(cov["cloud:gcp/acme-readonly"][0], "ok", cov)
            self.assertIn("scoutsuite cannot act as the audit service account", cov["cloud:gcp/acme-readonly/engine:scoutsuite"][1])
            self.assertTrue(any(f["check"] == "cloud.storage_public" for f in doc["findings"]))
            ev = json.load(open(os.path.join(run, "raw", "cloud", "gcp-acme-readonly.json")))
            self.assertEqual(ev["identity"], {"principal": "serviceAccount:a@p.iam.gserviceaccount.com",
                                              "account": "acme-readonly", "source": "adc"})
            for root, _, files in os.walk(run):
                for f in files:
                    text = open(os.path.join(root, f)).read()
                    for secret in (ADC_REFRESH, ADC_USER_TOKEN, "ya29.x", "operator@example.com"):
                        self.assertNotIn(secret, text, f"{f} holds {secret[:10]}")
        e = json.load(open(logs["access_token"]))
        self.assertTrue(e["env"]["CLOUDSDK_AUTH_ACCESS_TOKEN"].startswith("ya29.x"), "the service account's token")
        self.assertNotIn("GOOGLE_APPLICATION_CREDENTIALS", e["env"], "ambient key file stripped, no ADC handed over")
        self.assertEqual(e["gcloud_config_files"], [])
        self.assertNotIn("--impersonate-service-account", e["argv"])
        e = json.load(open(logs["impersonate"]))
        self.assertEqual(e["env"]["GOOGLE_APPLICATION_CREDENTIALS"], self.adc)
        self.assertNotIn("CLOUDSDK_AUTH_ACCESS_TOKEN", e["env"], "ambient access token stripped")
        i = e["argv"].index("--impersonate-service-account")
        self.assertEqual(e["argv"][i + 1], "a@p.iam.gserviceaccount.com")

    def test_discovery_gcp(self):
        from adapters import discovery
        FakeIdP.instances = [("web-1", "europe-west1-b", "RUNNING", ["10.0.0.2"], ["192.0.2.10"]),
                             ("batch-1", "europe-west1-b", "RUNNING", ["10.0.0.3"], []),
                             ("old-1", "europe-west1-c", "TERMINATED", ["10.0.0.4"], []),
                             ("db-1", "europe-west1-c", "RUNNING", ["10.0.0.5", "10.1.0.5"], ["198.51.100.7"])]
        base = dict({k: v for k, v in self.cfg().items() if k != "provider"}, type="gcp",
                    cloudasset_url=self.url + "/asset/v1", compute_url=self.url + "/compute/v1")
        want = [("web-1", "192.0.2.10", True), ("batch-1", None, True), ("db-1", "198.51.100.7", True)]
        for api in ("cloudasset", "compute"):
            with self.subTest(api=api):
                FakeIdP.calls = []
                got = discovery.discover(dict(base, api=api))
                self.assertEqual([(d["name"], d["address"], d["online"]) for d in got], want)
                self.assertEqual(got[0]["attrs"], {"provider": "gcp", "project": "p", "zone": "europe-west1-b",
                                                   "status": "RUNNING", "online_verified": True, "external": True,
                                                   "asset": "cloud:gcp/p/compute/web-1"})
                lists = [c for c in FakeIdP.calls if c[0] == "list"]
                self.assertEqual(len(lists), 2, "followed nextPageToken")
                self.assertTrue(all(c[1].startswith("ya29.x") for c in lists), "listed as the service account")
                self.assertIn("getIamPolicy", [c[0] for c in FakeIdP.calls], "self-check before listing")
        got = discovery.discover(dict(base, address="internal", include_stopped=True))
        self.assertEqual([(d["name"], d["address"], d["online"]) for d in got],
                         [("web-1", "10.0.0.2", True), ("batch-1", "10.0.0.3", True), ("old-1", "10.0.0.4", False),
                          ("db-1", "10.0.0.5", True)])
        got = discovery.discover(dict(base, project_ids=["p", "p2"]))
        self.assertEqual(sorted({d["attrs"]["project"] for d in got}), ["p", "p2"])
        with self.assertRaisesRegex(ValueError, "more than 3 instances"):
            discovery.discover(dict(base, max_hosts=3))
        with self.assertRaisesRegex(cloud.CloudAuthError, "refused: the discovery identity is over-privileged.*roles/editor"):
            discovery.discover(dict(base, project_id="over"))
        with self.assertRaisesRegex(cloud.CloudAuthError, "gcp discovery searchAllResources: HTTP 403 PERMISSION_DENIED"):
            discovery.discover(dict(base, project_ids=["forbidden"]))
        with self.assertRaisesRegex(ValueError, "api 'x' unknown"):
            discovery.discover(dict(base, api="x"))


# ---- engine / import contracts and classification -----------------------------------------------------------------
class Contracts(unittest.TestCase):
    def pool(self, results, provider, account):
        p = collector.Pool()
        for r in results:
            p.add(provider, r.get("account") or account, r)
        return {(f["check"], f["asset"]): f for f in p.items.values()}

    def test_prowler_aws(self):
        rs = engines.parse_prowler_ocsf(fx("prowler-aws.ocsf.json"), "aws")
        self.assertTrue(all(r["status"] in ("FAIL", "PASS") for r in rs))
        got = self.pool(rs, "aws", "000000000000")
        want = {("cloud.firewall_admin_port_open", "cloud:aws/000000000000/ec2/us-east-1/security-group/sg-b56c0e193ea8cb744"): "network",
                ("cloud.storage_public", "cloud:aws/000000000000/s3/global/acme-public-assets"): "software",
                ("cloud.storage_unencrypted", "cloud:aws/000000000000/s3/global/acme-unencrypted-logs"): "software",
                ("cloud.user_without_mfa", "cloud:aws/000000000000/iam/global/user/legacy-deployer"): "people",
                ("cloud.audit_log_disabled", "cloud:aws/000000000000/cloudtrail/us-east-1/trail"): "software"}
        for k, pillar in want.items():
            self.assertIn(k, got)
            self.assertEqual(got[k]["pillar"], pillar)
        self.assertEqual(len(got), len(want), sorted(got))      # PASS verdicts never become findings
        self.assertIn("cis-aws:3.0/1.10", got[("cloud.user_without_mfa", "cloud:aws/000000000000/iam/global/user/legacy-deployer")]["refs"])
        self.assertEqual(got[("cloud.audit_log_disabled", "cloud:aws/000000000000/cloudtrail/us-east-1/trail")]["layer"], "detection")

    def test_prowler_gcp(self):
        got = self.pool(engines.parse_prowler_ocsf(fx("prowler-gcp.ocsf.json")), "gcp", "acme-readonly")
        pill = {k[0]: v["pillar"] for k, v in got.items()}
        self.assertEqual(pill["cloud.firewall_admin_port_open"], "network")
        self.assertEqual(pill["cloud.storage_public"], "software")
        self.assertEqual(pill["cloud.access_key_old"], "people")
        self.assertEqual(pill["cloud.service_account_key_user_managed"], "people")
        self.assertEqual(pill["cloud.audit_log_disabled"], "software")
        self.assertEqual(pill["cloud.gcp.compute_instance_shielded_vm_enabled"], "device")   # unmapped: kept, classified
        self.assertNotIn("cloud.public_endpoint", pill)                                       # PASS
        self.assertIn(("cloud.storage_public", "cloud:gcp/acme-readonly/storage/acme-public-data"), got)
        self.assertIn("cis-gcp:2.0/5.1", got[("cloud.storage_public", "cloud:gcp/acme-readonly/storage/acme-public-data")]["refs"])

    def test_prowler_azure(self):
        sub = "33333333-3333-4333-8333-333333333333"
        got = self.pool(engines.parse_prowler_ocsf(fx("prowler-azure.ocsf.json")), "azure", sub)
        pill = {k[0]: v["pillar"] for k, v in got.items()}
        self.assertEqual(pill["cloud.firewall_admin_port_open"], "network")
        self.assertEqual(pill["cloud.storage_public"], "software")
        self.assertEqual(pill["cloud.user_without_mfa"], "people")
        self.assertEqual(pill["cloud.instance_unpatched"], "device")
        self.assertEqual(pill["cloud.azure.vm_ensure_using_managed_disks"], "device")
        self.assertIn(("cloud.storage_public", f"cloud:azure/{sub}/storage/resourcegroups/rg-web/providers/microsoft.storage/"
                                               "storageaccounts/acmepublicsa"), got)

    def test_every_prowler_mapping_names_a_control(self):
        for table in (controls.PROWLER, controls.SCOUTSUITE, controls.SECURITYHUB, controls.SCC, controls.DEFENDER):
            for k, v in table.items():
                self.assertIn(v, controls.CONTROLS, k)
        for cid, (pillar, layer, *_rest) in controls.CONTROLS.items():
            self.assertIn(pillar, ("network", "device", "people", "software"), cid)
        import steampipe_queries
        for q in steampipe_queries.AWS:
            self.assertIn(q["control"], controls.CONTROLS, q["id"])

    def test_imports(self):
        sh = engines.securityhub(fx("securityhub-asff.json"))
        self.assertEqual({(r["check"], r["status"]) for r in sh}, {("EC2.13", "FAIL"), ("S3.2", "FAIL"), ("IAM.6", "PASS")})  # archived skipped
        sc = engines.scc(fx("scc-findings.json"))
        self.assertEqual([r["control"] for r in sc], ["cloud.firewall_admin_port_open", "cloud.storage_public"])          # inactive skipped
        df = engines.defender(fx("defender-assessments.json"))
        self.assertEqual(sorted(r["control"] for r in df if r["status"] == "FAIL"),
                         ["cloud.firewall_admin_port_open", "cloud.instance_unpatched", "cloud.storage_public"])
        ss = engines.parse_scoutsuite(fx("scoutsuite-aws.json"), "aws", "000000000000")
        res = {r["resource"] for r in ss if r["status"] == "FAIL"}
        self.assertTrue({"arn:aws:ec2:us-east-1:000000000000:security-group/sg-b56c0e193ea8cb744", "arn:aws:s3:::acme-public-assets",
                         "arn:aws:iam::000000000000:user/legacy-deployer"} <= res, res)     # internal ids resolved
        self.assertEqual(engines.scoutsuite_blind_services(fx("scoutsuite-aws.json")), ["cloudtrail"])

    def test_dedup_across_engines_and_imports(self):
        """The same (resource, control) from Prowler, ScoutSuite and Security Hub is ONE finding with three sources."""
        p = collector.Pool()
        for r in (engines.parse_prowler_ocsf(fx("prowler-aws.ocsf.json"), "aws")
                  + engines.parse_scoutsuite(fx("scoutsuite-aws.json"), "aws", "000000000000")
                  + engines.securityhub(fx("securityhub-asff.json"))):
            p.add("aws", r.get("account") or "000000000000", r)
        by = {(f["check"], f["asset"]): f for f in p.items.values()}
        sg = by[("cloud.firewall_admin_port_open", "cloud:aws/000000000000/ec2/us-east-1/security-group/sg-b56c0e193ea8cb744")]
        self.assertEqual(sorted({s["source"] for s in sg["sources"]}), ["prowler", "scoutsuite", "securityhub"])
        s3 = by[("cloud.storage_public", "cloud:aws/000000000000/s3/global/acme-public-assets")]
        self.assertEqual(sorted({s["source"] for s in s3["sources"]}), ["prowler", "scoutsuite", "securityhub"])
        mfa = by[("cloud.user_without_mfa", "cloud:aws/000000000000/iam/global/user/legacy-deployer")]
        self.assertEqual(sorted({s["source"] for s in mfa["sources"]}), ["prowler", "scoutsuite"])
        self.assertEqual(len([k for k in by if k[0] == "cloud.storage_public"]), 1)
        # GCP: Prowler + SCC; Azure: Prowler + Defender
        g = collector.Pool()
        for r in engines.parse_prowler_ocsf(fx("prowler-gcp.ocsf.json")) + engines.scc(fx("scc-findings.json")):
            g.add("gcp", r["account"], r)
        fw = [f for f in g.items.values() if f["check"] == "cloud.firewall_admin_port_open"]
        self.assertEqual(len(fw), 1)
        self.assertEqual(sorted(s["source"] for s in fw[0]["sources"]), ["prowler", "scc"])
        a = collector.Pool()
        for r in engines.parse_prowler_ocsf(fx("prowler-azure.ocsf.json")) + engines.defender(fx("defender-assessments.json")):
            a.add("azure", r["account"], r)
        st = [f for f in a.items.values() if f["check"] == "cloud.storage_public"]
        self.assertEqual(len(st), 1)
        self.assertEqual(sorted(s["source"] for s in st[0]["sources"]), ["defender", "prowler"])
        upd = [f for f in a.items.values() if f["check"] == "cloud.instance_unpatched"]
        self.assertEqual(len(upd), 1)

    def test_unmapped_merges_by_cis_reference(self):
        p = collector.Pool()
        base = dict(provider="aws", account="1", service="s3", region="global", resource="arn:aws:s3:::b", status="FAIL",
                    severity="low", title="t", detail="")
        p.add("aws", "1", dict(base, source="a", check="x_check", control=None, refs=["cis-aws:3.0/2.1.2"]))
        p.add("aws", "1", dict(base, source="b", check="y_check", control=None, refs=["cis-aws:3.0/2.1.2"], severity="high"))
        self.assertEqual(len(p.items), 1)
        f = next(iter(p.items.values()))
        self.assertEqual(f["severity"], "high")
        self.assertEqual(len(f["sources"]), 2)


# ---- the collector end to end (fake STS/IAM, fake engine processes) + ledger lifecycle -----------------------------
FAKE_PROWLER = r'''#!/usr/bin/env python3
import json, os, sys, subprocess
a = sys.argv[1:]
out = a[a.index("-o") + 1]
os.makedirs(out, exist_ok=True)
bad = [k for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN") if k in os.environ]
cmd = open(os.environ["AWS_CONFIG_FILE"]).read().split("credential_process = ", 1)[1].splitlines()[0]
creds = json.loads(subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True).stdout)
json.dump({"argv": a, "ambient_keys": bad, "got_temporary": bool(creds.get("SessionToken"))},
          open(os.environ["FAKE_ENGINE_LOG"], "w"))
fx = json.load(open(os.environ["FAKE_PROWLER_FIXTURE"]))
json.dump(fx, open(os.path.join(out, "scan.ocsf.json"), "w"))
open(os.path.join(out, "prowler.log"), "w").write(json.dumps({"level": "ERROR", "module": "inspector2_service", "message": "AccessDenied"}) + "\n")
'''


class CollectorRun(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.tok = os.path.join(self.d, "token")
        open(self.tok, "w").write(jwt(sub="scanner", aud="sts.amazonaws.com", exp=int(time.time()) + 600))
        self.prowler = os.path.join(self.d, "prowler")
        open(self.prowler, "w").write(FAKE_PROWLER)
        os.chmod(self.prowler, 0o755)

    def tearDown(self):
        shutil.rmtree(self.d)

    def run_collector(self, name, inst, fixture):
        run = os.path.join(self.d, "runs", name)
        p = os.path.join(self.d, f"inst-{name}.json")
        json.dump(inst, open(p, "w"))
        env = dict(os.environ, SP_INSTANCE=p, SP_RUN_DIR=run, FAKE_PROWLER_FIXTURE=fixture,
                   FAKE_ENGINE_LOG=os.path.join(self.d, f"engine-{name}.json"), AWS_ACCESS_KEY_ID="ambient-should-not-leak")
        subprocess.run([sys.executable, os.path.join(ROOT, "collectors", "cloud", "collector.py")], env=env, check=True,
                       capture_output=True)
        return run, json.load(open(os.path.join(run, "cloud.findings.json")))

    def ledger(self, run):
        subprocess.run([sys.executable, os.path.join(ROOT, "core", "ledger.py"), "--run", run, "--data", self.d],
                       check=True, capture_output=True)
        return json.load(open(os.path.join(self.d, "ledger.json")))["entries"]

    def test_scan_dedup_lifecycle_and_self_check(self):
        sys.path.insert(0, os.path.join(ROOT, "core"))
        import validate
        with FakeAWSServer() as s:
            asff = os.path.join(self.d, "asff.json")
            shutil.copy(os.path.join(FX, "securityhub-asff.json"), asff)
            inst = {"cloud": {"accounts": [aws_cfg(s.url, self.tok, account_id="000000000000", engines=["prowler"])],
                              "engines": {"prowler": {"path": self.prowler}},
                              "imports": [{"type": "securityhub", "file": asff, "accounts": ["000000000000"]}]}}
            # the fake STS says account 111122223333: the collector must refuse a mismatching account
            run, doc = self.run_collector("mismatch", inst, os.path.join(FX, "prowler-aws.ocsf.json"))
            self.assertIn("expected 000000000000", next(c["reason"] for c in doc["coverage"] if c["asset"] == "cloud:aws/000000000000"))
            inst["cloud"]["accounts"][0]["account_id"] = "111122223333"
            inst["cloud"]["imports"][0]["accounts"] = ["111122223333"]
            fx_aws = json.loads(open(os.path.join(FX, "prowler-aws.ocsf.json")).read().replace("000000000000", "111122223333"))
            p1 = os.path.join(self.d, "p1.json")
            json.dump(fx_aws, open(p1, "w"))
            open(asff, "w").write(open(os.path.join(FX, "securityhub-asff.json")).read().replace("000000000000", "111122223333"))
            run1, doc1 = self.run_collector("1", inst, p1)
            self.assertEqual(validate.validate_findings(doc1), [])
            eng = json.load(open(os.path.join(self.d, "engine-1.json")))
            self.assertEqual(eng["ambient_keys"], [], "ambient static keys never reach an engine")
            self.assertTrue(eng["got_temporary"])
            self.assertIn("--scan-unused-services", eng["argv"])
            cov = {c["asset"]: c["status"] for c in doc1["coverage"]}
            self.assertEqual(cov["cloud:aws/111122223333"], "ok")
            # a service whose listing failed (an error and no verdict at all) is a gap: its findings can't be "fixed"
            self.assertEqual(cov["cloud:aws/111122223333/inspector2"], "gap")
            by = {f["check"]: f for f in doc1["findings"]}
            self.assertEqual(sorted(by["cloud.firewall_admin_port_open"]["attributes"]["engines"]), ["prowler", "securityhub"])
            self.assertEqual(by["cloud.user_without_mfa"]["attributes"]["pillar"], "people")
            raw = open(os.path.join(run1, "raw", "cloud", "aws-111122223333.json")).read()
            self.assertNotIn(FAKE_SECRET, raw)
            self.assertNotIn(FAKE_SESSION, raw)
            for root, _, files in os.walk(run1):
                for f in files:
                    self.assertNotIn(FAKE_SESSION, open(os.path.join(root, f)).read(), f)
            L = self.ledger(run1)
            sg = next(e for e in L.values() if e["check"] == "cloud.firewall_admin_port_open")
            self.assertEqual(sg["status"], "open")
            # the security group is fixed: the engine now reports PASS, the native service too -> fixed on this covered run
            for x in fx_aws:
                if x["metadata"]["event_code"].startswith("ec2_securitygroup"):
                    x["status_code"] = "PASS"
            json.dump(fx_aws, open(p1, "w"))
            d = json.load(open(asff))
            d["Findings"][0]["Compliance"]["Status"] = "PASSED"
            json.dump(d, open(asff, "w"))
            run2, doc2 = self.run_collector("2", inst, p1)
            L = self.ledger(run2)
            self.assertEqual(L[sg["id"]]["status"], "fixed")
            self.assertEqual(next(e for e in L.values() if e["check"] == "cloud.storage_public")["status"], "open")
            # an over-privileged platform role: finding + refuse-to-run (gap keeps every finding as it was)
            FakeAWS.state["attached"].append("arn:aws:iam::aws:policy/PowerUserAccess")
            FakeAWS.state["docs"]["arn:aws:iam::aws:policy/PowerUserAccess"] = {"Statement": [{"Effect": "Allow", "NotAction": ["iam:*"]}]}
            run3, doc3 = self.run_collector("3", inst, p1)
            self.assertIn("refused", next(c["reason"] for c in doc3["coverage"] if c["asset"] == "cloud:aws/111122223333"))
            self.assertEqual([f["check"] for f in doc3["findings"] if f["asset"] == "cloud:aws/111122223333"],
                             ["cloud.platform_credential_over_privileged"])
            self.assertFalse(os.path.exists(os.path.join(self.d, "engine-3.json")), "no engine ran")
            L = self.ledger(run3)
            self.assertEqual(next(e for e in L.values() if e["check"] == "cloud.storage_public")["status"], "open")


# ---- scorecard ------------------------------------------------------------------------------------------------
class Scorecard(unittest.TestCase):
    def test_not_applicable_without_cloud(self):
        import scorecard as sc
        d = tempfile.mkdtemp()
        try:
            r = sc.compute(d, {}, time.time())
            self.assertNotIn("cloud", r["dimensions"])
            self.assertIn("cloud", r["not_applicable"])
            st = {c["id"]: c["status"] for c in r["controls"]}
            self.assertEqual(st["cloud.mfa"], "na")
            self.assertEqual(st["self.cloud-credential-read-only"], "na")
            self.assertEqual(r["overall"], min(x["score"] for x in r["dimensions"].values()))
            r2 = sc.compute(d, {"cloud": {"accounts": [{"provider": "aws", "account_id": "1"}]}}, time.time())
            self.assertIn("cloud", r2["dimensions"])
            self.assertEqual({c["id"]: c["status"] for c in r2["controls"]}["cloud.mfa"], "unknown")   # nobody looked yet
            self.assertNotIn("security_score{dimension=\"cloud\"}", sc.prom(r, time.time()))
            self.assertIn("NOT APPLICABLE", sc.markdown(r))
        finally:
            shutil.rmtree(d)

    def test_catalog_cites_cis_benchmarks(self):
        import scorecard as sc
        dims, ctrls = sc.load_catalog([os.path.join(ROOT, "scorecard", "catalog")])
        cloud_ctrls = [c for c in ctrls if c["dimension"] == "cloud"]
        self.assertEqual({p for c in cloud_ctrls for p in c["pillars"]}, set(sc.PILLARS))
        cited = {k for c in cloud_ctrls for k in (c.get("cis_benchmarks") or {})}
        self.assertEqual(cited, {"aws", "gcp", "azure"})
        checks = {x for c in cloud_ctrls for x in (c.get("source") or {}).get("check_in", [])}
        self.assertEqual(checks - set(controls.CONTROLS), set())
        self.assertEqual(set(controls.CONTROLS) - checks - {"cloud.platform_credential_over_privileged"}, set(),
                         "every generic control is scored")
        self.assertEqual(sc.lint(dims, ctrls), [])


if __name__ == "__main__":
    unittest.main()
