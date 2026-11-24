"""cloud adapter interface: cloud accounts (AWS accounts, GCP projects, Azure subscriptions) as assets, reached with
SHORT-LIVED, READ-ONLY credentials only. Stdlib; never stores or logs a credential. docs/cloud.md is the guide.

  provider(cfg)                  -> AWS | GCP | Azure (cfg = one entry of the instance's `cloud.accounts`)
  p.asset                        -> "cloud:<provider>/<account id>" (coverage asset; findings live below it)
  p.credentials()                -> short-lived credentials, cached IN MEMORY and refreshed REFRESH_MARGIN s before expiry
  p.identity()                   -> {"principal": ..., "account": ...} the identity the platform runs as
  p.permissions()                -> {"principal", "method", "grants": [..], "write_capable": [..]} (self-verification)
  p.engine_env(tmpdir)           -> (env, args): how an external engine (Prowler, Steampipe, ...) authenticates. The env
                                    carries no secret: the engine calls back into this module (`credential_process`,
                                    an external-account config, a federated token file) whenever it needs a token.

Credential modes (long-lived keys are refused: access keys, client secrets, service-account key files):
  aws    web_identity  OIDC token (file / command / env) -> STS AssumeRoleWithWebIdentity [-> AssumeRole chain_role_arn]
         profile       an AWS CLI profile that yields temporary credentials (IAM Identity Center/SSO, a role with
                       credential_source); `aws configure export-credentials`; refused if it yields long-lived keys
  gcp    workload_identity  OIDC token -> STS token exchange (sts.googleapis.com) -> iamcredentials generateAccessToken
                            for `service_account` (impersonation)
  azure  federated     OIDC token as client assertion -> Microsoft Entra token endpoint (workload identity federation)
Every endpoint is configurable (an emulator or a sovereign cloud) and defaults to the public one.

Failures raise CloudAuthError(reason): the collector records a coverage gap with that reason, never "no findings".
"""
import base64
import datetime
import hashlib
import hmac
import json
import os
import shlex
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

VERSION = "0.1.0"
REFRESH_MARGIN = 300          # seconds before expiry at which cached credentials are renewed
SESSION_SECONDS = 3600
LONG_LIVED_KEYS = ("access_key_id", "secret_access_key", "aws_access_key_id", "aws_secret_access_key", "client_secret",
                   "private_key", "service_account_key", "key_file", "password", "certificate_password")
AWS_ENV_KEYS = ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN", "AWS_PROFILE",
                "AWS_DEFAULT_PROFILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE")
GCP_ENV_KEYS = ("GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_OAUTH_ACCESS_TOKEN", "CLOUDSDK_AUTH_ACCESS_TOKEN")
AZURE_ENV_KEYS = ("AZURE_CLIENT_SECRET", "AZURE_CLIENT_CERTIFICATE_PATH", "AZURE_USERNAME", "AZURE_PASSWORD",
                  "AZURE_FEDERATED_TOKEN_FILE", "AZURE_CLIENT_ID", "AZURE_TENANT_ID")

# The minimal read-only grants per provider (docs/cloud.md). Anything else attached to the platform's identity is
# "write-capable or unverified" -> finding cloud.platform_credential_over_privileged (and refuse-to-run by default).
AWS_READ_ONLY_POLICIES = {"arn:aws:iam::aws:policy/SecurityAudit", "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"}
AWS_READ_VERBS = ("Get", "List", "Describe", "BatchGet", "Search", "Lookup", "View", "Head", "Query", "Select",
                  "Generate", "Simulate", "Check", "Validate", "Preview", "Estimate")
GCP_READ_ONLY_ROLES = {"roles/iam.securityReviewer", "roles/viewer", "roles/browser", "roles/cloudasset.viewer",
                       "roles/securitycenter.findingsViewer", "roles/securitycenter.adminViewer", "roles/logging.viewer",
                       "roles/monitoring.viewer", "roles/serviceusage.serviceUsageConsumer", "roles/iam.roleViewer"}
AZURE_READ_ONLY_ROLES = {"acdd72a7-3385-48ef-bd42-f606fba81ae7": "Reader",
                         "39bc4728-0917-49c7-9d2c-d95423bc2eb4": "Security Reader"}
AZURE_KNOWN_WRITE_ROLES = {"8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner", "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
                           "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator"}


class CloudAuthError(Exception):
    """Authentication / authorisation failed; str() is a short, secret-free reason for a coverage gap."""


# ---- identity tokens (the workload's OIDC token: Kubernetes projected token, CI OIDC, a local issuer) ----------
def _b64url(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jwt_claims(token):
    try:
        return json.loads(_b64url(token.split(".")[1]))
    except (IndexError, ValueError):
        raise CloudAuthError("identity token is not a JWT")


def precheck_token(token, audience=None, now=None, skew=30):
    """Checks a client can make before sending a token (the server still validates the signature): expiry, audience."""
    c = jwt_claims(token)
    now = now or time.time()
    if c.get("exp") is not None and float(c["exp"]) <= now + skew:
        raise CloudAuthError("identity token expired")
    if audience:
        aud = c.get("aud")
        if audience not in (aud if isinstance(aud, list) else [aud]):
            raise CloudAuthError(f"identity token audience mismatch (expected {audience})")
    return c


def identity_token(src):
    """{type: file, path} | {type: command, argv: [..]} | {type: env, name}: read fresh on every acquisition."""
    if not src:
        raise CloudAuthError("identity_token not configured")
    typ = src.get("type", "file")
    try:
        if typ == "file":
            return open(os.path.expanduser(src["path"])).read().strip()
        if typ == "env":
            v = os.environ.get(src["name"], "").strip()
            if not v:
                raise CloudAuthError(f"identity token env {src['name']} empty")
            return v
        if typ == "command":
            argv = src["argv"] if isinstance(src["argv"], list) else shlex.split(src["argv"])
            r = subprocess.run(argv, capture_output=True, text=True, timeout=int(src.get("timeout", 30)))
            if r.returncode != 0 or not r.stdout.strip():
                raise CloudAuthError(f"identity token command failed (rc={r.returncode})")
            return r.stdout.strip()
    except (OSError, KeyError, subprocess.TimeoutExpired) as e:
        raise CloudAuthError(f"identity token unavailable: {type(e).__name__}")
    raise CloudAuthError(f"identity_token type {typ!r} unknown (file, command, env)")


def refuse_long_lived(cfg):
    bad = sorted(k for k in cfg if k.lower() in LONG_LIVED_KEYS)
    if bad:
        raise CloudAuthError(f"long-lived credentials are not accepted ({', '.join(bad)}): use federation/short-lived roles")


# ---- HTTP -----------------------------------------------------------------------------------------------------
def http(method, url, data=None, headers=None, timeout=30):
    """-> (status, body bytes). Never raises on HTTP status; network errors raise CloudAuthError (no URL: it may
    carry a query string)."""
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except (urllib.error.URLError, OSError) as e:
        raise CloudAuthError(f"{urllib.parse.urlparse(url).hostname}: unreachable ({type(e).__name__})")


def _err_text(body):
    """A short reason from an error body (STS XML, Google/Entra JSON). Messages carry codes, never credentials."""
    try:
        root = ET.fromstring(body)
        code = root.findtext(".//{*}Code") or ""
        msg = root.findtext(".//{*}Message") or ""
        return f"{code}: {msg}"[:200]
    except ET.ParseError:
        pass
    try:
        d = json.loads(body)
        e = d.get("error")
        if isinstance(e, dict):
            return f"{e.get('status') or e.get('code')}: {e.get('message', '')}"[:200]
        return f"{e}: {d.get('error_description', '')}"[:200]
    except ValueError:
        return body[:120].decode("utf-8", "replace")


# ---- AWS SigV4 (Query APIs: STS, IAM) ---------------------------------------------------------------------------
def sigv4(method, url, region, service, body, creds, now=None):
    """Signature Version 4 headers for a request (stdlib; tested against the AWS documentation's example)."""
    t = datetime.datetime.fromtimestamp(now or time.time(), datetime.timezone.utc)
    amzdate, date = t.strftime("%Y%m%dT%H%M%SZ"), t.strftime("%Y%m%d")
    u = urllib.parse.urlparse(url)
    headers = {"host": u.netloc, "x-amz-date": amzdate}
    if body is not None and method == "POST":
        headers["content-type"] = "application/x-www-form-urlencoded; charset=utf-8"
    if creds.get("SessionToken"):
        headers["x-amz-security-token"] = creds["SessionToken"]
    names = sorted(headers)
    canon_q = "&".join(f"{urllib.parse.quote(k, safe='-_.~')}={urllib.parse.quote(v, safe='-_.~')}"
                       for k, v in sorted(urllib.parse.parse_qsl(u.query, keep_blank_values=True)))
    payload = hashlib.sha256(body or b"").hexdigest()
    creq = "\n".join([method, u.path or "/", canon_q, "".join(f"{k}:{headers[k].strip()}\n" for k in names),
                      ";".join(names), payload])
    scope = f"{date}/{region}/{service}/aws4_request"
    sts_ = "\n".join(["AWS4-HMAC-SHA256", amzdate, scope, hashlib.sha256(creq.encode()).hexdigest()])
    k = ("AWS4" + creds["SecretAccessKey"]).encode()
    for part in (date, region, service, "aws4_request"):
        k = hmac.new(k, part.encode(), hashlib.sha256).digest()
    sig = hmac.new(k, sts_.encode(), hashlib.sha256).hexdigest()
    headers["Authorization"] = (f"AWS4-HMAC-SHA256 Credential={creds['AccessKeyId']}/{scope}, "
                                f"SignedHeaders={';'.join(names)}, Signature={sig}")
    return headers


def _xml(body):
    root = ET.fromstring(body)
    for el in root.iter():           # drop namespaces: {ns}Tag -> Tag
        el.tag = el.tag.split("}", 1)[-1]
    return root


def _iso_epoch(s):
    s = s.strip().replace("Z", "+00:00")
    if "." in s:
        head, _, rest = s.partition(".")
        tz = rest[rest.find("+"):] if "+" in rest else (rest[rest.find("-"):] if "-" in rest else "")
        s = head + tz
    return datetime.datetime.fromisoformat(s).timestamp()


class Provider:
    kind = "?"

    def __init__(self, cfg, clock=time.time):
        refuse_long_lived(cfg)
        self.cfg, self.clock, self._cache = cfg, clock, None
        self.account = str(cfg.get(self.ID_KEY) or "")
        if not self.account:
            raise CloudAuthError(f"{self.kind}: `{self.ID_KEY}` missing")
        self.asset = f"cloud:{self.kind}/{self.account}"
        self.refreshes = 0

    def credentials(self):
        """Cached in memory; renewed REFRESH_MARGIN seconds before expiry (a long scan never runs on stale tokens)."""
        if self._cache and self._cache["expires"] - self.clock() > REFRESH_MARGIN:
            return self._cache
        self._cache = self._acquire()
        self.refreshes += 1
        return self._cache

    def _token(self):
        tok = identity_token(self.cfg.get("identity_token"))
        precheck_token(tok, self.cfg.get("audience"), self.clock())
        return tok


# ---- AWS ------------------------------------------------------------------------------------------------------
class AWS(Provider):
    kind, ID_KEY = "aws", "account_id"

    def __init__(self, cfg, clock=time.time):
        super().__init__(cfg, clock)
        self.region = cfg.get("region") or (cfg.get("regions") or ["us-east-1"])[0]
        self.endpoint = (cfg.get("endpoint_url") or "").rstrip("/")
        self.mode = cfg.get("mode") or ("profile" if cfg.get("profile") else "web_identity")

    def url(self, service):
        if self.endpoint:
            return self.endpoint + "/"
        if service == "iam":
            return "https://iam.amazonaws.com/"
        return f"https://sts.{self.region}.amazonaws.com/"

    def _query(self, service, params, creds=None):
        body = urllib.parse.urlencode(dict(params, Version="2010-05-08" if service == "iam" else "2011-06-15")).encode()
        url = self.url(service)
        region = "us-east-1" if service == "iam" else self.region
        headers = sigv4("POST", url, region, service, body, creds) if creds else \
            {"content-type": "application/x-www-form-urlencoded; charset=utf-8"}
        st, out = http("POST", url, body, headers)
        if st != 200:
            raise CloudAuthError(f"{service} {params['Action']}: HTTP {st} {_err_text(out)}")
        return _xml(out)

    @staticmethod
    def _creds_from(root):
        c = root.find(".//Credentials")
        if c is None:
            raise CloudAuthError("STS returned no credentials")
        return {"AccessKeyId": c.findtext("AccessKeyId"), "SecretAccessKey": c.findtext("SecretAccessKey"),
                "SessionToken": c.findtext("SessionToken"), "expires": _iso_epoch(c.findtext("Expiration"))}

    def _acquire(self):
        dur = str(int(self.cfg.get("session_seconds", SESSION_SECONDS)))
        name = self.cfg.get("session_name", "security-platform")
        if self.mode == "profile":
            creds = self._export_profile()
        elif self.mode == "web_identity":
            if not self.cfg.get("role_arn"):
                raise CloudAuthError("aws: role_arn missing")
            creds = self._creds_from(self._query("sts", {
                "Action": "AssumeRoleWithWebIdentity", "RoleArn": self.cfg["role_arn"], "RoleSessionName": name,
                "WebIdentityToken": self._token(), "DurationSeconds": dur}))
        else:
            raise CloudAuthError(f"aws: mode {self.mode!r} unknown (web_identity, profile)")
        if self.cfg.get("chain_role_arn"):
            p = {"Action": "AssumeRole", "RoleArn": self.cfg["chain_role_arn"], "RoleSessionName": name,
                 "DurationSeconds": dur}
            if self.cfg.get("external_id"):
                p["ExternalId"] = self.cfg["external_id"]
            creds = self._creds_from(self._query("sts", p, creds))
        return creds

    def _export_profile(self):
        """An AWS CLI profile (SSO / role) -> temporary credentials; long-lived user keys are refused."""
        try:
            r = subprocess.run(["aws", "configure", "export-credentials", "--profile", self.cfg["profile"],
                                "--format", "process"], capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise CloudAuthError(f"aws profile: {type(e).__name__}")
        if r.returncode != 0:
            raise CloudAuthError(f"aws profile {self.cfg['profile']}: export-credentials failed (rc={r.returncode})")
        d = json.loads(r.stdout)
        if not d.get("SessionToken") or not d.get("Expiration"):
            raise CloudAuthError(f"aws profile {self.cfg['profile']} yields long-lived keys: use SSO or a role")
        return {"AccessKeyId": d["AccessKeyId"], "SecretAccessKey": d["SecretAccessKey"],
                "SessionToken": d["SessionToken"], "expires": _iso_epoch(d["Expiration"])}

    def identity(self):
        r = self._query("sts", {"Action": "GetCallerIdentity"}, self.credentials())
        arn, acct = r.findtext(".//Arn"), r.findtext(".//Account")
        if acct and acct != self.account:
            raise CloudAuthError(f"aws: credentials are for account {acct}, expected {self.account}")
        return {"principal": arn, "account": acct}

    def permissions(self):
        """The role's attached + inline policies (SimulatePrincipalPolicy is not used: emulators do not implement
        it and it needs extra rights). Managed read-only policies pass; any other statement allowing a non-read
        verb, `*` or `service:*` is write-capable."""
        arn = self.identity()["principal"]
        parts = arn.split(":", 5)[-1].split("/")
        if parts[0] != "assumed-role":
            return {"principal": arn, "method": "n/a", "grants": [], "write_capable": [f"not a role session: {parts[0]}"]}
        role, creds = parts[1], self.credentials()
        try:
            self._query("iam", {"Action": "GetRole", "RoleName": role}, creds)
        except CloudAuthError as e:
            if "NoSuchEntity" in str(e):
                raise CloudAuthError(f"aws: role {role} does not exist")
            raise
        grants, write = [], []
        attached = self._query("iam", {"Action": "ListAttachedRolePolicies", "RoleName": role}, creds)
        for m in attached.iter("member"):
            parn = m.findtext("PolicyArn")
            if not parn:
                continue
            grants.append(parn)
            if parn in AWS_READ_ONLY_POLICIES:
                continue
            pol = self._query("iam", {"Action": "GetPolicy", "PolicyArn": parn}, creds)
            ver = pol.findtext(".//DefaultVersionId")
            doc = self._query("iam", {"Action": "GetPolicyVersion", "PolicyArn": parn, "VersionId": ver}, creds)
            if write_actions(urllib.parse.unquote(doc.findtext(".//Document") or "{}")):
                write.append(parn)
        inline = self._query("iam", {"Action": "ListRolePolicies", "RoleName": role}, creds)
        for name in [m.text for m in inline.iter("member") if m.text]:
            grants.append(f"inline:{name}")
            doc = self._query("iam", {"Action": "GetRolePolicy", "RoleName": role, "PolicyName": name}, creds)
            if write_actions(urllib.parse.unquote(doc.findtext(".//PolicyDocument") or "{}")):
                write.append(f"inline:{name}")
        return {"principal": arn, "method": "attached and inline role policies", "grants": grants, "write_capable": write}

    def engine_env(self, tmpdir):
        """A profile whose credential_process calls back into this module: the engine (boto3, the Go SDK) gets
        temporary credentials in memory and asks again before they expire. The files hold no secret."""
        acct = os.path.join(tmpdir, f"aws-{self.account}.json")
        with open(os.open(acct, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
            json.dump(self.cfg, f)
        cfgp = os.path.join(tmpdir, f"aws-{self.account}.config")
        cmd = f"{shlex.quote(sys.executable)} -I {shlex.quote(os.path.abspath(__file__))} credential-process {shlex.quote(acct)}"
        with open(os.open(cfgp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
            f.write(f"[profile security-platform]\ncredential_process = {cmd}\nregion = {self.region}\n")
        env = {"AWS_CONFIG_FILE": cfgp, "AWS_PROFILE": "security-platform", "AWS_REGION": self.region,
               "AWS_DEFAULT_REGION": self.region, "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
               "AWS_EC2_METADATA_DISABLED": "true"}
        if self.endpoint:
            env["AWS_ENDPOINT_URL"] = self.endpoint
        return env, {"profile": "security-platform", "regions": self.cfg.get("regions") or [self.region]}


def write_actions(doc):
    """Actions an IAM policy document ALLOWS that are not read-only (empty list = read-only)."""
    try:
        d = json.loads(doc) if isinstance(doc, str) else doc
    except ValueError:
        return ["<unparseable policy>"]
    out = []
    stmts = d.get("Statement") or []
    for s in stmts if isinstance(stmts, list) else [stmts]:
        if s.get("Effect") != "Allow":
            continue
        if "NotAction" in s:
            out.append("NotAction")
            continue
        acts = s.get("Action") or []
        for a in acts if isinstance(acts, list) else [acts]:
            verb = a.split(":", 1)[-1]
            if a == "*" or verb == "*" or not verb.startswith(AWS_READ_VERBS):
                out.append(a)
    return sorted(set(out))


# ---- GCP ------------------------------------------------------------------------------------------------------
class GCP(Provider):
    kind, ID_KEY = "gcp", "project_id"

    def __init__(self, cfg, clock=time.time):
        super().__init__(cfg, clock)
        self.sts_url = cfg.get("sts_url", "https://sts.googleapis.com/v1/token")
        self.iamcred = cfg.get("iamcredentials_url", "https://iamcredentials.googleapis.com/v1").rstrip("/")
        self.crm = cfg.get("resourcemanager_url", "https://cloudresourcemanager.googleapis.com/v1").rstrip("/")
        for k in ("workload_identity_provider", "service_account"):
            if not cfg.get(k):
                raise CloudAuthError(f"gcp: {k} missing")
        self.audience = "//iam.googleapis.com/" + cfg["workload_identity_provider"].removeprefix("//iam.googleapis.com/")

    def _acquire(self):
        tok = self._token()
        body = urllib.parse.urlencode({
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange", "audience": self.audience,
            "scope": "https://www.googleapis.com/auth/cloud-platform",
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt", "subject_token": tok}).encode()
        st, out = http("POST", self.sts_url, body, {"Content-Type": "application/x-www-form-urlencoded"})
        if st != 200:
            raise CloudAuthError(f"gcp sts token exchange: HTTP {st} {_err_text(out)}")
        fed = json.loads(out)["access_token"]
        sa = self.cfg["service_account"]
        st, out = http("POST", f"{self.iamcred}/projects/-/serviceAccounts/{urllib.parse.quote(sa)}:generateAccessToken",
                       json.dumps({"scope": ["https://www.googleapis.com/auth/cloud-platform"],
                                   "lifetime": f"{int(self.cfg.get('session_seconds', SESSION_SECONDS))}s"}).encode(),
                       {"Authorization": "Bearer " + fed, "Content-Type": "application/json"})
        if st != 200:
            raise CloudAuthError(f"gcp impersonation of {sa}: HTTP {st} {_err_text(out)}")
        d = json.loads(out)
        return {"access_token": d["accessToken"], "expires": _iso_epoch(d["expireTime"])}

    def identity(self):
        self.credentials()
        return {"principal": "serviceAccount:" + self.cfg["service_account"], "account": self.account}

    def permissions(self):
        """Roles bound to the service account on the project (getIamPolicy: allowed by Security Reviewer)."""
        member = "serviceAccount:" + self.cfg["service_account"]
        st, out = http("POST", f"{self.crm}/projects/{urllib.parse.quote(self.account)}:getIamPolicy", b"{}",
                       {"Authorization": "Bearer " + self.credentials()["access_token"], "Content-Type": "application/json"})
        if st != 200:
            raise CloudAuthError(f"gcp getIamPolicy {self.account}: HTTP {st} {_err_text(out)}")
        roles = sorted({b["role"] for b in json.loads(out).get("bindings") or [] if member in (b.get("members") or [])})
        return {"principal": member, "method": "project IAM policy bindings", "grants": roles,
                "write_capable": [r for r in roles if r not in GCP_READ_ONLY_ROLES]}

    def engine_env(self, tmpdir):
        """An external-account (workload identity federation) config: no key; google-auth exchanges the OIDC token
        itself and impersonates the service account, refreshing as needed."""
        src = self.cfg.get("identity_token") or {}
        if src.get("type", "file") == "file":
            cred_src = {"file": os.path.expanduser(src["path"])}
            extra = {}
        else:
            acct = os.path.join(tmpdir, f"gcp-{self.account}.json")
            with open(os.open(acct, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
                json.dump(self.cfg, f)
            cred_src = {"executable": {"command": f"{sys.executable} -I {os.path.abspath(__file__)} executable-token {acct}",
                                       "timeout_millis": 30000}}
            extra = {"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"}
        conf = {"type": "external_account", "audience": self.audience,
                "subject_token_type": "urn:ietf:params:oauth:token-type:jwt", "token_url": self.sts_url,
                "service_account_impersonation_url":
                    f"{self.iamcred}/projects/-/serviceAccounts/{self.cfg['service_account']}:generateAccessToken",
                "credential_source": cred_src}
        p = os.path.join(tmpdir, f"gcp-{self.account}.external-account.json")
        with open(os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
            json.dump(conf, f)
        return dict(extra, GOOGLE_APPLICATION_CREDENTIALS=p, GOOGLE_CLOUD_PROJECT=self.account), \
            {"projects": self.cfg.get("project_ids") or [self.account]}


# ---- Azure ----------------------------------------------------------------------------------------------------
class Azure(Provider):
    kind, ID_KEY = "azure", "subscription_id"

    def __init__(self, cfg, clock=time.time):
        super().__init__(cfg, clock)
        for k in ("tenant_id", "client_id"):
            if not cfg.get(k):
                raise CloudAuthError(f"azure: {k} missing")
        self.authority = cfg.get("authority_host", "https://login.microsoftonline.com").rstrip("/")
        self.arm = cfg.get("arm_url", "https://management.azure.com").rstrip("/")

    def _acquire(self):
        tok = self._token()
        body = urllib.parse.urlencode({
            "client_id": self.cfg["client_id"], "grant_type": "client_credentials",
            "scope": self.cfg.get("scope", "https://management.azure.com/.default"),
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": tok}).encode()
        st, out = http("POST", f"{self.authority}/{self.cfg['tenant_id']}/oauth2/v2.0/token", body,
                       {"Content-Type": "application/x-www-form-urlencoded"})
        if st != 200:
            raise CloudAuthError(f"azure federated token: HTTP {st} {_err_text(out)}")
        d = json.loads(out)
        return {"access_token": d["access_token"], "expires": self.clock() + float(d.get("expires_in", 3600))}

    def identity(self):
        c = jwt_claims(self.credentials()["access_token"])
        return {"principal": c.get("oid") or c.get("sub"), "account": self.account}

    def permissions(self):
        """Role assignments of the platform's principal on the subscription (Reader can list them)."""
        oid = self.identity()["principal"]
        q = urllib.parse.urlencode({"api-version": "2022-04-01", "$filter": f"assignedTo('{oid}')"})
        st, out = http("GET", f"{self.arm}/subscriptions/{self.account}/providers/Microsoft.Authorization/roleAssignments?{q}",
                       None, {"Authorization": "Bearer " + self.credentials()["access_token"]})
        if st != 200:
            raise CloudAuthError(f"azure role assignments: HTTP {st} {_err_text(out)}")
        grants, write = [], []
        for a in json.loads(out).get("value") or []:
            rid = a.get("properties", {}).get("roleDefinitionId", "").rsplit("/", 1)[-1]
            name = AZURE_READ_ONLY_ROLES.get(rid) or AZURE_KNOWN_WRITE_ROLES.get(rid) or f"role {rid}"
            grants.append(name)
            if rid not in AZURE_READ_ONLY_ROLES:
                write.append(name)
        return {"principal": oid, "method": "subscription role assignments", "grants": sorted(grants),
                "write_capable": sorted(set(write))}

    def engine_env(self, tmpdir):
        """Workload identity federation for azure-identity (DefaultAzureCredential's WorkloadIdentityCredential).
        It needs the OIDC token in a FILE: a configured file is used as is; a command/env token is written to a 0600
        file in this run's private temporary directory (removed after the run). It is the short-lived workload
        assertion, not an Azure credential."""
        src = self.cfg.get("identity_token") or {}
        if src.get("type", "file") == "file":
            tokp = os.path.expanduser(src["path"])
        else:
            tokp = os.path.join(tmpdir, f"azure-{self.account}.assertion")
            with open(os.open(tokp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
                f.write(self._token())
        env = {"AZURE_TENANT_ID": self.cfg["tenant_id"], "AZURE_CLIENT_ID": self.cfg["client_id"],
               "AZURE_FEDERATED_TOKEN_FILE": tokp}
        if self.cfg.get("authority_host"):
            env["AZURE_AUTHORITY_HOST"] = self.authority
        return env, {"subscriptions": self.cfg.get("subscription_ids") or [self.account]}


PROVIDERS = {"aws": AWS, "gcp": GCP, "azure": Azure}


def provider(cfg, clock=time.time):
    cls = PROVIDERS.get(cfg.get("provider"))
    if not cls:
        raise CloudAuthError(f"provider {cfg.get('provider')!r} unknown ({', '.join(PROVIDERS)})")
    return cls(cfg, clock)


def clean_env(base=None):
    """The environment an engine starts from: ambient cloud credentials removed, so only what engine_env() grants is
    used (a developer's admin keys in the shell must never reach a scan)."""
    env = dict(base if base is not None else os.environ)
    for k in AWS_ENV_KEYS + GCP_ENV_KEYS + AZURE_ENV_KEYS:
        env.pop(k, None)
    return env


# ---- callbacks used by engines (credential_process / executable-sourced tokens) ---------------------------------
def _main(argv):
    if len(argv) == 2 and argv[0] == "credential-process":
        c = AWS(json.load(open(argv[1]))).credentials()
        exp = datetime.datetime.fromtimestamp(c["expires"], datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        print(json.dumps({"Version": 1, "AccessKeyId": c["AccessKeyId"], "SecretAccessKey": c["SecretAccessKey"],
                          "SessionToken": c["SessionToken"], "Expiration": exp}))
        return 0
    if len(argv) == 2 and argv[0] == "executable-token":          # google-auth executable-sourced credentials
        cfg = json.load(open(argv[1]))
        tok = identity_token(cfg.get("identity_token"))
        exp = int(jwt_claims(tok).get("exp") or time.time() + 300)
        print(json.dumps({"version": 1, "success": True, "token_type": "urn:ietf:params:oauth:token-type:jwt",
                          "id_token": tok, "expiration_time": exp}))
        return 0
    print("usage: cloud.py credential-process ACCOUNT.json | executable-token ACCOUNT.json", file=sys.stderr)
    return 2


if __name__ == "__main__":
    try:
        sys.exit(_main(sys.argv[1:]))
    except CloudAuthError as e:
        print(f"security-platform cloud: {e}", file=sys.stderr)
        sys.exit(1)
