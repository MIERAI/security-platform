"""identity adapter interface: who (and what) can act as us. READ-ONLY; never returns a secret value.

  provider(cfg).collect() -> Snapshot{accounts, orgs, grants, credentials, policies, gaps, covered}
  local_credentials(cfg)   -> Snapshot (credentials found on this host: metadata only)

Providers normalise their API into the records below; the `identity` collector applies the checks, so a new identity
provider is a new adapter, never new checks. Records (plain dicts):

  account     {provider, id, kind: human|bot|service, mfa: True|False|None (None = the API cannot tell),
               mfa_methods: [..]|None, admin: bool|None, created_at, last_active}
  org         {provider, id, mfa_required: True|False|None, members, outside_collaborators}
  grant       {provider, resource, principal, kind: collaborator|deploy_key|app|oauth_app|member, permission,
               read_only, created_at, last_used}
  credential  {provider|store, id (a NAME, never the value), kind: oauth_token|pat_classic|pat_fine_grained|ssh_key|
               deploy_key|kube_client_cert|kube_token|kube_exec|registry|api_key|token_file, location, scopes: [..]|None,
               created_at, expires_at, last_used, notes}
  policy      {provider, resource, name, value, public: bool}   e.g. fork_pr_approval, acl_allow_all
  gaps        [(asset, reason)]  what the provider could not see (missing scope, no API key): a coverage gap
  covered     [asset]            what it did see

Implemented: github (gh CLI; conditional requests with ETags cached under <cache>, so an unchanged resource costs no
rate limit), tailscale (API with a read-only key file when configured; otherwise the local CLI: devices and key
expiry, ACL = gap). local credentials: gh keyring (macOS keychain metadata), kubeconfig files, SSH key files, Docker
config, token files.
Interface only (documented, `collect()` raises NotImplementedError -> a coverage gap): google-workspace (Admin SDK
Directory users.list: isEnrolledIn2Sv/isEnforcedIn2Sv, tokens.list), okta (/api/v1/users + /factors, /api/v1/apps),
entra (Microsoft Graph /reports/authenticationMethods/userRegistrationDetails, /users, /applications), gitlab
(/users?two_factor=disabled, /personal_access_tokens).
"""
import base64
import glob
import hashlib
import json
import os
import re
import subprocess
import time
import urllib.request

VERSION = "0.2.0"


def iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t)) if t else None


def snapshot():
    return {"accounts": [], "orgs": [], "grants": [], "credentials": [], "policies": [], "gaps": [], "covered": []}


# ---- GitHub ----------------------------------------------------------------------------------------------------------
class GitHubAPI:
    """gh api with ETag caching (a 304 does not count against the rate limit). The token stays in the child env."""

    def __init__(self, user, cache_dir=None):
        tok = subprocess.run(["gh", "auth", "token", "--user", user], capture_output=True, text=True).stdout.strip()
        self.env = dict(os.environ, GH_TOKEN=tok)
        self.prefix = tok[:4] if tok.startswith(("gho_", "ghp_", "ghu_", "ghs_")) else ("github_pat_" if tok.startswith("github_pat_") else "")
        self.cache = os.path.join(cache_dir, user) if cache_dir else None
        self.calls = self.not_modified = 0
        self.headers = {}

    def get(self, path):
        """-> (status, body|None, error). Cached bodies are reused on 304."""
        cp = os.path.join(self.cache, hashlib.sha1(path.encode()).hexdigest() + ".json") if self.cache else None
        cached = None
        if cp and os.path.exists(cp):
            try:
                cached = json.load(open(cp))
            except ValueError:
                cached = None
        cmd = ["gh", "api", "-i", "-H", "Accept: application/vnd.github+json", path]
        if cached and cached.get("etag"):
            cmd[3:3] = ["-H", f"If-None-Match: {cached['etag']}"]
        p = subprocess.run(cmd, capture_output=True, text=True, env=self.env, timeout=60)
        self.calls += 1
        head, _, body = p.stdout.replace("\r\n", "\n").partition("\n\n")
        m = re.match(r"HTTP/\S+ (\d+)", head)
        status = int(m.group(1)) if m else 0
        hdr = {k.lower(): v.strip() for k, v in (l.split(":", 1) for l in head.splitlines()[1:] if ":" in l)}
        if status == 304 and cached:
            self.not_modified += 1
            self.headers = cached.get("headers", {})
            return 200, cached["body"], None
        self.headers = {k: hdr[k] for k in ("x-oauth-scopes", "github-authentication-token-expiration") if k in hdr}
        if status != 200:
            try:
                msg = json.loads(body).get("message", "")
            except ValueError:
                msg = (p.stderr or body).strip()
            return status, None, f"HTTP {status}: {msg[:160]}"
        data = json.loads(body) if body.strip() else None
        if cp and hdr.get("etag"):
            os.makedirs(os.path.dirname(cp), mode=0o700, exist_ok=True)
            with open(cp, "w") as f:
                json.dump({"etag": hdr["etag"], "body": data, "headers": self.headers}, f)
        return status, data, None


class GitHub:
    """cfg: {type: github, accounts: [{gh_user}], orgs?: [logins in scope; default all of the accounts' orgs],
    repos_owner?, repos_via?: <gh_user whose token lists the repos>, expected_collaborators: [..]}"""

    def __init__(self, cfg, cache_dir=None, keyring=None):
        self.cfg, self.cache_dir, self.keyring = cfg, cache_dir, keyring or keychain_meta

    def collect(self):
        s = snapshot()
        orgs_seen, repos_done = set(), False
        for a in self.cfg.get("accounts", []):
            user = a["gh_user"]
            g = GitHubAPI(user, self.cache_dir)
            st, me, err = g.get("/user")
            if me is None:
                s["gaps"].append((f"identity:github/{user}", err or "no /user"))
                continue
            s["covered"].append(f"identity:github/{user}")
            mfa = me.get("two_factor_authentication")
            s["accounts"].append({"provider": "github", "id": me["login"], "kind": "bot" if me.get("type") == "Bot" else "human",
                                  "mfa": mfa, "mfa_methods": None, "admin": None, "created_at": me.get("created_at"),
                                  "last_active": None})
            if mfa is None:
                s["gaps"].append((f"identity-mfa:github/{user}",
                                  "the API does not tell 2FA status to this token (needs the `user` scope): attest instead"))
            else:
                s["covered"].append(f"identity-mfa:github/{user}")
            scopes = [x.strip() for x in g.headers.get("x-oauth-scopes", "").split(",") if x.strip()]
            kind = {"gho_": "oauth_token", "ghp_": "pat_classic", "github_pat_": "pat_fine_grained", "ghu_": "oauth_token"}.get(g.prefix, "token")
            meta = self.keyring("gh:github.com", user)
            s["credentials"].append({"store": "gh-keyring", "id": f"gh:{user}", "kind": kind, "location": "keyring",
                                     "scopes": scopes, "created_at": meta.get("created_at"), "updated_at": meta.get("updated_at"),
                                     "expires_at": g.headers.get("github-authentication-token-expiration"),
                                     "last_used": None, "notes": "age = keyring item creation (upper bound)"})
            st, orgs, err = g.get("/user/orgs")
            for o in orgs or []:
                if o["login"] in orgs_seen or (self.cfg.get("orgs") is not None and o["login"] not in self.cfg["orgs"]):
                    continue        # `orgs:` scopes the collection: other organisations (e.g. an employer's) are never read
                orgs_seen.add(o["login"])
                st, od, err = g.get(f"/orgs/{o['login']}")
                if od is None:
                    s["gaps"].append((f"org:github/{o['login']}", err))
                    continue
                st, outside, _ = g.get(f"/orgs/{o['login']}/outside_collaborators?per_page=100")
                st, members, _ = g.get(f"/orgs/{o['login']}/members?per_page=100")
                s["orgs"].append({"provider": "github", "id": o["login"], "mfa_required": od.get("two_factor_requirement_enabled"),
                                  "members": len(members or []), "outside_collaborators": len(outside or []) if outside is not None else None})
                s["covered"].append(f"org:github/{o['login']}")
                for m in members or []:
                    s["grants"].append({"provider": "github", "resource": f"org:github/{o['login']}", "principal": m["login"],
                                        "kind": "member", "permission": "member", "read_only": None})
            owner = self.cfg.get("repos_owner")
            if owner and not repos_done and user == self.cfg.get("repos_via", user):
                repos_done = True
                self.repos(g, owner, s)
        return s

    def repos(self, g, owner, s):
        st, repos, err = g.get("/user/repos?per_page=100&affiliation=owner")
        if repos is None:
            s["gaps"].append((f"repos:github/{owner}", err))
            return
        for r in repos:
            if r["owner"]["login"] != owner or r.get("archived") or r.get("disabled"):
                continue
            full, res = r["full_name"], f"repo:github/{r['full_name']}"
            st, collab, err = g.get(f"/repos/{full}/collaborators?affiliation=direct&per_page=100")
            if collab is None:
                s["gaps"].append((f"{res}/collaborators", err))
            else:
                s["covered"].append(f"{res}/collaborators")
                for c in collab:
                    perm = max((k for k, v in (c.get("permissions") or {}).items() if v),
                               key=["pull", "triage", "push", "maintain", "admin"].index, default="pull")
                    s["grants"].append({"provider": "github", "resource": res, "principal": c["login"], "kind": "collaborator",
                                        "permission": perm, "read_only": perm in ("pull", "triage")})
            st, keys, err = g.get(f"/repos/{full}/keys")
            for k in keys or []:
                s["grants"].append({"provider": "github", "resource": res, "principal": f"deploy-key/{k['title']}",
                                    "kind": "deploy_key", "permission": "read" if k["read_only"] else "write",
                                    "read_only": k["read_only"], "created_at": k.get("created_at"), "last_used": k.get("last_used")})
            if r.get("visibility") == "public":
                st, ap, err = g.get(f"/repos/{full}/actions/permissions/fork-pr-contributor-approval")
                if ap is not None:
                    s["policies"].append({"provider": "github", "resource": res, "name": "fork_pr_approval",
                                          "value": ap.get("approval_policy"), "public": True})


def keychain_meta(service, account):
    """macOS keychain item dates (attributes only: `security` without -g/-w never prints the secret)."""
    try:
        p = subprocess.run(["security", "find-generic-password", "-s", service, "-a", account], capture_output=True,
                           text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return {}
    out = {}
    for key, name in (("cdat", "created_at"), ("mdat", "updated_at")):
        m = re.search(rf'"{key}"<timedate>=\S+\s+"(\d{{14}})Z', p.stdout)
        if m:
            v = m.group(1)
            out[name] = f"{v[:4]}-{v[4:6]}-{v[6:8]}T{v[8:10]}:{v[10:12]}:{v[12:14]}Z"
    return out


# ---- Tailscale -------------------------------------------------------------------------------------------------------
class Tailscale:
    """cfg: {type: tailscale, tailnet: "-", oauth_client_id + oauth_client_secret_file (preferred: an OAuth client with
    read-only scopes devices:core:read, users:read, policy_file:read) | api_key_file}. Secret files must be mode 0600.
    With credentials: users, devices, ACL. Without: the local CLI's view (devices, key expiry); the ACL is a gap."""

    API = "https://api.tailscale.com/api/v2"

    def __init__(self, cfg, cache_dir=None, **_):
        self.cfg = cfg

    def _api(self, path, key):
        req = urllib.request.Request(f"{self.API}{path}", headers={"Authorization": f"Bearer {key}",
                                                                  "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())

    def _oauth_token(self, client_id, secret):
        """OAuth client credentials -> a short-lived access token with only the client's scopes (read-only:
        devices:core:read, users:read, policy_file:read). Preferred over an API key, which carries the user's rights."""
        import urllib.parse
        body = urllib.parse.urlencode({"client_id": client_id, "client_secret": secret}).encode()
        req = urllib.request.Request(f"{self.API}/oauth/token", data=body,
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())["access_token"]

    def collect(self):
        s = snapshot()
        kf = self.cfg.get("oauth_client_secret_file") or self.cfg.get("api_key_file")
        key = None
        if kf:
            p = os.path.expanduser(kf)
            if not os.path.exists(p):
                s["gaps"].append(("identity-provider:tailscale", f"{os.path.basename(kf)} missing"))
            elif os.stat(p).st_mode & 0o077:
                s["gaps"].append(("identity-provider:tailscale", f"{os.path.basename(kf)} must be mode 0600 (refused)"))
            elif self.cfg.get("oauth_client_secret_file"):
                try:
                    key = self._oauth_token(self.cfg["oauth_client_id"], open(p).read().strip())
                except Exception as e:  # noqa: BLE001 - revoked client / offline: a gap
                    s["gaps"].append(("identity-provider:tailscale", f"OAuth token exchange: {type(e).__name__}"))
            else:
                key = open(p).read().strip()
        if key:
            tn = self.cfg.get("tailnet", "-")
            try:
                devs = self._api(f"/tailnet/{tn}/devices?fields=all", key).get("devices", [])
                users = self._api(f"/tailnet/{tn}/users", key).get("users", [])
                acl = self._api(f"/tailnet/{tn}/acl", key)
            except Exception as e:  # noqa: BLE001 - offline / revoked key: a gap, not a crash
                s["gaps"].append(("identity-provider:tailscale", f"API: {type(e).__name__}: {str(e)[:120]}"))
                return self.cli(s)
            s["covered"].append("identity-provider:tailscale")
            for u in users:
                s["accounts"].append({"provider": "tailscale", "id": u.get("loginName"), "kind": "human",
                                      "mfa": None, "mfa_methods": None, "admin": u.get("role") in ("owner", "admin"),
                                      "created_at": u.get("created"), "last_active": u.get("lastSeen")})
            for d in devs:
                s["credentials"].append({"store": "tailscale", "id": f"device/{d.get('hostname')}", "kind": "device_key",
                                         "location": "tailnet", "scopes": None, "created_at": d.get("created"),
                                         "expires_at": None if d.get("keyExpiryDisabled") else d.get("expires"),
                                         "last_used": d.get("lastSeen"), "notes": "key expiry disabled" if d.get("keyExpiryDisabled") else ""})
            s["policies"].append({"provider": "tailscale", "resource": "identity-provider:tailscale", "name": "acl_allow_all",
                                  "value": acl_allows_all(acl), "public": False})
            return s
        if not kf:
            s["gaps"].append(("identity-provider:tailscale", "no read-only API key configured: ACL and users cannot be checked"))
        return self.cli(s)

    def cli(self, s):
        try:
            st = json.loads(subprocess.run(["tailscale", "status", "--json"], capture_output=True, text=True, timeout=30).stdout)
        except (OSError, ValueError, subprocess.SubprocessError) as e:
            s["gaps"].append(("identity-devices:tailscale", f"tailscale CLI: {type(e).__name__}"))
            return s
        s["covered"].append("identity-devices:tailscale")
        for p in list((st.get("Peer") or {}).values()):
            s["credentials"].append({"store": "tailscale", "id": f"device/{p.get('HostName')}", "kind": "device_key",
                                     "location": "tailnet", "scopes": None, "created_at": p.get("Created"),
                                     "expires_at": p.get("KeyExpiry"), "last_used": p.get("LastSeen") if not p.get("Online") else iso(time.time()),
                                     "notes": "" if p.get("KeyExpiry") else "key expiry disabled"})
        return s


def acl_allows_all(acl):
    """True when any ACL/grant rule lets every source reach every destination (the default policy)."""
    for r in (acl.get("acls") or []):
        if r.get("action") == "accept" and "*" in (r.get("src") or []) and any(d.startswith("*:") or d == "*" for d in (r.get("dst") or [])):
            return True
    for g in (acl.get("grants") or []):
        if "*" in (g.get("src") or []) and "*" in (g.get("dst") or []):
            return True
    return False


# ---- interface-only providers ----------------------------------------------------------------------------------------
class Future:
    def __init__(self, cfg, **_):
        self.cfg = cfg

    def collect(self):
        raise NotImplementedError(f"identity provider {self.cfg.get('type')!r} is a documented interface, not implemented")


PROVIDERS = {"github": GitHub, "tailscale": Tailscale, "google-workspace": Future, "okta": Future, "entra": Future,
             "gitlab": Future}


def provider(cfg, cache_dir=None):
    return PROVIDERS[cfg["type"]](cfg, cache_dir=cache_dir)


# ---- local credential stores -------------------------------------------------------------------------------------------
def _expand(paths):
    out = []
    for p in paths or []:
        out += sorted(glob.glob(os.path.expanduser(p)))
    return out


def _excluded(p, excl):
    return any(os.path.abspath(p) == x or os.path.abspath(p).startswith(x + os.sep) for x in excl)


def cert_not_after(pem_b64):
    """Expiry of a PUBLIC certificate (openssl); the private key is never touched."""
    try:
        pem = base64.b64decode(pem_b64)
        p = subprocess.run(["openssl", "x509", "-noout", "-enddate", "-subject"], input=pem, capture_output=True, timeout=10)
        out = p.stdout.decode()
        m = re.search(r"notAfter=(.+)", out)
        exp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.strptime(m.group(1).strip(), "%b %d %H:%M:%S %Y %Z")) if m else None
        org = re.findall(r"O ?= ?([^,/\n]+)", out)
        return exp, [o.strip() for o in org]
    except (OSError, ValueError, subprocess.SubprocessError):
        return None, []


def local_credentials(cfg):
    """cfg: {kubeconfigs: [globs], ssh_dirs: [dirs], docker_configs: [files], token_files: [globs], exclude: [paths]}.
    Metadata only: names, kinds, scopes/groups, file ages and modes, certificate expiry. Values are never returned."""
    s = snapshot()
    excl = [os.path.abspath(os.path.expanduser(x)) for x in cfg.get("exclude", [])]
    for p in _expand(cfg.get("kubeconfigs")):
        if _excluded(p, excl) or os.path.isdir(p):
            continue
        try:
            import yaml
            kc = yaml.safe_load(open(p)) or {}
        except Exception as e:  # noqa: BLE001 - unreadable file = gap
            s["gaps"].append((f"credential-store:{p}", f"{type(e).__name__}"))
            continue
        s["covered"].append(f"credential-store:{p}")
        st = os.stat(p)
        for u in kc.get("users") or []:
            uu = u.get("user") or {}
            base = {"store": "kubeconfig", "location": p, "scopes": None, "created_at": iso(st.st_mtime), "last_used": None,
                    "mode": oct(st.st_mode & 0o777)}
            if uu.get("client-certificate-data"):
                exp, groups = cert_not_after(uu["client-certificate-data"])
                s["credentials"].append(dict(base, id=f"kube:{os.path.basename(p)}/{u.get('name')}", kind="kube_client_cert",
                                             expires_at=exp, scopes=groups, notes="groups = certificate O"))
            elif uu.get("token") or uu.get("tokenFile"):
                s["credentials"].append(dict(base, id=f"kube:{os.path.basename(p)}/{u.get('name')}", kind="kube_token",
                                             expires_at=None, notes="static bearer token"))
            elif uu.get("exec"):
                s["credentials"].append(dict(base, id=f"kube:{os.path.basename(p)}/{u.get('name')}", kind="kube_exec",
                                             expires_at=None, notes=f"exec plugin {os.path.basename(str(uu['exec'].get('command')))}"))
    for d in _expand(cfg.get("ssh_dirs")):
        for pub in sorted(glob.glob(os.path.join(d, "*.pub"))):
            key = pub[:-4]
            if not os.path.exists(key) or _excluded(key, excl):
                continue
            st = os.stat(key)
            kt = (open(pub).read().split() or ["?"])[0]
            s["credentials"].append({"store": "ssh", "id": f"ssh:{os.path.basename(key)}", "kind": "ssh_key", "location": key,
                                     "scopes": [kt], "created_at": iso(st.st_mtime), "expires_at": None, "last_used": None,
                                     "mode": oct(st.st_mode & 0o777), "notes": "age = file mtime"})
        s["covered"].append(f"credential-store:{d}")
    for p in _expand(cfg.get("docker_configs")):
        if _excluded(p, excl):
            continue
        try:
            dc = json.load(open(p))
        except ValueError:
            continue
        s["covered"].append(f"credential-store:{p}")
        skip = set(cfg.get("exclude_registries", []))
        for host, a in sorted((dc.get("auths") or {}).items()):
            if host in skip:
                continue
            s["credentials"].append({"store": "docker", "id": f"registry:{host}", "kind": "registry", "location": p,
                                     "scopes": None, "created_at": iso(os.stat(p).st_mtime), "expires_at": None,
                                     "last_used": None, "notes": "inline auth in file" if (a or {}).get("auth") else f"credsStore {dc.get('credsStore')}"})
    for p in _expand(cfg.get("token_files")):
        if _excluded(p, excl) or os.path.isdir(p):
            continue
        st = os.stat(p)
        s["credentials"].append({"store": "file", "id": f"file:{os.path.basename(p)}", "kind": "token_file", "location": p,
                                 "scopes": None, "created_at": iso(st.st_mtime), "expires_at": None, "last_used": None,
                                 "mode": oct(st.st_mode & 0o777), "notes": "age = file mtime"})
    return s
