"""Conformance cases of the `identity` collector (collector-protocol/1.0, findings/1.2). Imported by gen_cases.py, which
passes its helpers (write_case, collector_env, protocol_checks).

The code host and the overlay network are one local mock (fakes/mock_api.py). The Python collector reaches the code host
through the GitHub CLI: a fake `gh` on PATH (fakes/fake_gh.py) forwards its `gh api` calls to the mock; the Go collector
calls the mock directly (`api_url`). The macOS keychain (`security`) and the `tailscale` CLI are fakes too, so no case
ever reads the real machine. Cases that configure an overlay-network API key set a dead proxy, so the Python collector
(which always calls the vendor's host) can never reach a real service."""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
C = "collector-protocol/1.0 / findings/1.2"
GH_CANARY = "conformanceCanary"                 # inside the code-host token the fakes build at run time
KUBE_CANARY = "kube-conformance-token-canary-51aa"
DOCKER_CANARY = "docker-conformance-auth-canary-2f0e"
KEY_CANARY = "PRIVATE-KEY-CANARY-77c1"
FILE_CANARY = "token-file-canary-0b3d"
TS_KEY = "ts-conformance-api-key-canary-4b2e"
TS_SECRET = "ts-conformance-oauth-secret-canary-9a3c"
CANARIES = [GH_CANARY, KUBE_CANARY, DOCKER_CANARY, KEY_CANARY, FILE_CANARY, TS_KEY, TS_SECRET,
            "ts-conformance-access-canary-1c4f"]
# a public certificate (no key): O=system:masters, O=dev-team, CN=admin, valid 2020-01-01 .. 2021-01-01
CERT_B64 = ("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJyRENDQVZLZ0F3SUJBZ0lVV3E5aFRnL1VuRU1XZmY3R2cycE5WYzNXOUt3"
            "d0NnWUlLb1pJemowRUF3SXcKUERFWE1CVUdBMVVFQ2d3T2MzbHpkR1Z0T20xaGMzUmxjbk14RVRBUEJnTlZCQW9NQ0dSbGRpMTBa"
            "V0Z0TVE0dwpEQVlEVlFRRERBVmhaRzFwYmpBZUZ3MHlNREF4TURFd01EQXdNREJhRncweU1UQXhNREV3TURBd01EQmFNRHd4CkZ6"
            "QVZCZ05WQkFvTURuTjVjM1JsYlRwdFlYTjBaWEp6TVJFd0R3WURWUVFLREFoa1pYWXRkR1ZoYlRFT01Bd0cKQTFVRUF3d0ZZV1J0"
            "YVc0d1dUQVRCZ2NxaGtqT1BRSUJCZ2dxaGtqT1BRTUJCd05DQUFUN3c2MnU2b2JucXdBMgpSaUQ1eEI3VkF3Y1MyK0hmUFhXS3BY"
            "a3FCUUo5WjBCZG83eFFjWnZZTXQrc3ppYnN3M2VxOC9BenNlUFhkRE5kCmwxdmc4NFRxb3pJd01EQWRCZ05WSFE0RUZnUVUvdS80"
            "aWNBbHEySmhLa2ZVdUtEZ3UwQU9VWU13RHdZRFZSMFQKQVFIL0JBVXdBd0VCL3pBS0JnZ3Foa2pPUFFRREFnTklBREJGQWlFQThE"
            "WVJBK2ZwNDNzVkZwb2ZuUlJxQjBVUwpsTU9uWHVCVkdyVmtTOXJHZElJQ0lGbFI0WVBub3ZOUnJ6MzdYZm9DY28rcEFJcTBlTXlB"
            "YlBlWVVUMlVxNHNUCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K")
DEAD_PROXY = {k: "http://127.0.0.1:9" for k in ("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY")}
READ_ONLY = r"^(?!GET |POST /api/v2/oauth/token |$)"
KEYCHAIN = ('keychain: "/fake.keychain-db"\nattributes:\n'
            '    "cdat"<timedate>=0x32303230303130313030303030305A00  "20200101000000Z\\000"\n'
            '    "mdat"<timedate>=0x32303231303130313030303030305A00  "20210101000000Z\\000"\n')


def fake(name):
    return open(os.path.join(HERE, "fakes", name)).read()


def gh_routes(**override):
    """The code host as the account octo sees it (one page each unless a case paginates)."""
    r = {
        "/user": {"body": {"login": "octo", "id": 1, "type": "User", "two_factor_authentication": None,
                           "created_at": "2019-05-01T00:00:00Z"}},
        "/user/orgs": {"body": [{"login": "acme"}, {"login": "elsewhere"}]},
        "/orgs/acme": {"body": {"login": "acme", "two_factor_requirement_enabled": False}},
        "/orgs/acme/outside_collaborators?per_page=100": {"body": [{"login": "ext"}]},
        "/orgs/acme/members?per_page=100": {"body": [{"login": "octo"}, {"login": "dana"}]},
        "/orgs/acme/members?filter=2fa_disabled&per_page=100": {"body": []},
        "/user/repos?per_page=100&affiliation=owner": {"body": [
            {"full_name": "octo/app", "owner": {"login": "octo"}, "visibility": "public"},
            {"full_name": "octo/notes", "owner": {"login": "octo"}, "visibility": "private"},
            {"full_name": "octo/old", "owner": {"login": "octo"}, "visibility": "public", "archived": True},
            {"full_name": "other/x", "owner": {"login": "other"}, "visibility": "public"}]},
        "/repos/octo/app/collaborators?affiliation=direct&per_page=100": {"body": [
            {"login": "octo", "permissions": {"admin": True, "maintain": True, "push": True, "triage": True, "pull": True}},
            {"login": "mallory", "permissions": {"admin": False, "push": True, "pull": True}}]},
        "/repos/octo/app/keys": {"body": [
            {"id": 7, "title": "ci", "read_only": False, "created_at": "2020-01-01T00:00:00Z", "last_used": None},
            {"id": 8, "title": "mirror", "read_only": True, "created_at": "2024-03-01T10:00:00Z", "last_used": "2099-01-01T00:00:00Z"}]},
        "/repos/octo/app/actions/permissions/fork-pr-contributor-approval": {"body": {"approval_policy": "first_time_contributors"}},
        "/repos/octo/notes/collaborators?affiliation=direct&per_page=100": {"body": [
            {"login": "octo", "permissions": {"admin": True, "pull": True}},
            {"login": "viewer", "permissions": {"admin": False, "push": False, "pull": True}}]},
        "/repos/octo/notes/keys": {"body": []}}
    r.update(override)
    return {"scopes": "repo, read:org", "page_size": 2, "routes": r}


def tailscale_status():
    return {"BackendState": "Running", "Self": {"HostName": "this-host", "Online": True}, "Peer": {
        "nodekey:a1": {"HostName": "old-laptop", "Created": "2020-01-01T00:00:00Z", "KeyExpiry": "2021-01-01T00:00:00Z",
                       "LastSeen": "2020-06-01T00:00:00Z", "Online": False},
        "nodekey:b2": {"HostName": "phone", "Created": "{utc:-864000}", "KeyExpiry": "{utc:+259200}",
                       "LastSeen": "{utc:-3600}", "Online": True},
        "nodekey:c3": {"HostName": "server", "Created": "{utc:-8640000}", "LastSeen": "{utc:-60}", "Online": True}}}


def kubeconfig():
    return ("apiVersion: v1\nkind: Config\nusers:\n"
            "- name: admin\n  user:\n    client-certificate-data: " + CERT_B64 + "\n    client-key-data: " + KEY_CANARY + "\n"
            "- name: ci\n  user:\n    token: " + KUBE_CANARY + "\n"
            "- name: sso\n  user:\n    exec:\n      apiVersion: client.authentication.k8s.io/v1\n"
            "      command: /usr/local/bin/kubelogin\n      args: [get-token]\n")


def base_files(extra=None):
    f = {"instance.json": "instance.json", "data/.keep": {"text": ""},
         "bin/gh": {"text": "#!/bin/sh\nexec \"{python}\" \"{case}/fake_gh.py\" \"$@\"\n", "mode": "0755"},
         "bin/security": {"text": "#!/bin/sh\n# fake macOS keychain: attributes only (a fixed creation date), never a secret\n"
                                  "cat \"{case}/keychain.txt\"\n", "mode": "0755"},
         "bin/tailscale": {"text": "#!/bin/sh\n[ \"$1 $2\" = \"status --json\" ] || { echo \"fake tailscale: $*\" >&2; exit 1; }\n"
                                   "cat \"{sandbox}/tailscale-status.json\"\n", "mode": "0755"},
         "tailscale-status.json": "tailscale-status.json"}
    f.update(extra or {})
    return f


def env(h, extra=None):
    return h.collector_env(dict({"PATH": "{sandbox}/bin:{path}", "FAKE_GH_URL": "{svc_api}",
                                 "FAKE_GH_LOG": "{sandbox}/.svc-gh.calls"}, **(extra or {})))


def service():
    return [{"name": "api", "argv": ["{python}", "{case}/mock_api.py", "--data", "{case}/api.json",
                                     "--log", "{sandbox}/.svc-api.calls"]}]


def github(**kw):
    return dict({"type": "github", "api_url": "{svc_api}", "accounts": [{"gh_user": "octo"}], "orgs": ["acme"],
                 "repos_owner": "octo", "expected_collaborators": ["octo"]}, **kw)


def case_files(api, inst, status=None):
    return {"instance.json": inst, "api.json": api, "fake_gh.py": fake("fake_gh.py"), "mock_api.py": fake("mock_api.py"),
            "tailscale-status.json": status or {"Peer": {}}, "keychain.txt": KEYCHAIN}


def read_only():
    return {"file": ".svc-api.calls", "not_regex": [READ_ONLY]}


def cases(h):
    people_case(h)
    deviation_cases(h)


def people_case(h):
    home = "{sandbox}/home"
    inst = {"name": "conformance", "identity": {
        "providers": [github(), {"type": "tailscale"}, {"type": "google-workspace"}],
        "credentials": {"kubeconfigs": [home + "/.kube/*.yaml"], "ssh_dirs": [home + "/.ssh"],
                        "docker_configs": [home + "/.docker/config.json"], "token_files": [home + "/.config/sp/*.token"],
                        "exclude": [home + "/.ssh/work_key", home + "/.kube/excluded.yaml"],
                        "exclude_registries": ["skip.example"]}}}
    files = base_files({
        "home/.kube/config.yaml": {"text": kubeconfig(), "mode": "0600"},
        "home/.kube/excluded.yaml": {"text": "users:\n- name: x\n  user: {token: " + KUBE_CANARY + "}\n", "mode": "0600"},
        "home/.ssh/id_ed25519": {"text": KEY_CANARY + "\n", "mode": "0600"},
        "home/.ssh/id_ed25519.pub": {"text": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIconformance octo@laptop\n", "mode": "0644"},
        "home/.ssh/id_rsa_nopub": {"text": KEY_CANARY + "\n", "mode": "0600"},
        "home/.ssh/work_key": {"text": KEY_CANARY + "\n", "mode": "0600"},
        "home/.ssh/work_key.pub": {"text": "ssh-rsa AAAAB3conformance work\n", "mode": "0644"},
        "home/.docker/config.json": {"json": {"auths": {"registry.example": {"auth": DOCKER_CANARY}, "skip.example": {},
                                                        "ghcr.example": {}}, "credsStore": "desktop"}, "mode": "0600"},
        "home/.config/sp/a.token": {"text": FILE_CANARY + "\n", "mode": "0644"},
        "home/.config/sp/b.token": {"text": FILE_CANARY + "\n", "mode": "0600"}})
    F = "run/identity.findings.json"
    findings = [
        {"check": "identity.org_mfa_not_required", "asset": "org:github/acme", "severity": "medium", "needs_human": True,
         "owner": "human", "evidence": "raw/identity/inventory.json", "title": "organisation acme does not require 2FA of its members"},
        {"check": "identity.collaborator_unexpected", "asset": "repo:github/octo/app/collaborator/mallory", "severity": "high",
         "title": "mallory has push access to github/octo/app and is not in the expected list"},
        {"check": "identity.collaborator_unexpected", "asset": "repo:github/octo/notes/collaborator/viewer", "severity": "medium"},
        {"check": "identity.deploy_key_unused", "asset": "repo:github/octo/app/deploy-key/ci", "severity": "low",
         "title": "deploy key ci (write) not used for 180 days (or never)"},
        {"check": "identity.fork_pr_approval_weak", "asset": "repo:github/octo/app", "severity": "low", "needs_human": False},
        {"check": "identity.token_age_over_90d", "asset": "credential:gh-keyring/gh:octo", "severity": "medium",
         "title": {"$regex": "^oauth_token gh:octo is [0-9]+ days old \\(rotate every 90 days\\)$"}},
        {"check": "identity.token_classic_full_repo", "asset": "credential:gh-keyring/gh:octo", "severity": "medium"},
        {"check": "identity.credential_expired", "asset": "credential:tailscale/device/old-laptop", "severity": "low",
         "title": "device_key device/old-laptop expired 2021-01-01 and is still configured"},
        {"check": "identity.overlay_device_dormant", "asset": "credential:tailscale/device/old-laptop", "severity": "low"},
        {"check": "identity.token_expiring_soon", "asset": "credential:tailscale/device/phone", "severity": "medium"},
        {"check": "identity.credential_expired", "asset": "credential:kubeconfig/kube:config.yaml/admin", "severity": "low",
         "title": "kube_client_cert kube:config.yaml/admin expired 2021-01-01 and is still configured"},
        {"check": "identity.credential_file_readable", "asset": "credential:file/file:a.token", "severity": "high",
         "title": "file:a.token file is readable by others (0o644)"}]
    cov = [{"asset": "identity-mfa:github/octo", "status": "gap", "reason": {"$regex": "user` scope"}},
           {"asset": "identity:github/octo", "status": "ok"}, {"asset": "org:github/acme", "status": "ok"},
           {"asset": "repo:github/octo/app/collaborators", "status": "ok"},
           {"asset": "repo:github/octo/notes/collaborators", "status": "ok"},
           {"asset": "identity-provider:tailscale", "status": "gap", "reason": {"$regex": "no read-only API key"}},
           {"asset": "identity-devices:tailscale", "status": "ok"},
           {"asset": "identity-provider:google-workspace", "status": "gap",
            "reason": "identity provider 'google-workspace' is a documented interface, not implemented"},
           {"asset": {"$regex": "^credential-store:.*/home/.kube/config.yaml$"}, "status": "ok"},
           {"asset": {"$regex": "^credential-store:.*/home/.ssh$"}, "status": "ok"},
           {"asset": {"$regex": "^credential-store:.*/home/.docker/config.json$"}, "status": "ok"}]
    inv_creds = [
        {"store": "gh-keyring", "id": "gh:octo", "kind": "oauth_token", "scopes": ["repo", "read:org"],
         "created_at": "2020-01-01T00:00:00Z", "updated_at": "2021-01-01T00:00:00Z", "location": "keyring"},
        {"id": "device/old-laptop", "kind": "device_key", "expires_at": "2021-01-01T00:00:00Z"},
        {"id": "device/phone"}, {"id": "device/server", "expires_at": None, "notes": "key expiry disabled"},
        {"id": "kube:config.yaml/admin", "kind": "kube_client_cert", "expires_at": "2021-01-01T00:00:00Z",
         "scopes": ["system:masters", "dev-team"], "mode": "0o600", "notes": "groups = certificate O"},
        {"id": "kube:config.yaml/ci", "kind": "kube_token", "notes": "static bearer token"},
        {"id": "kube:config.yaml/sso", "kind": "kube_exec", "notes": "exec plugin kubelogin"},
        {"id": "ssh:id_ed25519", "kind": "ssh_key", "scopes": ["ssh-ed25519"], "mode": "0o600"},
        {"id": "registry:ghcr.example", "kind": "registry", "notes": "credsStore desktop"},
        {"id": "registry:registry.example", "notes": "inline auth in file"},
        {"id": "file:a.token", "kind": "token_file", "mode": "0o644", "age_days": {"$type": "number"}},
        {"id": "file:b.token", "mode": "0o600"}]
    metrics = [{"name": "security_identity_credentials", "labels": {"kind": "device_key"}, "value": 3},
               {"name": "security_identity_credentials", "labels": {"kind": "registry"}, "value": 2},
               {"name": "security_identity_credentials", "labels": {"kind": "token_file"}, "value": 2},
               {"name": "security_identity_accounts", "value": 1}, {"name": "security_identity_mfa_unknown", "value": 1},
               {"name": "security_identity_grants", "value": 8},
               {"name": "security_collector_gaps", "labels": {"collector": "identity"}, "value": 3}]
    expect = h.protocol_checks("identity", canaries=CANARIES) + [
        {"json": F, "subset": {"collector": {"tools": {"identity-adapter": "0.2.0"}}, "coverage": cov,
                               "findings": {"$unordered": findings}}},
        {"json": "run/raw/identity/inventory.json", "subset": {
            "accounts": [{"provider": "github", "id": "octo", "kind": "human", "mfa": None, "created_at": "2019-05-01T00:00:00Z"}],
            "orgs": [{"provider": "github", "id": "acme", "mfa_required": False, "members": 2, "outside_collaborators": 1}],
            "grants": {"$len": 8}, "policies": [{"name": "fork_pr_approval", "value": "first_time_contributors", "public": True}],
            "credentials": inv_creds}},
        {"prom": "run/identity.prom", "has": metrics}, read_only(),
        {"file": ".svc-api.calls", "not_regex": ["elsewhere", "other/x", "octo/old"]},
        {"file": ".svc-gh.calls", "not_regex": [GH_CANARY]}]
    h.write_case("collector-identity", "people-pillar-across-providers", {
        "title": "Code host (2FA unknown, org 2FA policy, unexpected collaborators, unused deploy keys, fork-PR approval, the "
                 "token's age and scopes), overlay-network devices through the local CLI (expired, expiring, dormant), an "
                 "interface-only provider, local credential stores (kubeconfig certificate expiry and groups, static and exec "
                 "users, SSH keys, registry logins, token files and their modes): metadata only, read-only calls, no secret "
                 "value in any output; the second run revalidates every cached answer with its ETag",
        "contract": C, "origin": "collectors/identity/collector.py; tests/test_identity.py",
        "services": service(), "files": files,
        "steps": [{"name": "collect", "exec": {"impl": "collector-identity", "env": env(h), "writes_only_under": ["run", "data/cache"]},
                   "expect": expect},
                  {"name": "collect again: conditional requests, same document", "remove": ["run"],
                   "exec": {"impl": "collector-identity", "env": env(h), "writes_only_under": ["run", "data/cache"]},
                   "expect": h.protocol_checks("identity", canaries=CANARIES) + [
                       {"json": F, "subset": {"findings": {"$unordered": findings}}},
                       {"file": ".svc-api.calls", "regex": [r"^GET /user auth=yes inm=yes$",
                                                            r"^GET /repos/octo/app/keys auth=yes inm=yes$"]}]}]},
        case_files(gh_routes(), inst, tailscale_status()))


def gh_case(h, name, title, deviation, origin, api, expect, providers=None, extra_env=None, status=None):
    inst = {"name": "conformance", "identity": {"providers": providers or [github()]}}
    h.write_case("collector-identity", name, {
        "title": title, "contract": C, "deviation": deviation, "origin": origin, "services": service(), "files": base_files(
            {"home/.config/ts/api.key": {"text": TS_KEY + "\n", "mode": "0600"},
             "home/.config/ts/oauth.secret": {"text": TS_SECRET + "\n", "mode": "0600"}}),
        "steps": [{"name": "collect", "exec": {"impl": "collector-identity", "env": env(h, extra_env),
                                               "writes_only_under": ["run", "data/cache"]},
                   "expect": h.protocol_checks("identity", canaries=CANARIES) + expect + [read_only()]}]},
        case_files(api, inst, status))


def deviation_cases(h):
    """Target behaviour the Python collector does not have (contracts/collector-protocol/SPEC.md, Known deviations)."""
    F = "run/identity.findings.json"
    collabs = [{"login": n, "permissions": {"push": n != "octo", "admin": n == "octo", "pull": True}}
               for n in ("octo", "a1", "a2", "a3", "mallory")]
    members = [{"login": n} for n in ("octo", "m1", "m2", "m3", "m4")]
    api = gh_routes(**{
        "/repos/octo/app/collaborators?affiliation=direct&per_page=100": {"body": collabs, "paginate": True},
        "/orgs/acme/members?per_page=100": {"body": members, "paginate": True}})
    gh_case(h, "pagination-is-followed",
            "Listings longer than one page (the server's page size, whatever per_page asked for) are read to the end through "
            "the Link header: a collaborator on the last page is reported, every member counted",
            "IDENTITY-D1", "only the first page (100 entries) of every listing was read", api, [
                {"json": F, "subset": {"findings": {"$contains": [
                    {"check": "identity.collaborator_unexpected", "asset": "repo:github/octo/app/collaborator/mallory"},
                    {"check": "identity.collaborator_unexpected", "asset": "repo:github/octo/app/collaborator/a3"}]}}},
                {"json": "run/raw/identity/inventory.json", "subset": {"orgs": [{"id": "acme", "members": 5}]}},
                {"file": ".svc-api.calls", "regex": [r"^GET /orgs/acme/members\?per_page=100&page=3 auth=yes"]}])

    denied = {"status": 403, "body": {"message": "Must have admin rights to Repository."},
              "headers": {"X-Accepted-OAuth-Scopes": "admin:org"}}
    api = gh_routes(**{
        "/orgs/acme/outside_collaborators?per_page=100": denied,
        "/orgs/acme/members?per_page=100": {"status": 403, "body": {"message": "Resource not accessible"},
                                            "headers": {"X-Accepted-OAuth-Scopes": "read:org"}},
        "/orgs/acme/members?filter=2fa_disabled&per_page=100": {"status": 403, "body": {"message": "Must be an owner"}},
        "/repos/octo/app/keys": {"status": 404, "body": {"message": "Not Found"}},
        "/repos/octo/app/actions/permissions/fork-pr-contributor-approval": {"status": 403, "body": {"message": "Forbidden"}}})
    gh_case(h, "unreadable-listings-are-gaps",
            "A listing the token may not read (members, outside collaborators, deploy keys, the fork-PR approval policy) is "
            "a gap of that part, naming the scope the API asks for; never silently an empty list",
            "IDENTITY-D2", "errors of these listings were dropped: no members, no deploy keys, no policy, no gap", api, [
                {"json": F, "subset": {"coverage": {"$contains": [
                    {"asset": "org:github/acme", "status": "ok"},
                    {"asset": "org:github/acme/members", "status": "gap", "reason": {"$regex": "HTTP 403.*read:org"}},
                    {"asset": "org:github/acme/outside_collaborators", "status": "gap", "reason": {"$regex": "HTTP 403.*admin:org"}},
                    {"asset": "org:github/acme/members-2fa", "status": "gap", "reason": {"$regex": "HTTP 403"}},
                    {"asset": "repo:github/octo/app/deploy-key", "status": "gap", "reason": {"$regex": "HTTP 404"}},
                    {"asset": "repo:github/octo/app/actions", "status": "gap", "checks": ["identity.fork_pr_approval_weak"]}]},
                    "findings": {"$not_contains": [{"check": "identity.deploy_key_unused"}]}}},
                {"json": "run/raw/identity/inventory.json", "subset": {"orgs": [{"id": "acme", "members": None,
                                                                                  "outside_collaborators": None}]}}])

    api = gh_routes(**{"/user/orgs": {"rate_limited": True}})
    gh_case(h, "rate-limit-is-a-gap-until-reset",
            "A rate-limited answer is a gap naming when the limit resets, and the collector stops calling the API for that "
            "account (the organisations and repositories it could not read are gaps, not an empty list)",
            "IDENTITY-D3", "a rate-limited organisation listing read as `no organisations`, later calls kept failing", api, [
                {"json": F, "subset": {"coverage": {"$contains": [
                    {"asset": "identity:github/octo", "status": "ok"},
                    {"asset": "orgs:github/octo", "status": "gap", "reason": {"$regex": "rate limited until 2100-01-01T00:00:00Z"}},
                    {"asset": "repos:github/octo", "status": "gap", "reason": {"$regex": "rate limited until 2100-01-01T00:00:00Z"}}]}}},
                {"file": ".svc-api.calls", "not_regex": [r"^GET /user/repos", r"^GET /orgs/"]}])

    api = gh_routes(**{"/orgs/acme/members?filter=2fa_disabled&per_page=100": {"body": [{"login": "dana"}]}})
    gh_case(h, "org-members-without-2fa",
            "Where the API tells (an organisation owner's token), members without two-factor authentication are reported "
            "as accounts without 2FA",
            "IDENTITY-D4", "members' 2FA was never read, only the token owner's own", api, [
                {"json": F, "subset": {"findings": {"$contains": [
                    {"check": "identity.mfa_disabled", "asset": "identity:github/dana", "severity": "high",
                     "title": "github account dana has no two-factor authentication"}]}}},
                {"prom": "run/identity.prom", "has": [{"name": "security_identity_accounts", "value": 2}]}])

    ts = {"/api/v2/tailnet/-/devices": {"body": {"devices": [
              {"hostname": "build", "created": "2020-01-01T00:00:00Z", "expires": "2021-01-01T00:00:00Z",
               "lastSeen": "2020-02-01T00:00:00Z", "keyExpiryDisabled": False},
              {"hostname": "nas", "created": "2024-01-01T00:00:00Z", "keyExpiryDisabled": True, "lastSeen": "2099-01-01T00:00:00Z"}]}},
          "/api/v2/tailnet/-/users": {"body": {"users": [{"loginName": "octo@example.com", "role": "owner", "created": "2020-01-01T00:00:00Z"}]}},
          "/api/v2/tailnet/-/acl": {"body": {"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}}}
    api = {"routes": ts, "tailscale_key": TS_KEY, "tailscale_oauth_secret": TS_SECRET}
    tsapi = "{svc_api}/api/v2"
    expect = [{"json": F, "subset": {
        "coverage": {"$contains": [{"asset": "identity-provider:tailscale", "status": "ok"}]},
        "findings": {"$contains": [
            {"check": "identity.overlay_acl_allow_all", "asset": "identity-provider:tailscale", "severity": "high"},
            {"check": "identity.credential_expired", "asset": "credential:tailscale/device/build"}]}}},
        {"json": "run/raw/identity/inventory.json", "subset": {"accounts": {"$contains": [
            {"provider": "tailscale", "id": "octo@example.com", "admin": True}]}}}]
    gh_case(h, "overlay-network-api",
            "The overlay network's API (a read-only key or an OAuth client, from 0600 files) gives users, devices and the "
            "ACL: an allow-all policy is reported. The API base is configurable (`api_url`), as for the code host",
            "IDENTITY-D5", "the API base was fixed to the vendor's host: no mirror, proxy or test endpoint", api,
            expect + [{"file": ".svc-api.calls", "regex": [r"^GET /api/v2/tailnet/-/acl auth=yes"]}],
            providers=[{"type": "tailscale", "api_url": tsapi, "api_key_file": "{sandbox}/home/.config/ts/api.key"},
                       {"type": "tailscale", "api_url": tsapi, "oauth_client_id": "cid",
                        "oauth_client_secret_file": "{sandbox}/home/.config/ts/oauth.secret"}],
            extra_env=DEAD_PROXY)
