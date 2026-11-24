#!/usr/bin/env python3
"""Collector `codehost-gitea`: repository posture on a Gitea or Forgejo server via its REST API, READ-ONLY. Stdlib.

Instance config:
  codehost: [{type: gitea, url: https://git.example.com, owner: <org or user>, token_file: <0600 file>,
              ca_file?: <PEM>, include_private?: true}]
`type: forgejo` is accepted too (same API). The token needs read access only (Gitea scopes `read:repository`,
`read:organization`, `read:user`). It is read from a file that must be mode 0600, sent only as an HTTP header and
never logged. Entries of another `type` are ignored (another collector handles them).

Check names are the same as the GitHub collector's where the meaning is the same, so SLIs and dashboards work for
either code host: repo.default_branch_unprotected, repo.deploy_key_write. Gitea-specific: repo.protection_no_approvals
(the default branch is protected but merges need no approving review), repo.mirror_unverified_remote (a pull mirror
fetched over plain http).
"""
import json
import os
import ssl
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(__file__)
ROOT = os.path.join(HERE, "..", "..")
sys.path[:0] = [os.path.join(ROOT, "sdk"), ROOT]
import spsdk  # noqa: E402

VERSION = open(os.path.join(HERE, "VERSION")).read().strip()
TYPES = ("gitea", "forgejo")


def read_token(path):
    p = os.path.expanduser(path)
    if stat.S_IMODE(os.stat(p).st_mode) & 0o077:
        raise PermissionError(f"{path} must be mode 0600")
    return open(p).read().strip()


class API:
    def __init__(self, cfg):
        self.base = cfg["url"].rstrip("/") + "/api/v1"
        self.tok = read_token(cfg["token_file"]) if cfg.get("token_file") else None
        self.ctx = ssl.create_default_context(cafile=os.path.expanduser(cfg["ca_file"])) if cfg.get("ca_file") else None

    def get(self, path, paginate=False):
        out, page = [], 1
        while True:
            q = ("&" if "?" in path else "?") + f"limit=50&page={page}" if paginate else ""
            req = urllib.request.Request(self.base + path + q, headers={"Accept": "application/json"})
            if self.tok:
                req.add_header("Authorization", "token " + self.tok)
            try:
                with urllib.request.urlopen(req, timeout=30, context=self.ctx) as r:
                    data = json.load(r)
            except urllib.error.HTTPError as e:
                return None, f"HTTP {e.code}"
            except (urllib.error.URLError, OSError, ValueError) as e:
                return None, f"{type(e).__name__}: {str(e)[:120]}"
            if not paginate:
                return data, None
            out += data or []
            if not data or len(data) < 50:
                return out, None
            page += 1


def protection_for(rules, branch):
    """The branch protection rule that applies to `branch` (exact name first, then glob patterns)."""
    import fnmatch
    for r in rules or []:
        if (r.get("rule_name") or r.get("branch_name")) == branch:
            return r
    for r in rules or []:
        if fnmatch.fnmatchcase(branch, r.get("rule_name") or r.get("branch_name") or ""):
            return r
    return None


def scan(c, ch):
    host = urllib.parse.urlparse(ch["url"]).hostname or "gitea"
    scope = f"codehost:{ch['type']}/{ch['owner']}"
    try:
        api = API(ch)
    except (OSError, KeyError) as e:
        c.gap(scope, f"{type(e).__name__}: {e}")
        return
    repos, err = api.get(f"/orgs/{urllib.parse.quote(ch['owner'])}/repos", paginate=True)
    if repos is None:
        repos, err = api.get(f"/users/{urllib.parse.quote(ch['owner'])}/repos", paginate=True)
    if repos is None:
        c.gap(scope, f"cannot list repositories: {err}")
        return
    summary, public_unprotected = {}, 0
    for r in sorted(repos, key=lambda x: x["full_name"]):
        if r.get("archived") or (r.get("private") and ch.get("include_private") is False):
            continue
        full, br = r["full_name"], r.get("default_branch") or "main"
        A = f"repo:{ch['type']}/{host}/{full}"
        pub = not r.get("private") and not r.get("internal")
        rules, rerr = api.get(f"/repos/{full}/branch_protections")
        keys, kerr = api.get(f"/repos/{full}/keys", paginate=True)
        if rules is None:
            c.gap(A, f"cannot read branch protection: {rerr}")
            continue
        c.ok(A)
        rule = protection_for(rules, br)
        row = dict(visibility="public" if pub else "private", default_branch=br, protected=bool(rule),
                   push_restricted=bool(rule and (not rule.get("enable_push") or rule.get("enable_push_whitelist"))),
                   required_approvals=(rule or {}).get("required_approvals", 0),
                   status_checks=bool((rule or {}).get("enable_status_check")), mirror=bool(r.get("mirror")),
                   deploy_keys=[dict(title=k.get("title"), read_only=k.get("read_only"), created_at=k.get("created_at"))
                                for k in (keys or [])], deploy_keys_error=kerr)
        summary[full] = row
        ev = f"raw/{c.name}/repos.json#{full}"
        if not rule or not row["push_restricted"]:
            public_unprotected += 1 if pub else 0
            c.finding("supply-chain", A, "repo.default_branch_unprotected",
                      f"{row['visibility']} repo: default branch '{br}' can be pushed to directly"
                      + ("" if rule else " (no branch protection rule)"), "high" if pub else "medium", ev,
                      "add a branch protection rule for the default branch: disable direct push, require a pull "
                      "request with an approval and status checks")
        elif not row["required_approvals"]:
            c.finding("supply-chain", A, "repo.protection_no_approvals",
                      f"default branch '{br}' is protected but merges need no approving review", "low", ev,
                      "set required approvals to at least 1 in the branch protection rule")
        if r.get("mirror") and str(r.get("original_url", "")).startswith("http://"):
            c.finding("supply-chain", A, "repo.mirror_unverified_remote", "pull mirror fetches over plain http",
                      "medium", ev, "mirror over https or ssh")
        for k in keys or []:
            if not k.get("read_only"):
                c.finding("identity", f"{A}/deploy-key/{k.get('title')}", "repo.deploy_key_write",
                          f"write-enabled deploy key '{k.get('title')}' (created {str(k.get('created_at'))[:10]})",
                          "low", ev, "keep only if a pipeline needs push; rotate yearly")
    c.raw("repos.json", summary)
    c.metric("security_repos_public_without_protection", public_unprotected,
             "Public repos whose default branch has no protection/ruleset", owner=ch["owner"])
    c.metric("security_repos_total", len(summary), "Repos checked", owner=ch["owner"])


def main():
    inst = spsdk.load_instance()
    c = spsdk.Collector("codehost-gitea", VERSION)
    for ch in inst.get("codehost") or []:
        if ch.get("type") in TYPES:
            scan(c, ch)
    c.write()


if __name__ == "__main__":
    main()
