#!/usr/bin/env python3
"""Collector `codehost-github`: repository/supply-chain posture via the GitHub API (gh), READ-ONLY.

Instance config `codehost: [{type: github, owner, gh_user}]`. Uses `gh auth token --user <gh_user>` in the
child environment only. Secret-scanning alerts are reduced server-side with --jq to counts/types: the secret
value never leaves gh. Also records the local gh auth accounts and their token SCOPES (names only).
Future adapter: GitLab (same checks via its API).
"""
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(__file__)
ROOT = os.path.join(HERE, "..", "..")
sys.path[:0] = [os.path.join(ROOT, "sdk"), ROOT]
import spsdk  # noqa: E402

VERSION = open(os.path.join(HERE, "VERSION")).read().strip()


class GH:
    def __init__(self, user):
        tok = subprocess.run(["gh", "auth", "token", "--user", user], capture_output=True, text=True).stdout.strip()
        self.env = dict(os.environ, GH_TOKEN=tok)

    def api(self, path, jq=None, paginate=False):
        cmd = ["gh", "api", "-H", "Accept: application/vnd.github+json", path] + (["--paginate"] if paginate else []) \
            + (["--jq", jq] if jq else [])
        p = subprocess.run(cmd, capture_output=True, text=True, env=self.env, timeout=60)
        if p.returncode != 0:
            return None, (p.stderr or p.stdout).strip()[-200:]
        out = p.stdout.strip()
        if jq:
            return out, None
        return (json.loads(out) if out else None), None


def gh_scopes():
    p = subprocess.run(["gh", "auth", "status"], capture_output=True, text=True)
    accts, cur = [], None
    for l in (p.stdout + p.stderr).splitlines():
        l = l.strip()
        if "Logged in to" in l and "account" in l:
            cur = {"host": l.split("Logged in to ")[1].split()[0], "account": l.split("account ")[1].split()[0],
                   "storage": l.split("(")[-1].rstrip(")")}
            accts.append(cur)
        elif l.startswith("- Token scopes:") and cur:
            cur["scopes"] = [s.strip(" '") for s in l.split(":", 1)[1].split(",")]
        elif l.startswith("- Active account:") and cur:
            cur["active"] = l.endswith("true")
    return accts


def main():
    inst = spsdk.load_instance()
    c = spsdk.Collector("codehost-github", VERSION)
    accts = gh_scopes()
    ev = c.raw("gh-auth.json", accts)
    for a in accts:
        asset = f"identity:github/{a['account']}@local-gh"
        c.ok(asset)
        risky = [s for s in a.get("scopes", []) if s in ("delete_repo", "admin:org", "admin:public_key", "admin:repo_hook",
                                                         "workflow", "write:packages", "admin:enterprise")]
        if "repo" in a.get("scopes", []):
            risky.append("repo(full)")
        if risky:
            c.finding("identity", asset, "github.token_broad_scopes",
                      f"local gh token for {a['account']} has broad scopes: {', '.join(risky)} (classic OAuth token, no expiry)",
                      "medium", ev, "use fine-grained, repo-scoped, expiring tokens for automation; keep this one for interactive use only",
                      needs_human=True)
    for ch in inst.get("codehost", []):
        if ch["type"] != "github":
            continue   # another code host: its own collector (codehost-gitea, ...) covers it
        g = GH(ch["gh_user"])
        repos, err = g.api(f"/users/{ch['owner']}/repos?per_page=100&type=owner", paginate=False)
        if repos is None:
            c.gap(f"codehost:github/{ch['owner']}", err)
            continue
        # include private repos visible to the token
        me, _ = g.api("/user/repos?per_page=100&affiliation=owner")
        byname = {r["full_name"]: r for r in (repos or []) + (me or []) if r["owner"]["login"] == ch["owner"]}
        summary = []
        public_unprotected = 0
        for full, r in sorted(byname.items()):
            if r.get("archived"):
                continue
            A = f"repo:github/{full}"
            c.ok(A)
            br = r["default_branch"]
            vis = r["visibility"]
            prot, _ = g.api(f"/repos/{full}/branches/{br}/protection")
            rules, _ = g.api(f"/repos/{full}/rules/branches/{br}")
            rule_types = sorted({x["type"] for x in (rules or [])})
            protected = bool(prot) or bool({"pull_request", "non_fast_forward", "deletion"} & set(rule_types))
            wf, _ = g.api(f"/repos/{full}/actions/permissions/workflow")
            ap, _ = g.api(f"/repos/{full}/actions/permissions")
            keys, _ = g.api(f"/repos/{full}/keys")
            full_r, _ = g.api(f"/repos/{full}")
            sa = (full_r or {}).get("security_and_analysis") or {}
            ss, ss_err = g.api(f"/repos/{full}/secret-scanning/alerts?state=open&per_page=100",
                               jq="[.[] | .secret_type_display_name] | {count: length, types: (group_by(.) | map({(.[0]): length}) | add)}")
            da, da_err = g.api(f"/repos/{full}/dependabot/alerts?state=open&per_page=100",
                               jq="[.[] | .security_advisory.severity] | group_by(.) | map({(.[0]): length}) | add")
            sec, _ = g.api(f"/repos/{full}/actions/secrets?per_page=100", jq="[.secrets[] | {name, updated_at}]")
            row = dict(repo=full, visibility=vis, default_branch=br, protected=protected, ruleset_rules=rule_types,
                       classic_protection=bool(prot),
                       workflow_default_permissions=(wf or {}).get("default_workflow_permissions"),
                       actions_can_approve_prs=(wf or {}).get("can_approve_pull_request_reviews"),
                       allowed_actions=(ap or {}).get("allowed_actions"), actions_enabled=(ap or {}).get("enabled"),
                       deploy_keys=[dict(title=k["title"], read_only=k["read_only"], created_at=k["created_at"],
                                         last_used=k.get("last_used")) for k in (keys or [])],
                       secret_scanning=(sa.get("secret_scanning") or {}).get("status"),
                       push_protection=(sa.get("secret_scanning_push_protection") or {}).get("status"),
                       dependabot_updates=(sa.get("dependabot_security_updates") or {}).get("status"),
                       secret_scanning_alerts=json.loads(ss) if ss else {"error": ss_err},
                       dependabot_alerts=json.loads(da) if da and da != "null" else ({} if da else {"error": da_err}),
                       actions_secrets=json.loads(sec) if sec else [])
            summary.append(row)
            ev = f"raw/codehost-github/repos.json#{full}"
            pub = vis == "public"
            if not protected:
                if pub:
                    public_unprotected += 1
                what = (f"ruleset only has {','.join(rule_types)} (no PR / force-push / deletion rules)" if rule_types
                        else "no protection/ruleset")
                c.finding("supply-chain", A, "repo.default_branch_unprotected",
                          f"{vis} repo: default branch '{br}': {what}", "high" if pub else "medium", ev,
                          "ruleset: require PR + status checks, block force-push/deletion")
            if row["workflow_default_permissions"] == "write":
                c.finding("supply-chain", A, "repo.actions_default_write",
                          "GITHUB_TOKEN default permission is write", "medium" if pub else "low", ev,
                          "set default workflow permissions to read; grant per job")
            if row["actions_can_approve_prs"]:
                c.finding("supply-chain", A, "repo.actions_can_approve_prs", "Actions may approve pull requests", "medium", ev,
                          "disable 'Allow GitHub Actions to create and approve pull requests' unless needed")
            if "error" not in (row["dependabot_alerts"] or {}) or "disabled" not in str(row["dependabot_alerts"].get("error")):
                pass
            else:
                c.finding("supply-chain", A, "repo.dependabot_alerts_off", "Dependabot alerts are disabled",
                          "medium" if pub else "low", ev, "enable Dependabot alerts + security updates")
            if pub and row["secret_scanning"] != "enabled":
                c.finding("supply-chain", A, "repo.secret_scanning_off", "secret scanning is off", "medium", ev, "enable it")
            if pub and row["push_protection"] != "enabled":
                c.finding("supply-chain", A, "repo.push_protection_off", "secret push protection is off", "low", ev, "enable it")
            n_ss = (row["secret_scanning_alerts"] or {}).get("count") or 0
            if n_ss:
                c.finding("data-secrets", A, "repo.secret_scanning_alerts_open",
                          f"{n_ss} open secret-scanning alert(s) (types: {', '.join((row['secret_scanning_alerts'].get('types') or {}).keys())})",
                          "critical" if pub else "high", ev, "revoke/rotate the secret, then close the alert", needs_human=True)
            dep = row["dependabot_alerts"] if isinstance(row["dependabot_alerts"], dict) else {}
            if dep.get("critical") or dep.get("high"):
                c.finding("supply-chain", A, "repo.dependabot_alerts_open",
                          f"open Dependabot alerts: {', '.join(f'{k}={v}' for k, v in dep.items() if k != 'error')}",
                          "high" if dep.get("critical") else "medium", ev, "merge the security updates")
            for k in row["deploy_keys"]:
                if not k["read_only"]:
                    c.finding("identity", f"{A}/deploy-key/{k['title']}", "repo.deploy_key_write",
                              f"write-enabled deploy key '{k['title']}' (created {k['created_at'][:10]})", "low", ev,
                              "keep only if a pipeline needs push; rotate yearly")
            for s in row["actions_secrets"]:
                age = (time.time() - time.mktime(time.strptime(s["updated_at"][:10], "%Y-%m-%d"))) / 86400
                if age > 90:
                    c.finding("data-secrets", f"{A}/actions-secret/{s['name']}", "secret.age_over_90d",
                              f"Actions secret {s['name']} not rotated for {int(age)} days", "low", ev, "rotate", needs_human=True)
        c.raw("repos.json", {r["repo"]: r for r in summary})
        c.metric("security_repos_public_without_protection", public_unprotected,
                 "Public repos whose default branch has no protection/ruleset", owner=ch["owner"])
        c.metric("security_repos_total", len(summary), "Repos checked", owner=ch["owner"])
    c.write()


if __name__ == "__main__":
    main()
