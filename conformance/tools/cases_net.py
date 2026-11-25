"""Conformance cases of the network-facing and agent collectors (contract collector-protocol/1.0) and of the events
shipper (contract events/1.0): exposure, codehost-github, codehost-gitea, agent-claude-code, detection, events.
Called by gen_cases.py (cases(write_case)); stdlib only, imports nothing from the product.

Fakes, all test tools in this directory, copied into the case and started by the harness or put first on PATH:
  fake_nmap.py      nmap emitting recorded XML (open/filtered/closed ports, a host down, a host timed out); logs argv
  fake_gh.py        the gh CLI over a fake GitHub API (auth token/status, api --paginate --jq)
  mock_codehost.py  fake GitHub and Gitea REST APIs: pagination, rate limits, 404 for missing features, private and
                    public repositories, a redirect to another host; logs every method (a mutating one is a failure)
  mock_obs.py       fake Loki / Prometheus / Alertmanager read APIs and a Loki push endpoint for the events shipper
  fake_kubectl.py   kubectl get daemonsets/prometheusrules from fixtures
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
C = "collector-protocol/1.0"


def tool(name):
    with open(os.path.join(HERE, name)) as f:
        return f.read()


def collector_env(extra=None):
    e = {"SP_RUN_DIR": "{sandbox}/run", "SP_INSTANCE": "{sandbox}/instance.json", "SP_DATA": "{sandbox}/data",
         "SP_INPUT_DIR": "{sandbox}/data/latest", "SP_INSTANCE_NAME": "conformance"}
    e.update(extra or {})
    return e


def protocol_checks(name, canaries=()):
    out = [{"json": f"run/{name}.findings.json", "schema": "findings", "findings_ids": True,
            "subset": {"collector": {"name": name}}},
           {"writes_only_under": True}]
    if canaries:
        out.append({"no_secret": list(canaries), "in": "run"})
    return out


def collect(impl, expect, env=None, name="collect", exit_=0, writes=("run",), path=False, **extra):
    ex = {"impl": impl, "env": collector_env(env), "writes_only_under": list(writes)}
    if path:
        ex["path_prepend"] = ["{sandbox}/bin"]
    step = {"name": name, "exec": ex, "exit": exit_, "expect": expect}
    step.update(extra)
    return step


def wrapper(script):
    """An executable on the sandbox PATH that runs a fake from the case directory with the suite's interpreter."""
    return {"text": f'#!/bin/sh\nexec "{{python}}" "{{case}}/{script}" "$@"\n', "mode": "0755"}


def findings_has(path, *subsets):
    return {"json": path, "subset": {"findings": {"$contains": list(subsets)}}}


def coverage_has(path, *subsets):
    return {"json": path, "subset": {"coverage": {"$contains": list(subsets)}}}


# ==================================================================================================================
# agent-claude-code
# ==================================================================================================================
AGENT = "collector-agent-claude-code"
AGENT_DOC = "run/agent-claude-code.findings.json"
MEMORY = ("# notes\n"
          "github token for the bot: {canary_github}\n"
          "password: {canary_password}\n"
          "password = same as the admin UI\n"
          "the deploy key lives in the vault, not here\n")
NOTES = "ssh key backup\n{canary_privkey}\nAAAA\n"


def agent_instance(**agent):
    return {"name": "conformance", "agents": [dict({"type": "claude-code"}, **agent)]}


def agent_cases(write_case):
    canaries = ["{canary_github}", "{canary_password}", "{canary_privkey}", "{canary_token}"]
    memory_files = {"home/.claude/projects/proj-a/memory/MEMORY.md": {"text": MEMORY},
                    "home/.claude/projects/proj-b/memory/notes.md": {"text": NOTES},
                    "home/.claude/projects/proj-b/memory/.hidden.md": {"text": "token: {canary_token}\n"},
                    "home/.claude/projects/proj-b/memory/clean.md": {"text": "nothing to see\n"},
                    "home/.claude/projects/proj-a/s1.jsonl": {"text": "{}\n"},
                    "data/.keep": {"text": ""}}
    inst = agent_instance(settings=["{sandbox}/home/.claude/settings.json"], memory_dirs=["~/.claude/projects"])
    settings = {"permissions": {"deny": ["Read(~/.ssh/**)"]}, "cleanupPeriodDays": 60}
    write_case(AGENT, "memory-credentials-never-copied", {
        "title": "Credential-shaped lines in agent memory files are reported per FILE (count, asset), never the value: "
                 "not in the document, the evidence or the output; prose after a keyword is not a credential; hidden files "
                 "are not scanned",
        "contract": C, "origin": "collectors/agent-claude-code memory_scan",
        "files": dict(memory_files, **{"instance.json": "instance.json", "home/.claude/settings.json": "settings.json"}),
        "steps": [collect(AGENT, protocol_checks("agent-claude-code", canaries) + [
            findings_has(AGENT_DOC,
                         {"check": "agent.memory_secret_suspect", "asset": "agent-memory:claude-code/proj-a/MEMORY.md",
                          "title": "2 line(s) shaped like a credential in agent memory file MEMORY.md", "severity": "high",
                          "layer": "ai-agents", "needs_human": True},
                         {"check": "agent.memory_secret_suspect", "asset": "agent-memory:claude-code/proj-b/notes.md",
                          "title": "1 line(s) shaped like a credential in agent memory file notes.md"}),
            {"json": AGENT_DOC, "subset": {"findings": {"$not_contains": [
                {"check": "agent.memory_secret_suspect", "asset": "agent-memory:claude-code/proj-b/clean.md"},
                {"check": "agent.memory_secret_suspect", "asset": "agent-memory:claude-code/proj-b/.hidden.md"},
                {"check": "agent.no_credential_deny_rules"}]}}},
            {"json": "run/raw/agent-claude-code/memory-scan.json", "subset": {
                "files": 3, "suspect_files": {"MEMORY.md": 2, "notes.md": 1}}},
            {"prom": "run/agent-claude-code.prom", "has": [{"name": "security_agent_memory_files", "value": 3}]}])]},
        {"instance.json": inst, "settings.json": settings})

    write_case(AGENT, "memory-credentials-pattern-class", {
        "title": "A memory-file finding names the PATTERN CLASS of what it saw (github-token, credential-assignment, "
                 "private-key, ...) so the owner knows what to rotate, still never the value",
        "contract": C, "origin": "collectors/agent-claude-code memory_scan: only a count per file",
        "deviation": "AGENT-D1",
        "files": dict(memory_files, **{"instance.json": "instance.json", "home/.claude/settings.json": "settings.json"}),
        "steps": [collect(AGENT, protocol_checks("agent-claude-code", canaries) + [
            findings_has(AGENT_DOC,
                         {"asset": "agent-memory:claude-code/proj-a/MEMORY.md",
                          "attributes": {"pattern_classes": ["credential-assignment", "github-token"]}},
                         {"asset": "agent-memory:claude-code/proj-b/notes.md", "attributes": {"pattern_classes": ["private-key"]}}),
            {"json": "run/raw/agent-claude-code/memory-scan.json", "subset": {"pattern_classes": {
                "MEMORY.md": ["credential-assignment", "github-token"], "notes.md": ["private-key"]}}}])]},
        {"instance.json": inst, "settings.json": settings})

    risky = {"permissions": {"defaultMode": "bypassPermissions",
                             "allow": ["Bash(*)", "Bash(ssh lab:*)", "Bash(scp:*)", "Read(~/notes/**)", "Bash(ls:*)"],
                             "deny": ["Read(./build/**)"], "blockReadsOutsideWorkingDirectories": False,
                             "additionalDirectories": ["/tmp/x"]},
             "skipDangerousModePermissionPrompt": True, "cleanupPeriodDays": 7,
             "hooks": {"PreToolUse": [{"matcher": "Bash"}], "Stop": []},
             "env": {"API_TOKEN": "{canary_token}", "OTHER": "x"}}
    write_case(AGENT, "risky-settings", {
        "title": "Risky agent settings: bypassPermissions by default with the danger prompt skipped, reads outside the "
                 "working directories, allow rules granting a shell / remote hosts / files outside the project, no "
                 "credential-path deny rule, a settings file writable by others, transcripts kept too briefly; env "
                 "values are never read into the output",
        "contract": C, "origin": "collectors/agent-claude-code",
        "files": {"instance.json": "instance.json", "home/.claude/settings.json": {"text": json.dumps(risky, indent=1), "mode": "0666"},
                  "home/.claude/projects/p/s1.jsonl": {"text": "{}\n"}, "data/.keep": {"text": ""}},
        "steps": [collect(AGENT, protocol_checks("agent-claude-code", ["{canary_token}"]) + [
            findings_has(AGENT_DOC,
                         {"check": "agent.bypass_permissions_default",
                          "title": "agent runs in bypassPermissions by default (no per-action confirmation) and the danger "
                                   "prompt is skipped", "severity": "high"},
                         {"check": "agent.reads_outside_workdir", "severity": "high"},
                         {"check": "agent.broad_allow.any_shell_command",
                          "title": "1 allow rule(s) grant any shell command without confirmation", "severity": "medium"},
                         {"check": "agent.broad_allow.remote_shell_to_other_hosts",
                          "title": "2 allow rule(s) grant remote shell to other hosts without confirmation"},
                         {"check": "agent.broad_allow.file_access_outside_the_project"},
                         {"check": "agent.settings_writable_by_others", "title": "settings file writable by others (0o666)"},
                         {"check": "agent.no_credential_deny_rules", "asset": "agent-guard:claude-code"},
                         {"check": "agent.audit_trail_missing", "severity": "low",
                          "title": "agent transcripts are kept 7 days (< 30): too short to investigate an incident"}),
            coverage_has(AGENT_DOC, {"asset": "agent-memory:claude-code", "status": "gap", "reason": "no memory_dirs configured"},
                         {"asset": "agent-audit:claude-code", "status": "ok"}),
            {"json": "run/raw/agent-claude-code/guards.json", "subset": {
                "deny_rules": 1, "credential_path_deny_rules": 0, "hooks": {"PreToolUse": 1, "Stop": 0}}},
            {"json": "run/raw/agent-claude-code/audit-trail.json", "subset": {"transcripts": 1, "retention_days": 7}}])]},
        {"instance.json": agent_instance(settings=["{sandbox}/home/.claude/settings.json"],
                                         transcripts_dirs=["~/.claude/projects"])})

    write_case(AGENT, "malformed-settings-is-a-gap", {
        "title": "A settings file that is not a settings document (invalid JSON, not an object) is a coverage gap for that "
                 "file; the run completes and every other file is still evaluated",
        "contract": C + " §5", "origin": "collectors/agent-claude-code: json.load of the second pass raises, the run "
                                         "exits 1 and no document is written", "deviation": "AGENT-D2",
        "files": {"instance.json": "instance.json", "home/a/settings.json": {"text": '{"permissions": {"allow": ["Bash(*)"]'},
                  "home/b/settings.json": {"text": json.dumps({"permissions": {"allow": ["Bash(curl:*)"]}})},
                  "home/c/settings.json": {"text": "[1, 2]"}, "data/.keep": {"text": ""}},
        "steps": [collect(AGENT, protocol_checks("agent-claude-code") + [
            coverage_has(AGENT_DOC, {"asset": "agent:claude-code:{sandbox}/home/a/settings.json", "status": "gap",
                                     "reason": {"$regex": "invalid JSON"}},
                         {"asset": "agent:claude-code:{sandbox}/home/c/settings.json", "status": "gap",
                          "reason": {"$regex": "not a JSON object"}},
                         {"asset": "agent:claude-code:{sandbox}/home/b/settings.json", "status": "ok"}),
            findings_has(AGENT_DOC, {"check": "agent.broad_allow.arbitrary_network_egress",
                                     "asset": "agent:claude-code:{sandbox}/home/b/settings.json"})])]},
        {"instance.json": agent_instance(settings=["{sandbox}/home/a/settings.json", "{sandbox}/home/b/settings.json",
                                                   "{sandbox}/home/c/settings.json", "{sandbox}/home/missing.json"],
                                         transcripts_dirs=["{sandbox}/nowhere"])})

    write_case(AGENT, "other-agent-types-and-missing-sources", {
        "title": "An agent type without an adapter is a gap (not silently ignored); no memory directories and no "
                 "transcript directory are gaps, not a clean result",
        "contract": C + " §4", "origin": "collectors/agent-claude-code",
        "files": {"instance.json": "instance.json", "data/.keep": {"text": ""}},
        "steps": [collect(AGENT, protocol_checks("agent-claude-code") + [
            coverage_has(AGENT_DOC, {"asset": "agent:cursor", "status": "gap", "reason": "adapter not implemented (future)"},
                         {"asset": "agent-memory:claude-code", "status": "gap"},
                         {"asset": "agent-audit:claude-code", "status": "gap", "reason": "transcripts directory not found"},
                         {"asset": "agent-guard:claude-code", "status": "ok"})])]},
        {"instance.json": {"name": "conformance", "agents": [{"type": "cursor"}, {"type": "claude-code",
                                                                                   "transcripts_dirs": ["{sandbox}/none"]}]}})


# ==================================================================================================================
# exposure
# ==================================================================================================================
def exposure_cases(write_case):
    """exposure: cases written here."""
    return None


# ==================================================================================================================
# codehost-github
# ==================================================================================================================
CODEHOST_SVC = [{"name": "codehost", "argv": ["{python}", "{case}/mock_codehost.py", "--fixture", "{sandbox}/codehost-api.json"]}]
READ_ONLY = [{"absent": ".svc-codehost-mutations.log"}, {"no_secret": ["{canary_token}"], "in": ".svc-codehost-leaks"}]


def gh_repo(name, vis="public", owner="acme", archived=False, branch="main"):
    return {"name": name, "full_name": f"{owner}/{name}", "owner": {"login": owner}, "visibility": vis,
            "private": vis != "public", "archived": archived, "default_branch": branch}


GH = "collector-codehost-github"
GH_DOC = "run/codehost-github.findings.json"
GH_STATUS = ("github.com\n"
             "  ✓ Logged in to github.com account bot (keyring)\n"
             "  - Active account: true\n"
             "  - Git operations protocol: https\n"
             "  - Token: gho_************************************\n"
             "  - Token scopes: 'delete_repo', 'gist', 'read:org', 'repo', 'workflow'\n"
             "\n"
             "  ✓ Logged in to github.com account reader (keyring)\n"
             "  - Active account: false\n"
             "  - Git operations protocol: https\n"
             "  - Token: gho_************************************\n"
             "  - Token scopes: 'read:org'\n")


def gh_files():
    return {"instance.json": "instance.json", "codehost-api.json": "api.json", "gh-status.txt": "gh-status.txt",
            "gh.token": {"text": "{canary_token}\n", "mode": "0600"}, "bin/gh": wrapper("fake_gh.py"),
            "data/.keep": {"text": ""}}


def gh_case_files(api, owners=("acme",)):
    inst = {"name": "conformance", "codehost": [
        {"type": "github", "owner": o, "gh_user": "bot", "api": "{svc_codehost}", "token_file": "{sandbox}/gh.token"}
        for o in owners] + [{"type": "gitea", "url": "http://127.0.0.1:1", "owner": "elsewhere"}]}
    return {"instance.json": inst, "api.json": api, "gh-status.txt": GH_STATUS, "mock_codehost.py": tool("mock_codehost.py"),
            "fake_gh.py": tool("fake_gh.py")}


GH_ENV = {"FAKE_GH_API": "{svc_codehost}", "FAKE_GH_TOKEN_FILE": "{sandbox}/gh.token",
          "FAKE_GH_STATUS_FILE": "{sandbox}/gh-status.txt"}


def gh_routes(full, protection=None, rules=(), workflow=None, perms=None, keys=None, sa=None, secret_alerts=None,
              dependabot=None, secrets=None, branch="main"):
    """The per-repository answers; None = the endpoint answers 404 (a feature the repository does not have)."""
    r = f"/repos/{full}"
    out = {f"{r}/branches/{branch}/protection": protection or {"status": 404, "body": {"message": "Branch not protected"}},
           f"{r}/rules/branches/{branch}": {"body": list(rules)}, r: {"body": {"full_name": full, "security_and_analysis": sa}}}
    for path, v in ((f"{r}/actions/permissions/workflow", workflow), (f"{r}/actions/permissions", perms),
                    (f"{r}/keys", keys), (f"{r}/secret-scanning/alerts", secret_alerts),
                    (f"{r}/dependabot/alerts", dependabot), (f"{r}/actions/secrets", secrets)):
        if v is not None:
            out[path] = v if isinstance(v, dict) and ("status" in v or "items" in v) else {"body": v}
    return out


def enabled(on):
    st = {"status": "enabled" if on else "disabled"}
    return {"secret_scanning": st, "secret_scanning_push_protection": st, "dependabot_security_updates": st}


def github_cases(write_case):
    """codehost-github: cases written here."""
    routes = {"/users/acme/repos": {"items": [gh_repo("public-open"), gh_repo("public-safe"),
                                              gh_repo("old", archived=True), gh_repo("fork", owner="other")]},
              "/user/repos": {"items": [gh_repo("public-open"), gh_repo("public-safe"), gh_repo("private-ruleset", "private")]}}
    routes.update(gh_routes(
        "acme/public-open", workflow={"default_workflow_permissions": "write", "can_approve_pull_request_reviews": True},
        perms={"enabled": True, "allowed_actions": "all"}, sa=enabled(False),
        keys=[{"id": 1, "title": "ci-push", "read_only": False, "created_at": "2025-01-02T03:04:05Z", "last_used": None,
               "key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIConformanceOnly"},
              {"id": 2, "title": "mirror", "read_only": True, "created_at": "2025-02-02T00:00:00Z"}],
        secret_alerts={"status": 404, "body": {"message": "Secret scanning is disabled on this repository."}},
        dependabot={"status": 403, "body": {"message": "Dependabot alerts are disabled for this repository."}},
        secrets={"total_count": 2, "secrets": [{"name": "DEPLOY_KEY", "created_at": "2020-01-01T00:00:00Z",
                                                "updated_at": "{utc:-12960000}"},
                                               {"name": "FRESH", "updated_at": "{utc:-86400}"}]}))
    routes.update(gh_routes(
        "acme/public-safe", protection={"body": {"url": "x", "required_pull_request_reviews": {"required_approving_review_count": 1}}},
        rules=[{"type": "pull_request", "ruleset_id": 1}, {"type": "deletion"}],
        workflow={"default_workflow_permissions": "read", "can_approve_pull_request_reviews": False},
        perms={"enabled": True, "allowed_actions": "selected"}, keys=[], sa=enabled(True),
        secret_alerts=[{"number": 1, "state": "open", "secret_type_display_name": "GitHub Personal Access Token",
                        "secret": "{canary_github}"},
                       {"number": 2, "state": "open", "secret_type_display_name": "Amazon AWS Access Key ID",
                        "secret": "{canary_aws}"},
                       {"number": 3, "state": "open", "secret_type_display_name": "GitHub Personal Access Token",
                        "secret": "{canary_password}"}],
        dependabot=[{"security_advisory": {"severity": "high"}}, {"security_advisory": {"severity": "critical"}},
                    {"security_advisory": {"severity": "high"}}],
        secrets={"total_count": 0, "secrets": []}))
    routes.update(gh_routes("acme/private-ruleset", rules=[{"type": "required_signatures"}]))
    api = {"token": "{canary_token}", "routes": routes}
    canaries = ["{canary_token}", "{canary_github}", "{canary_aws}", "{canary_password}"]
    write_case(GH, "repository-posture", {
        "title": "Repository posture read through the GitHub API, read-only: unprotected default branches (none, or a ruleset "
                 "without PR/force-push/deletion rules), Actions defaults, secret scanning / push protection / Dependabot "
                 "off, open secret-scanning alerts (types only: an alert's secret value never reaches the output), open "
                 "Dependabot alerts, write deploy keys, Actions secrets not rotated, broad local gh token scopes; archived "
                 "and foreign repositories skipped; an owner that cannot be listed is a gap",
        "contract": C, "origin": "collectors/codehost-github",
        "services": CODEHOST_SVC, "files": gh_files(),
        "steps": [collect(GH, protocol_checks("codehost-github", canaries) + READ_ONLY + [
            findings_has(GH_DOC,
                         {"check": "repo.default_branch_unprotected", "asset": "repo:github/acme/public-open", "severity": "high",
                          "title": "public repo: default branch 'main': no protection/ruleset", "layer": "supply-chain"},
                         {"check": "repo.default_branch_unprotected", "asset": "repo:github/acme/private-ruleset",
                          "severity": "medium", "title": "private repo: default branch 'main': ruleset only has "
                                                         "required_signatures (no PR / force-push / deletion rules)"},
                         {"check": "repo.actions_default_write", "asset": "repo:github/acme/public-open", "severity": "medium"},
                         {"check": "repo.actions_can_approve_prs", "asset": "repo:github/acme/public-open"},
                         {"check": "repo.dependabot_alerts_off", "asset": "repo:github/acme/public-open", "severity": "medium"},
                         {"check": "repo.secret_scanning_off", "asset": "repo:github/acme/public-open"},
                         {"check": "repo.push_protection_off", "asset": "repo:github/acme/public-open", "severity": "low"},
                         {"check": "repo.deploy_key_write", "asset": "repo:github/acme/public-open/deploy-key/ci-push",
                          "title": "write-enabled deploy key 'ci-push' (created 2025-01-02)", "layer": "identity"},
                         {"check": "secret.age_over_90d", "asset": "repo:github/acme/public-open/actions-secret/DEPLOY_KEY",
                          "title": {"$regex": r"^Actions secret DEPLOY_KEY not rotated for 1[45]\d days$"}},
                         {"check": "repo.secret_scanning_alerts_open", "asset": "repo:github/acme/public-safe",
                          "severity": "critical", "layer": "data-secrets",
                          "title": "3 open secret-scanning alert(s) (types: Amazon AWS Access Key ID, GitHub Personal "
                                   "Access Token)"},
                         {"check": "repo.dependabot_alerts_open", "asset": "repo:github/acme/public-safe", "severity": "high",
                          "title": "open Dependabot alerts: critical=1, high=2"},
                         {"check": "github.token_broad_scopes", "asset": "identity:github/bot@local-gh",
                          "title": "local gh token for bot has broad scopes: delete_repo, workflow, repo(full) (classic "
                                   "OAuth token, no expiry)"}),
            {"json": GH_DOC, "subset": {"findings": {"$not_contains": [
                {"asset": "repo:github/acme/public-safe", "check": "repo.default_branch_unprotected"},
                {"asset": "repo:github/acme/private-ruleset", "check": "repo.secret_scanning_off"},
                {"asset": "repo:github/acme/private-ruleset", "check": "repo.dependabot_alerts_off"},
                {"asset": "repo:github/acme/public-open/actions-secret/FRESH"},
                {"asset": "repo:github/acme/public-open/deploy-key/mirror"},
                {"asset": "identity:github/reader@local-gh"}]},
                "coverage": {"$not_contains": [{"asset": "repo:github/acme/old"}, {"asset": "repo:github/other/fork"}]}}},
            coverage_has(GH_DOC, {"asset": "repo:github/acme/public-open", "status": "ok"},
                         {"asset": "repo:github/acme/private-ruleset", "status": "ok"},
                         {"asset": "identity:github/reader@local-gh", "status": "ok"},
                         {"asset": "codehost:github/ghost", "status": "gap", "reason": {"$regex": "404"}}),
            {"json": "run/raw/codehost-github/repos.json", "subset": {
                "acme/public-safe": {"protected": True, "classic_protection": True, "ruleset_rules": ["deletion", "pull_request"],
                                     "secret_scanning_alerts": {"count": 3, "types": {"Amazon AWS Access Key ID": 1,
                                                                                      "GitHub Personal Access Token": 2}},
                                     "dependabot_alerts": {"critical": 1, "high": 2}, "actions_secrets": []},
                "acme/public-open": {"protected": False, "deploy_keys": [{"title": "ci-push", "read_only": False},
                                                                          {"title": "mirror", "read_only": True}]}}},
            {"prom": "run/codehost-github.prom", "has": [
                {"name": "security_repos_total", "labels": {"owner": "acme"}, "value": 3},
                {"name": "security_repos_public_without_protection", "labels": {"owner": "acme"}, "value": 1}]}],
            env=GH_ENV, path=True)]},
        gh_case_files(api, owners=("acme", "ghost")))

    limited = {"/users/acme/repos": {"items": [gh_repo("limited"), gh_repo("flaky"), gh_repo("fine")]}, "/user/repos": {"items": []}}
    limited.update(gh_routes("acme/limited", protection={"status": 403, "headers": {"X-RateLimit-Remaining": "0"},
                                                         "body": {"message": "API rate limit exceeded for user ID 1."}}))
    limited.update(gh_routes("acme/flaky", protection={"status": 502, "body": {"message": "Server Error"}}))
    limited.update(gh_routes("acme/fine", protection={"body": {"url": "x"}}))
    write_case(GH, "protection-unreadable-is-a-gap", {
        "title": "A branch protection that could not be read (rate limited, server error) is a coverage gap for the "
                 "repository, not a finding that its default branch is unprotected",
        "contract": C + " §4", "origin": "collectors/codehost-github: any failed protection read counts as no protection",
        "deviation": "GITHUB-D1", "services": CODEHOST_SVC, "files": gh_files(),
        "steps": [collect(GH, protocol_checks("codehost-github", ["{canary_token}"]) + READ_ONLY + [
            coverage_has(GH_DOC, {"asset": "repo:github/acme/limited", "status": "gap", "reason": {"$regex": "protection"}},
                         {"asset": "repo:github/acme/flaky", "status": "gap", "reason": {"$regex": "protection"}},
                         {"asset": "repo:github/acme/fine", "status": "ok"}),
            {"json": GH_DOC, "subset": {"findings": {"$not_contains": [{"check": "repo.default_branch_unprotected"}]}}}],
            env=GH_ENV, path=True)]},
        gh_case_files({"token": "{canary_token}", "routes": limited}))

    paged = {"/users/acme/repos": {"items": [gh_repo(n) for n in ("a", "b", "c")], "page_size": 2},
             "/user/repos": {"items": [gh_repo(n) for n in ("a", "b", "c")], "page_size": 2}}
    for n in ("a", "b", "c"):
        paged.update(gh_routes(f"acme/{n}", protection={"body": {"url": "x"}}))
    write_case(GH, "repositories-on-several-pages", {
        "title": "Every page of the repository list is read (Link rel=\"next\"): a repository on the second page is "
                 "checked, not silently missing",
        "contract": C + " §4", "origin": "collectors/codehost-github: the first page of 100 only",
        "deviation": "GITHUB-D2", "services": CODEHOST_SVC, "files": gh_files(),
        "steps": [collect(GH, protocol_checks("codehost-github", ["{canary_token}"]) + READ_ONLY + [
            coverage_has(GH_DOC, *[{"asset": f"repo:github/acme/{n}", "status": "ok"} for n in ("a", "b", "c")]),
            {"prom": "run/codehost-github.prom", "has": [{"name": "security_repos_total", "labels": {"owner": "acme"}, "value": 3}]}],
            env=GH_ENV, path=True)]},
        gh_case_files({"token": "{canary_token}", "routes": paged}))


# ==================================================================================================================
# codehost-gitea
# ==================================================================================================================
GT = "collector-codehost-gitea"
GT_DOC = "run/codehost-gitea.findings.json"


def gt_repo(full, private=False, archived=False, branch="main", **extra):
    owner, name = full.split("/")
    return dict({"name": name, "full_name": full, "owner": {"login": owner}, "private": private, "internal": False,
                 "archived": archived, "default_branch": branch, "mirror": False}, **extra)


def gt_rule(name, push=False, whitelist=False, approvals=0, checks=False):
    return {"rule_name": name, "branch_name": name, "enable_push": push, "enable_push_whitelist": whitelist,
            "required_approvals": approvals, "enable_status_check": checks}


def gt_files(mode="0600"):
    return {"instance.json": "instance.json", "codehost-api.json": "api.json",
            "gitea.token": {"text": "{canary_token}\n", "mode": mode}, "data/.keep": {"text": ""}}


def gt_case_files(routes, entries=None):
    entries = entries or [{"type": "gitea", "url": "{svc_codehost}", "owner": "lab", "token_file": "{sandbox}/gitea.token"}]
    return {"instance.json": {"name": "conformance", "codehost": entries},
            "api.json": {"token": "{canary_token}", "routes": routes}, "mock_codehost.py": tool("mock_codehost.py")}


def gitea_cases(write_case):
    """codehost-gitea: cases written here."""
    v1 = "/api/v1"
    routes = {
        f"{v1}/orgs/lab/repos": {"items": [
            gt_repo("lab/app"), gt_repo("lab/site"),
            gt_repo("lab/mirror", private=True, mirror=True, original_url="http://example.org/up.git"),
            gt_repo("lab/rel", branch="release/v1"), gt_repo("lab/old", archived=True), gt_repo("lab/legacy")]},
        f"{v1}/repos/lab/app/branch_protections": {"body": [gt_rule("main", checks=True), gt_rule("dev*", push=True)]},
        f"{v1}/repos/lab/app/keys": {"items": [{"id": 1, "title": "deploy", "read_only": False,
                                                "created_at": "2025-03-04T05:06:07Z",
                                                "key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIConformanceOnly"},
                                               {"id": 2, "title": "reader", "read_only": True, "created_at": "2025-03-05T00:00:00Z"}]},
        f"{v1}/repos/lab/site/branch_protections": {"body": []},
        f"{v1}/repos/lab/site/keys": {"items": []},
        f"{v1}/repos/lab/mirror/branch_protections": {"body": [gt_rule("main", push=True, approvals=1)]},
        f"{v1}/repos/lab/rel/branch_protections": {"body": [gt_rule("main", push=True),
                                                            gt_rule("release/*", push=True, whitelist=True, approvals=2)]},
        f"{v1}/users/solo/repos": {"items": [gt_repo("solo/pub"), gt_repo("solo/secret", private=True)]},
        f"{v1}/repos/solo/pub/branch_protections": {"body": [gt_rule("main", approvals=1)]},
    }
    entries = [{"type": "gitea", "url": "{svc_codehost}", "owner": "lab", "token_file": "{sandbox}/gitea.token"},
               {"type": "forgejo", "url": "{svc_codehost}/", "owner": "solo", "token_file": "{sandbox}/gitea.token",
                "include_private": False},
               {"type": "github", "owner": "elsewhere", "gh_user": "x"}]
    write_case(GT, "repository-posture", {
        "title": "Gitea/Forgejo repository posture, read-only: default branch without a rule or open to direct push, a "
                 "protected branch without approvals, a pull mirror over plain http, write deploy keys; a glob rule "
                 "(release/*) applies to its branches; archived repositories and (include_private: false) private ones "
                 "skipped; an owner that is a user, not an organisation; an unreadable branch protection is a gap; the "
                 "token never reaches the output",
        "contract": C, "origin": "collectors/codehost-gitea",
        "services": CODEHOST_SVC, "files": gt_files(),
        "steps": [collect(GT, protocol_checks("codehost-gitea", ["{canary_token}"]) + READ_ONLY + [
            findings_has(GT_DOC,
                         {"check": "repo.protection_no_approvals", "asset": "repo:gitea/127.0.0.1/lab/app", "severity": "low",
                          "title": "default branch 'main' is protected but merges need no approving review"},
                         {"check": "repo.deploy_key_write", "asset": "repo:gitea/127.0.0.1/lab/app/deploy-key/deploy",
                          "title": "write-enabled deploy key 'deploy' (created 2025-03-04)", "layer": "identity"},
                         {"check": "repo.default_branch_unprotected", "asset": "repo:gitea/127.0.0.1/lab/site", "severity": "high",
                          "title": "public repo: default branch 'main' can be pushed to directly (no branch protection rule)"},
                         {"check": "repo.default_branch_unprotected", "asset": "repo:gitea/127.0.0.1/lab/mirror",
                          "severity": "medium", "title": "private repo: default branch 'main' can be pushed to directly"},
                         {"check": "repo.mirror_unverified_remote", "asset": "repo:gitea/127.0.0.1/lab/mirror"}),
            {"json": GT_DOC, "subset": {"findings": {"$not_contains": [
                {"asset": "repo:gitea/127.0.0.1/lab/rel"}, {"asset": "repo:forgejo/127.0.0.1/solo/pub"},
                {"asset": "repo:gitea/127.0.0.1/lab/app/deploy-key/reader"}]},
                "coverage": {"$not_contains": [{"asset": "repo:gitea/127.0.0.1/lab/old"},
                                               {"asset": "repo:forgejo/127.0.0.1/solo/secret"}]}}},
            coverage_has(GT_DOC, {"asset": "repo:gitea/127.0.0.1/lab/rel", "status": "ok"},
                         {"asset": "repo:forgejo/127.0.0.1/solo/pub", "status": "ok"},
                         {"asset": "repo:gitea/127.0.0.1/lab/legacy", "status": "gap",
                          "reason": "cannot read branch protection: HTTP 404"}),
            {"json": "run/raw/codehost-gitea/repos.json", "subset": {"solo/pub": {"protected": True, "required_approvals": 1}}},
            {"prom": "run/codehost-gitea.prom", "has": [
                {"name": "security_repos_total", "labels": {"owner": "lab"}, "value": 4},
                {"name": "security_repos_public_without_protection", "labels": {"owner": "lab"}, "value": 1},
                {"name": "security_repos_total", "labels": {"owner": "solo"}, "value": 1}]}])]},
        gt_case_files(routes, entries))

    write_case(GT, "token-file-readable-by-others", {
        "title": "A token file readable by group or others is refused: the owner is a coverage gap and no request is sent",
        "contract": C + " §2", "origin": "collectors/codehost-gitea read_token",
        "services": CODEHOST_SVC, "files": gt_files("0644"),
        "steps": [collect(GT, protocol_checks("codehost-gitea", ["{canary_token}"]) + READ_ONLY + [
            coverage_has(GT_DOC, {"asset": "codehost:gitea/lab", "status": "gap", "reason": {"$regex": "0600"}}),
            {"absent": ".svc-codehost-requests.log"}])]},
        gt_case_files(routes))

    paged = {f"{v1}/orgs/lab/repos": {"items": [gt_repo(f"lab/r{i}") for i in (1, 2, 3)], "page_size": 2}}
    for i in (1, 2, 3):
        paged[f"{v1}/repos/lab/r{i}/branch_protections"] = {"body": [gt_rule("main", approvals=1)]}
    write_case(GT, "server-page-size-below-50", {
        "title": "A server that answers fewer items per page than asked (its own maximum page size) is read to the end "
                 "(Link rel=\"next\" / X-Total-Count): the repositories after the first page are checked",
        "contract": C + " §4", "origin": "collectors/codehost-gitea: a page shorter than 50 is taken as the last one",
        "deviation": "GITEA-D1", "services": CODEHOST_SVC, "files": gt_files(),
        "steps": [collect(GT, protocol_checks("codehost-gitea", ["{canary_token}"]) + READ_ONLY + [
            coverage_has(GT_DOC, *[{"asset": f"repo:gitea/127.0.0.1/lab/r{i}", "status": "ok"} for i in (1, 2, 3)]),
            {"prom": "run/codehost-gitea.prom", "has": [{"name": "security_repos_total", "labels": {"owner": "lab"}, "value": 3}]}])]},
        gt_case_files(paged))

    moved = {f"{v1}/orgs/lab/repos": {"redirect": f"{v1}/moved/lab/repos"},
             f"{v1}/users/lab/repos": {"redirect": f"{v1}/moved/lab/repos"},
             f"{v1}/moved/lab/repos": {"items": [gt_repo("lab/app")]},
             f"{v1}/repos/lab/app/branch_protections": {"body": [gt_rule("main", approvals=1)]}}
    write_case(GT, "token-not-sent-to-another-host", {
        "title": "The API token is never sent to another host: a redirect to another host name is not followed (the "
                 "owner is a gap), so the credential does not leave for wherever the redirect points",
        "contract": C + " §2", "origin": "collectors/codehost-gitea: urllib follows the redirect with the Authorization header",
        "deviation": "GITEA-D2", "services": CODEHOST_SVC, "files": gt_files(),
        "steps": [collect(GT, protocol_checks("codehost-gitea", ["{canary_token}"]) + READ_ONLY + [
            coverage_has(GT_DOC, {"asset": "codehost:gitea/lab", "status": "gap", "reason": {"$regex": "redirect"}})])]},
        gt_case_files(moved))


# ==================================================================================================================
# detection
# ==================================================================================================================
def detection_cases(write_case):
    """detection: cases written here."""
    return None


# ==================================================================================================================
# events (contract events/1.0)
# ==================================================================================================================
def events_cases(write_case):
    """events (contract events/1.0): cases written here."""
    return None


def cases(write_case):
    agent_cases(write_case)
    exposure_cases(write_case)
    github_cases(write_case)
    gitea_cases(write_case)
    detection_cases(write_case)
    events_cases(write_case)
