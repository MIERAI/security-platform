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
def github_cases(write_case):
    """codehost-github: cases written here."""
    return None


# ==================================================================================================================
# codehost-gitea
# ==================================================================================================================
def gitea_cases(write_case):
    """codehost-gitea: cases written here."""
    return None


# ==================================================================================================================
# detection
# ==================================================================================================================
def detection_cases(write_case):
    """detection: cases written here."""
    return None


# ==================================================================================================================
# events (contract events/1.0)
# ==================================================================================================================
EVENTS = "events"
NOW = 1795608000                     # 2026-11-25T12:00:00Z: every case runs with this --now
EV_ARGS = ["--config", "{sandbox}/events.json", "--state", "{sandbox}/state", "--summary", "{sandbox}/out/summary.json",
           "--now", str(NOW)]
AUTH_1 = ("2026-11-25T11:40:00+00:00 lab sshd[101]: Accepted publickey for ops from 10.0.0.1 port 50000 ssh2\n"
          "2026-11-25T11:41:00+00:00 lab sshd[102]: Failed password for invalid user admin from 192.0.2.7 port 50001 ssh2\n"
          "2026-11-25T11:42:00+00:00 lab sudo:      ops : TTY=pts/0 ; PWD=/home/ops ; USER=root ; COMMAND=/usr/bin/id\n"
          "2026-11-25T11:43:00+00:00 lab cron[5]: unrelated\n")
AUTH_2 = AUTH_1 + ("2026-11-25T11:55:00+00:00 lab sshd[103]: Accepted publickey for ops from 10.0.0.1 port 50002 ssh2\n"
                   "2026-11-25T11:56:00+00:00 lab sshd[104]: Accepted publickey for ops from 10.0.0.9 port 50003 ssh2\n")


def events_config(sources, loki=None):
    return {"loki": dict({"url": "{svc_obs}/loki/api/v1/push"}, **(loki or {})), "sources": sources}


def auth_source(name="lab-auth", **kw):
    return dict({"name": name, "type": "command", "host": "lab", "parser": "openssh", "argv": ["cat", "{sandbox}/auth.log"]},
                **kw)


def ship(expect, name="ship", exit_=0, env=None, extra_args=(), **kw):
    ex = {"impl": EVENTS, "args": EV_ARGS + list(extra_args), "writes_only_under": ["state", "out", "pushed", "leak"]}
    if env:
        ex["env"] = env
    step = {"name": name, "exec": ex, "exit": exit_, "expect": expect + [{"absent": "mutations.log"}, {"writes_only_under": True}]}
    step.update(kw)
    return step


def events_cases(write_case):
    C_EV = "events/1.0"
    svc = [{"name": "obs", "argv": ["{python}", "{case}/mock_events.py"]}]
    mock = {"mock_events.py": tool("mock_events.py")}
    write_case(EVENTS, "baseline-then-new-lines", {
        "title": "The first run of a source is a baseline (cursor stored, nothing novel); the next run ships only the lines "
                 "after the cursor, with structured metadata, and marks a login from a new address novel; every run "
                 "sends a heartbeat line",
        "contract": C_EV, "origin": "tests/test_events.py; events/ship.py CommandSource",
        "services": svc, "files": {"out/.keep": {"text": ""}, "events.json": {"json": events_config([auth_source()])}, "auth.log": {"text": AUTH_1}},
        "steps": [
            ship([{"json": "out/summary.json", "subset": {"sources": {"lab-auth": {"ok": True, "shipped": 3, "baseline": True,
                                                                                "events": {"ssh_login_success": 1, "ssh_login_failure": 1, "sudo": 1}}}}},
                  {"file": "pushed/0001.json", "regex": ['"source": "auth"', '"host": "lab"', '"novel": "false"',
                                                         '"event": "ssh_login_failure"', '"src_ip": "192.0.2.7"']},
                  {"file": "pushed/0002.json", "regex": ['heartbeat.{1,3}: .{1,3}lab-auth', '"event": "heartbeat"']},
                  {"exists": "state/lab-auth.json"}], name="first run (baseline)"),
            ship([{"json": "out/summary.json", "subset": {"sources": {"lab-auth": {"ok": True, "shipped": 2, "baseline": False}}}},
                  {"file": "pushed/0003.json", "regex": ['"src_ip": "10.0.0.9", "novel": "true"',
                                                         '"src_ip": "10.0.0.1", "novel": "false"']},
                  {"file": "pushed/0003.json", "regex": ["^(?!.*192\\.0\\.2\\.7)"]}],
                 name="second run (two new lines)", files={"auth.log": {"text": AUTH_2}})]}, mock)

    write_case(EVENTS, "push-failure-keeps-the-cursor", {
        "title": "A failed push keeps the cursor (exit 1, no state written); the next run delivers the same events "
                 "(at least once)",
        "contract": C_EV, "origin": "events/ship.py main: the cursor is stored only after the push",
        "services": svc, "files": {"out/.keep": {"text": ""}, "events.json": {"json": events_config([auth_source()])}, "auth.log": {"text": AUTH_1},
                                   "loki-fail": {"text": ""}},
        "steps": [
            ship([{"json": "out/summary.json", "subset": {"sources": {"lab-auth": {"ok": False, "error": {"$regex": "500"}}}}},
                  {"absent": "state/lab-auth.json"}, {"absent": "pushed/0001.json"},
                  {"stderr": {"regex": ["lab-auth: FAILED .*cursor kept"]}}], name="store down", exit_=1),
            ship([{"json": "out/summary.json", "subset": {"sources": {"lab-auth": {"ok": True, "shipped": 3}}}},
                  {"file": "pushed/0001.json", "regex": ['"event": "sudo"']}, {"exists": "state/lab-auth.json"}],
                 name="store back", remove=["loki-fail"])]}, mock)

    write_case(EVENTS, "one-failing-source-does-not-stop-the-others", {
        "title": "One failing source does not stop the others: they ship, it is reported failed, the exit status is 1",
        "contract": C_EV, "origin": "events/ship.py main",
        "services": svc, "files": {"out/.keep": {"text": ""}, "events.json": {"json": events_config([
            auth_source("broken", argv=["sh", "-c", "echo boom >&2; exit 3"]), auth_source()])}, "auth.log": {"text": AUTH_1}},
        "steps": [ship([{"json": "out/summary.json", "subset": {"sources": {
            "broken": {"ok": False, "error": {"$regex": "rc=3"}}, "lab-auth": {"ok": True, "shipped": 3}}}},
            {"absent": "state/broken.json"}, {"exists": "state/lab-auth.json"}], exit_=1)]}, mock)

    write_case(EVENTS, "token-file-readable-by-others-is-refused", {
        "title": "A push token in a file readable by group/others is refused: the source fails, nothing is pushed, and the "
                 "token never appears in the summary, the state or the output",
        "contract": C_EV + " (secrets)", "origin": "events/ship.py read_secret",
        "services": svc, "files": {"out/.keep": {"text": ""}, "events.json": {"json": events_config([auth_source()], {"token_file": "{sandbox}/secrets/loki.token"})},
                                   "auth.log": {"text": AUTH_1}, "secrets/loki.token": {"text": "{canary_token}\n", "mode": "0644"}},
        "steps": [ship([{"json": "out/summary.json", "subset": {"sources": {"lab-auth": {"ok": False,
                                                                                       "error": {"$regex": "group/others|chmod 600"}}}}},
                        {"absent": "pushed/0001.json"}, {"absent": "state/lab-auth.json"},
                        {"no_secret": ["{canary_token}"], "in": ".", "except": ["secrets"]}], exit_=1)]}, mock)

    write_case(EVENTS, "dry-run-prints-and-keeps-state", {
        "title": "--dry-run prints the push body and changes nothing: no push, no state",
        "contract": C_EV, "origin": "events/ship.py --dry-run",
        "services": svc, "files": {"out/.keep": {"text": ""}, "events.json": {"json": events_config([auth_source()])}, "auth.log": {"text": AUTH_1}},
        "steps": [ship([{"stdout": {"regex": ['"streams"', '"ssh_login_success"']}}, {"absent": "pushed/0001.json"},
                        {"absent": "state/lab-auth.json"}], extra_args=["--dry-run"])]}, mock)

    write_case(EVENTS, "bad-source-name", {
        "title": "A source name that is not letters, digits, . _ - (it names the state file) is refused before anything runs",
        "contract": C_EV, "origin": "events/ship.py main",
        "services": svc, "files": {"out/.keep": {"text": ""}, "events.json": {"json": events_config([auth_source("../escape")])}, "auth.log": {"text": AUTH_1}},
        "steps": [ship([{"stderr": {"regex": ["letters, digits"]}}, {"absent": "pushed/0001.json"}], exit_={"not": 0})]}, mock)

    gh_canary = "{canary_token}"
    me = [200, {"login": "acme-bot"}]
    base_routes = {"/user": me, "/user/keys": [200, [{"id": 1, "title": "laptop", "created_at": "2026-01-01T00:00:00Z"}]],
                   "/user/gpg_keys": [404, {"message": "Not Found"}], "/user/ssh_signing_keys": [200, []],
                   "/user/repos": [200, [{"full_name": "acme-bot/site", "visibility": "private", "owner": {"login": "acme-bot"},
                                          "pushed_at": "2026-11-01T00:00:00Z"}]],
                   "/repos/acme-bot/site/keys": [200, []], "/repos/acme-bot/site/hooks": [200, []],
                   "/user/installations": [200, {"installations": []}], "/users/acme-bot/events": [200, []]}
    changed = dict(base_routes, **{"/user/keys": [200, [{"id": 1, "title": "laptop", "created_at": "2026-01-01T00:00:00Z"},
                                                         {"id": 2, "title": "unknown", "created_at": "2026-11-25T11:00:00Z"}]],
                                   "/user/repos": [200, [{"full_name": "acme-bot/site", "visibility": "public",
                                                          "owner": {"login": "acme-bot"}, "pushed_at": "2026-11-01T00:00:00Z"}]]})
    gh_src = {"name": "gh", "type": "github-account", "host": "acme-bot", "api": "{svc_obs}", "token_env": "EV_GH_TOKEN"}
    write_case(EVENTS, "code-host-account-changes", {
        "title": "Code host account: the first snapshot is a baseline; a new SSH key and a repository made public are "
                 "shipped as events (source codehost); an endpoint the token cannot read is recorded as unsupported; only "
                 "GET requests; the token never appears in the output",
        "contract": C_EV, "origin": "events/ship.py GitHubAccountSource",
        "services": svc, "files": {"out/.keep": {"text": ""}, "events.json": {"json": events_config([gh_src])}, "api.json": {"json": base_routes}},
        "steps": [
            ship([{"json": "out/summary.json", "subset": {"sources": {"gh": {"ok": True, "shipped": 0, "baseline": True,
                                                                         "unsupported": {"/user/gpg_keys": 404}}}}}],
                 name="baseline", env={"EV_GH_TOKEN": gh_canary}),
            ship([{"json": "out/summary.json", "subset": {"sources": {"gh": {"ok": True, "shipped": 2,
                                                                         "events": {"ssh_key_added": 1, "repo_made_public": 1}}}}},
                  {"file": "pushed/0002.json", "regex": ['"source": "codehost"', '"event": "ssh_key_added"',
                                                         '"event": "repo_made_public"']},
                  {"no_secret": [gh_canary], "in": "."}],
                 name="a key added, a repository made public", env={"EV_GH_TOKEN": gh_canary},
                 files={"api.json": {"json": changed}})]}, mock)

    redirect = dict(base_routes, **{"/user/gpg_keys": {"redirect": "/elsewhere"}, "/elsewhere": [200, []]})
    write_case(EVENTS, "credentials-not-sent-to-another-host", {
        "title": "A redirect to another host does not take the API token along",
        "contract": C_EV + " (secrets)", "origin": "events/ship.py HTTP: urllib copies the Authorization header to the "
                                                   "redirect target", "deviation": "EVENTS-D1",
        "services": svc, "files": {"out/.keep": {"text": ""}, "events.json": {"json": events_config([gh_src])}, "api.json": {"json": redirect}},
        "steps": [ship([{"absent": "leak/auth.txt"}], env={"EV_GH_TOKEN": gh_canary}, exit_={"in": [0, 1]})]}, mock)


def cases(write_case):
    agent_cases(write_case)
    exposure_cases(write_case)
    github_cases(write_case)
    gitea_cases(write_case)
    detection_cases(write_case)
    events_cases(write_case)
