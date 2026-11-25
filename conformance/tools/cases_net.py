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
EXPOSURE = "collector-exposure"
EXP_DOC = "run/exposure.findings.json"
NMAP_VERSION = "Nmap version 7.95 ( https://nmap.org )"


def exposure_files(spec, instance, **extra):
    """Sandbox files of an exposure case: the instance, the fake nmap scenario and the programs on PATH (nmap, and
    python for the reference, which runs its probe as `python -` on a local vantage)."""
    return dict({"instance.json": {"json": instance}, "nmap.json": {"json": spec}, "bin/nmap": wrapper("fake_nmap.py"),
                 "bin/python": {"text": '#!/bin/sh\nexec "{python}" "$@"\n', "mode": "0755"},
                 "data/.keep": {"text": ""}}, **extra)


def exposure_collect(expect, env=None, **kw):
    return collect(EXPOSURE, expect, env=dict({"FAKE_NMAP_SPEC": "{sandbox}/nmap.json"}, **(env or {})), path=True,
                   writes=("run", "nmaplog"), **kw)


def exposure_instance(targets, **cfg):
    return {"name": "conformance", "exposure": dict({"discovery": [{"type": "static", "targets": targets}],
                                                     "vantage": {"type": "local"}}, **cfg)}


def exposure_cases(write_case):
    web = {"name": "web", "address": "127.0.0.1"}
    targets_svc = [{"name": "web", "argv": ["{python}", "{case}/mock_http_targets.py"]}]
    tools = {"fake_nmap.py": tool("fake_nmap.py"), "mock_http_targets.py": tool("mock_http_targets.py")}
    ep = {"$regex": r"^net-endpoint:web@127\.0\.0\.1:\d+$"}
    spec = {"version": NMAP_VERSION, "hosts": {
        "127.0.0.1": {"ports": [["svc:web", "open", "http"], ["svc:web:closed1", "open", "telnet"],
                                ["svc:web:closed2", "open", "postgresql"], [8080, "filtered", "http-proxy"],
                                [9090, "closed", None]]},
        "192.0.2.10": {"status": "down"}, "127.0.0.4": {"ports": []}, "127.0.0.5": {"ports": []}}}
    inst = exposure_instance([web, {"name": "down", "address": "192.0.2.10"}], extra_ports="18443,20000-20010")
    inst["exposure"]["discovery"][0]["cidrs"] = ["127.0.0.4/31"]
    write_case(EXPOSURE, "open-services-by-fingerprint", {
        "title": "Open ports seen from the vantage point (nmap from the vantage, recorded XML): an HTTP service is "
                 "classified by its answers (unauthenticated Prometheus and Loki APIs, OTLP ingest), non-HTTP services by "
                 "nmap's name; filtered and closed ports are not exposure; a down host nobody vouched for is a gap, an "
                 "empty address of a CIDR range is not; the probe sends GET requests only",
        "contract": C, "origin": "collectors/exposure, remote/vantage_probe.py",
        "files": exposure_files(spec, inst),
        "services": targets_svc,
        "steps": [exposure_collect(protocol_checks("exposure") + [
            findings_has(EXP_DOC,
                         {"check": "prometheus.unauth_read", "asset": ep, "severity": "medium", "layer": "network",
                          "kind": "detection", "title": {"$regex": r"^Prometheus query API without auth .* \(127\.0\.0\.1:\d+\)$"},
                          "evidence": {"$regex": r"^raw/exposure/probe\.json#127\.0\.0\.1/\d+$"}},
                         {"check": "loki.unauth", "asset": ep, "severity": "high"},
                         {"check": "otlp.unauth_ingest", "asset": ep, "severity": "low"},
                         {"check": "telnet.open", "asset": ep, "severity": "high"},
                         {"check": "db.reachable", "asset": ep, "title": {"$regex": r"\(postgresql\)"}}),
            {"json": EXP_DOC, "subset": {"findings": {"$len": 5}, "collector": {"tools": {"nmap": NMAP_VERSION}}}},
            coverage_has(EXP_DOC, {"asset": "host:web", "status": "ok"}, {"asset": "net-endpoint:web@127.0.0.1", "status": "ok"},
                         {"asset": "host:down", "status": "gap", "reason": "no open port seen from the vantage point (down or filtered)"}),
            {"json": EXP_DOC, "subset": {"coverage": {"$not_contains": [{"asset": "host:127.0.0.4"}, {"asset": "host:127.0.0.5"},
                                                                         {"asset": "net-endpoint:127.0.0.4@127.0.0.4"}]}}},
            {"json": "run/raw/exposure/probe.json", "subset": {"targets": ["127.0.0.1", "192.0.2.10", "127.0.0.4", "127.0.0.5"],
                                                               "hosts": {"127.0.0.1": {"8080": {"$absent": True}, "9090": {"$absent": True}}}}},
            {"json": "run/raw/exposure/devices.json", "subset": {"$len": 4}},
            {"prom": "run/exposure.prom", "has": [{"name": "security_exposure_open_ports", "value": 3},
                                                 {"name": "security_exposure_unauth_services", "value": 4}]},
            {"file": "nmaplog/argv.log", "regex": [r'"--top-ports", "1000"', r'"-p", "22,53,.*,18443,20000-20010"', r'"--version"']},
            {"absent": "nmaplog/injected"}, {"absent": ".svc-web.MUTATION"},
            {"file": ".svc-web.requests", "regex": [r"^GET /api/v1/status/buildinfo$"]}])]},
        tools)

    fail = {"rc": 1, "stderr": "nmap: Failed to open device"}
    write_case(EXPOSURE, "nmap-failure-is-a-vantage-gap", {
        "title": "nmap failing on the vantage is a `vantage` coverage gap inside a valid document (exit 0), not a "
                 "clean result and not a crash",
        "contract": C + " §5", "origin": "collectors/exposure",
        "files": exposure_files(fail, exposure_instance([web])),
        "steps": [exposure_collect(protocol_checks("exposure") + [
            coverage_has(EXP_DOC, {"asset": "vantage", "status": "gap", "reason": {"$regex": "^probe failed rc=1: "}},
                         {"asset": "host:web", "status": "ok"}),
            {"json": EXP_DOC, "subset": {"findings": [], "metrics": []}}])]},
        tools)

    evil = "-iL/etc/hosts"
    write_case(EXPOSURE, "target-is-never-an-nmap-option", {
        "title": "A target address that is not an address (here an nmap option) never reaches nmap's command line: it "
                 "is a coverage gap for that host and the other targets are scanned",
        "contract": C + " §4", "origin": "collectors/exposure: discovery addresses are passed to nmap unchecked",
        "deviation": "EXPOSURE-D1",
        "files": exposure_files({"hosts": {"127.0.0.1": {"ports": []}}},
                                exposure_instance([web, {"name": "evil", "address": evil}])),
        "steps": [exposure_collect(protocol_checks("exposure") + [
            {"absent": "nmaplog/injected"},
            coverage_has(EXP_DOC, {"asset": "host:evil", "status": "gap", "reason": {"$regex": "not an IP address or host name"}}),
            {"json": "run/raw/exposure/probe.json", "subset": {"targets": ["127.0.0.1"]}}])]},
        tools)

    timed = {"hosts": {"127.0.0.1": {"timedout": True, "ports": [["svc:web:closed1", "open", "telnet"]]}}}
    write_case(EXPOSURE, "timed-out-host-is-a-gap", {
        "title": "An address nmap gave up on (host timeout) is a coverage gap: the ports it saw are reported, but a "
                 "partial scan does not cover the address (no `fixed` for what it did not get to)",
        "contract": C + " §4-5", "origin": "collectors/exposure: a partial nmap result counts as a complete one",
        "deviation": "EXPOSURE-D2",
        "files": exposure_files(timed, exposure_instance([web])),
        "services": targets_svc,
        "steps": [exposure_collect(protocol_checks("exposure") + [
            coverage_has(EXP_DOC, {"asset": "net-endpoint:web@127.0.0.1", "status": "gap", "reason": {"$regex": "timed out"}}),
            findings_has(EXP_DOC, {"check": "telnet.open", "asset": ep}),
            {"file": "nmaplog/argv.log", "regex": [r'"--host-timeout", "30m"']}])]},
        tools)

    write_case(EXPOSURE, "classification-and-discovery", {
        "title": "Re-classification of a recorded probe result (SP_EXPOSURE_RAW) after discovery from an overlay network "
                 "(fake tailscale), static targets and an asset file: every fingerprint class, verified hosts with nothing "
                 "open are covered, offline and out-of-scope assets, discovery failures are gaps",
        "contract": C, "origin": "collectors/exposure classify(); adapters/discovery.py",
        "files": {"instance.json": {"json": {"name": "conformance",
                                             "scope": [{"names": ["laptop"], "scope": ["host"]},
                                                       {"names": ["phone"], "scope": ["exposure"], "offline": "expected"}],
                                             "exposure": {"discovery": [
                                                 {"type": "tailscale"},
                                                 {"type": "static", "targets": [{"name": "edge", "address": "198.51.100.7"}]},
                                                 {"type": "static", "cidrs": ["10.0.0.0/16"]},
                                                 {"type": "file", "path": "{sandbox}/assets.json", "max_age": 3600},
                                                 {"type": "aws-vpc"}]}}},
                  "assets.json": {"json": [{"name": "filehost", "address": "198.51.100.8"}]},
                  "tailscale.json": {"json": TAILSCALE},
                  "bin/tailscale": {"text": '#!/bin/sh\ncat "{sandbox}/tailscale.json"\n', "mode": "0755"},
                  "probe.json": {"json": RAW_PROBE}, "data/.keep": {"text": ""}},
        "steps": [collect(EXPOSURE, protocol_checks("exposure") + [
            findings_has(EXP_DOC,
                         {"check": "overlay.node_key_expiry_disabled", "asset": "host:nas", "layer": "identity", "needs_human": True},
                         {"check": "http.catch_all_unverified", "asset": "net-endpoint:nas@100.64.0.1:3000"},
                         {"check": "alertmanager.unauth", "asset": "net-endpoint:nas@100.64.0.1:9093"},
                         {"check": "ollama.unauth", "asset": "net-endpoint:nas@100.64.0.1:11434"},
                         {"check": "prometheus.unauth_read", "asset": "net-endpoint:nas@100.64.0.1:9090"},
                         {"check": "prometheus.unauth_remote_write", "asset": "net-endpoint:nas@100.64.0.1:9090"},
                         {"check": "prometheus.admin_api_unauth", "asset": "net-endpoint:nas@100.64.0.1:9090"},
                         {"check": "blackbox.open_probe", "asset": "net-endpoint:edge@198.51.100.7:9115"},
                         {"check": "otlp.unauth_ingest", "asset": "net-endpoint:edge@198.51.100.7:4318"},
                         {"check": "metrics.unauth", "asset": "net-endpoint:edge@198.51.100.7:8080"},
                         {"check": "http.unauth_root", "asset": "net-endpoint:edge@198.51.100.7:8081"},
                         {"check": "telnet.open", "asset": "net-endpoint:edge@198.51.100.7:23"},
                         {"check": "smb.reachable", "asset": "net-endpoint:edge@198.51.100.7:445",
                          "title": "SMB (microsoft-ds) is reachable from the vantage point (198.51.100.7:445)"},
                         {"check": "db.reachable", "asset": "net-endpoint:edge@198.51.100.7:6379",
                          "title": "database port reachable from the vantage point (6379) (198.51.100.7:6379)"},
                         {"check": "tempo.unauth_read", "asset": "net-endpoint:203.0.113.9@203.0.113.9:3200"}),
            {"json": EXP_DOC, "subset": {"findings": {"$not_contains": [
                {"asset": "net-endpoint:edge@198.51.100.7:8443"}, {"asset": "host:printer"},
                {"check": "overlay.node_key_expiry_disabled", "asset": "host:scanner"}]}}},
            coverage_has(EXP_DOC,
                         {"asset": "discovery:static", "status": "gap",
                          "reason": "ValueError: CIDR 10.0.0.0/16 has 65536 addresses (max_hosts 1024)"},
                         {"asset": "discovery:aws-vpc", "status": "gap",
                          "reason": "NotImplementedError: discovery adapter 'aws-vpc' is a documented future adapter"},
                         {"asset": "host:old", "status": "gap", "reason": "offline at scan time"},
                         {"asset": "net-endpoint:printer@100.64.0.2", "status": "ok"},
                         {"asset": "host:filehost", "status": "gap",
                          "reason": "no open port seen from the vantage point (down or filtered)"},
                         {"asset": "host:scanner", "status": "ok"}),
            {"json": EXP_DOC, "subset": {"coverage": {"$not_contains": [{"asset": "host:laptop"}, {"asset": "host:phone"}]},
                                         "collector": {"tools": {"nmap": NMAP_VERSION}}}},
            {"prom": "run/exposure.prom", "has": [{"name": "security_exposure_open_ports", "value": 13},
                                                 {"name": "security_exposure_unauth_services", "value": 11}]}],
            env={"SP_EXPOSURE_RAW": "{sandbox}/probe.json"}, path=True)]},
        {})


def r200(snippet, ctype="text/html"):
    return {"status": 200, "auth": False, "server": "", "ctype": ctype, "snippet": snippet}


def rerr(status, auth=False):
    return {"status": status, "auth": auth, "server": "", "location": ""}


TAILSCALE = {"Self": {"HostName": "scanner", "TailscaleIPs": ["100.64.0.10", "fd7a:115c:a1e0::a"], "Online": False, "OS": "linux"},
             "Peer": {"n1": {"HostName": "nas", "TailscaleIPs": ["fd7a:115c:a1e0::1", "100.64.0.1"], "Online": True, "OS": "linux"},
                      "n2": {"HostName": "printer", "TailscaleIPs": ["100.64.0.2"], "Online": True, "KeyExpiry": "2027-01-01T00:00:00Z"},
                      "n3": {"HostName": "old", "TailscaleIPs": ["100.64.0.3"], "Online": False, "KeyExpiry": "2027-01-01T00:00:00Z"},
                      "n4": {"HostName": "laptop", "TailscaleIPs": ["100.64.0.4"], "Online": True, "KeyExpiry": "2027-01-01T00:00:00Z"},
                      "n5": {"HostName": "phone", "TailscaleIPs": ["100.64.0.5"], "Online": False, "KeyExpiry": "2027-01-01T00:00:00Z"}}}
SAME = "<html><head><title>app</title></head></html>"
RAW_PROBE = {
    "targets": ["100.64.0.1", "100.64.0.2", "198.51.100.7", "198.51.100.8", "100.64.0.10"],
    "tools": {"nmap": NMAP_VERSION},
    "hosts": {
        "100.64.0.1": {
            "3000": {"nmap_service": "ppp", "scheme": "http", "paths": {p: r200(SAME) for p in (
                "/", "/metrics", "/api/tags", "/api/search", "/status", "/api/health", "/api/v1/applications")}},
            "9090": {"nmap_service": "zeus-admin", "scheme": "http", "paths": {
                "/": rerr(302), "/api/v1/status/buildinfo": r200('{"status":"success","data":{"version":"2.53.0"}}', "application/json"),
                "/api/v1/status/flags": {"status": 200, "auth": False, "fields": {
                    "web.enable-remote-write-receiver": "true", "web.enable-admin-api": "true", "web.enable-lifecycle": None}}}},
            "9093": {"nmap_service": "copycat", "scheme": "http", "paths": {
                "/api/v2/status": r200('{"cluster":{"status":"ready"},"config":{"original":"x"}}', "application/json")}},
            "11434": {"nmap_service": "unknown", "scheme": "http", "paths": {"/api/tags": r200('{"models":[]}', "application/json")}}},
        "100.64.0.2": {},
        "198.51.100.7": {
            "23": {"nmap_service": "telnet"},
            "445": {"nmap_service": "microsoft-ds"},
            "4318": {"nmap_service": "unknown", "scheme": "http", "paths": {"/": rerr(404), "/v1/traces": rerr(405)}},
            "6379": {"nmap_service": None},
            "8080": {"nmap_service": "http-proxy", "scheme": "http", "paths": {"/": rerr(401, True), "/metrics": r200("# HELP x\n")}},
            "8081": {"nmap_service": "blackice-icecap", "scheme": "http", "paths": {"/": r200("<html>ok</html>"), "/metrics": rerr(404)}},
            "8443": {"nmap_service": "https-alt", "scheme": "https", "paths": {"/": rerr(401, True), "/api/v1/write": rerr(405, True)}},
            "9115": {"nmap_service": "unknown", "scheme": "http", "paths": {
                "/": r200("<html><head><title>Blackbox Exporter</title>"), "/probe": rerr(400)}}},
        "198.51.100.8": {},
        "203.0.113.9": {"3200": {"nmap_service": "unknown", "scheme": "http", "paths": {
            "/api/search": r200('{"traces":[]}', "application/json"), "/": rerr(404)}}}}}


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
DET = "collector-detection"
DET_DOC = "run/detection.findings.json"
DET_PROM = "run/detection.prom"
AM_PAGE = """route:
  receiver: team
  routes:
    - receiver: oncall
      matchers: ['severity = "page"']
receivers:
  - name: team
    email_configs: [{to: team@example.org}]
  - name: oncall
    webhook_configs: [{url: "http://pager.example.org/hook"}]
"""
AM_NO_PAGE = """route:
  receiver: team
  routes:
    - receiver: blackhole
      matchers: [severity="page"]
receivers:
  - name: team
    email_configs: [{to: team@example.org}]
  - name: blackhole
"""
VERDICTS = """verdicts:
  - {fired_at: "{utc:-3600}", verdict: true_positive}
  - {fired_at: "{utc:-7200}", verdict: true_positive}
  - {fired_at: "{utc:-1800}", verdict: false_positive}
  - {fired_at: "{utc:-600}", verdict: benign}
  - {fired_at: "{utc:-900}", verdict: drill}
  - {fired_at: "{utc:-5184000}", verdict: false_positive}
  - {fired_at: "not a time", verdict: false_positive}
"""


def det_service(scenario, token=True):
    argv = ["{python}", "{case}/mock_obs.py", "--config", "{case}/" + scenario]
    return [{"name": "obs", "argv": argv + (["--token-file", "{sandbox}/loki.token"] if token else [])}]


def det_instance(detection, **extra):
    return dict({"name": "conformance", "detection": detection}, **extra)


def prom(*has):
    return {"prom": DET_PROM, "has": [dict(name=n, labels=lab, value=v) for n, lab, v in has]}


def detection_cases(write_case):
    common = {"mock_obs.py": tool("mock_obs.py")}
    write_case(DET, "no-detection-section", {
        "title": "An instance without a `detection:` section is a coverage gap, not a clean result; the rule-content age "
                 "is still measured from the catalog",
        "contract": C + " §4", "origin": "collectors/detection main",
        "files": {"instance.json": "instance.json", "data/.keep": {"text": ""}},
        "steps": [collect(DET, protocol_checks("detection") + [
            coverage_has(DET_DOC, {"asset": "detection-config:instance", "status": "gap",
                                   "reason": "no `detection:` section in the instance"},
                         {"asset": "detection-ruleset:catalog", "status": "ok"}),
            {"prom": DET_PROM, "families": ["security_detection_ruleset_age_days", "security_detection_ruleset_info"]}])]},
        {"instance.json": {"name": "conformance"}})

    healthy = {"sources": {"k8s-audit": {"lab": 120}, "auth": {"web-1": 2}, "codehost": {}},
               "rules": [{"name": "SecurityDetectionK8sPodExec", "health": "ok"},
                         {"name": "SecurityDetectionAuthSudoFailure", "health": "err"},
                         {"name": "SomethingElse", "health": "unknown"}],
               "am_original": AM_PAGE, "alerts": {"page": 12, "ticket": 3}, "require_token": True}
    write_case(DET, "pipeline-sources-ruler-routing", {
        "title": "Detection pipeline against fake Loki/Prometheus/Alertmanager read APIs: an expected source without a "
                 "line in its window (heartbeats count as lines) is silent (k8s-audit/auth high, others medium), a live "
                 "one is not; ruler with missing and failing rules; page route reaches a notifying receiver; alert "
                 "minutes per severity (through curl on an exec target); verdicts and drills; GET only, the bearer "
                 "token (0600 file) is sent and never written anywhere",
        "contract": C, "origin": "tests/test_detection_collector.py; collectors/detection",
        "files": {"instance.json": "instance.json", "loki.token": {"text": "{canary_token}\n", "mode": "0600"},
                  "data/detections/verdicts.yaml": {"text": VERDICTS},
                  "data/detections/drills/2026-a.yaml": {"text": 'id: d-a\naction_at: "2026-01-01T00:00:00"\nresult: pass\nttd_seconds: 90\n'},
                  "data/detections/drills/.hidden.yaml": {"text": 'id: hidden\naction_at: "{utc:-60}"\nresult: fail\n'}},
        "services": det_service("obs.json"),
        "steps": [collect(DET, protocol_checks("detection", ["{canary_token}"]) + [
            findings_has(DET_DOC,
                         {"check": "detection.source_silent", "asset": "log-source:k8s-audit/prod", "severity": "high",
                          "layer": "detection", "title": "no k8s-audit log lines from prod in the last 30m: detections for it are blind"},
                         {"check": "detection.source_silent", "asset": "log-source:auth/phone", "severity": "high",
                          "title": "no auth log lines from phone in the last 6h: detections for it are blind"},
                         {"check": "detection.source_silent", "asset": "log-source:codehost/acct-a", "severity": "medium"},
                         {"check": "detection.ruler_incomplete", "asset": "detection-ruler:log-store", "severity": "high",
                          "title": {"$regex": "^[0-9]+ catalog rule\\(s\\) not loaded, 1 failing evaluation in the log store's ruler$"}}),
            {"json": DET_DOC, "subset": {"findings": {"$not_contains": [
                {"asset": "log-source:k8s-audit/lab"}, {"asset": "log-source:auth/web-1"},
                {"check": "detection.page_route_missing"}, {"check": "detection.drill_overdue"},
                {"check": "detection.drill_failed"}]}}},
            coverage_has(DET_DOC, {"asset": "log-source:k8s-audit/lab", "status": "ok"},
                         {"asset": "detection-alertmanager:routing", "status": "ok"},
                         {"asset": "detection-alerts:history", "status": "ok"}, {"asset": "detection-drills:lab", "status": "ok"}),
            {"json": "run/raw/detection/ruler.json", "subset": {"unhealthy": ["SecurityDetectionAuthSudoFailure"]}},
            {"json": "run/raw/detection/source-auth.json", "subset": {"window": "6h", "seen": ["web-1"]}},
            prom(("security_detection_sources_live", {"source": "k8s-audit"}, 1),
                 ("security_detection_sources_expected", {"source": "k8s-audit"}, 2),
                 ("security_detection_sources_live", {"source": "codehost"}, 0),
                 ("security_detection_rules_unhealthy", {}, 1), ("security_detection_rules_loaded", {}, 2),
                 ("security_detection_page_route", {}, 1),
                 ("security_detection_alert_minutes_24h", {"severity": "page"}, 12),
                 ("security_detection_alert_minutes_24h", {"severity": "ticket"}, 3),
                 ("security_detection_alert_minutes_24h", {"severity": "info"}, 0),
                 ("security_detection_verdicts", {"result": "false_positive"}, 1),
                 ("security_detection_verdicts", {"result": "drill"}, 1),
                 ("security_detection_false_positive_ratio", {}, 0.25),
                 ("security_detection_drill_pass", {}, 1), ("security_detection_drill_ttd_seconds", {}, 90)),
            {"file": ".svc-obs-requests.log", "regex": [
                r'^GET /loki/api/v1/query sum by \(cluster\) \(count_over_time\(\{source="k8s-audit"\}\[30m\]\)\)$',
                r'^GET /loki/api/v1/query sum by \(host\) \(count_over_time\(\{source="auth"\}\[6h\]\)\)$',
                r'^GET /api/v1/query sum by \(severity\) \(count_over_time\(ALERTS\{component="security-detection",alertstate="firing"\}\[24h\]\)\)$']},
            {"exists": ".svc-obs-token-seen"}, {"absent": ".svc-obs-mutations.log"}])]},
        dict(common, **{"obs.json": healthy, "instance.json": det_instance({
            "log_store": {"url": "{svc_obs}", "token_file": "{sandbox}/loki.token"},
            "alert_history": {"url": "{svc_obs}", "exec": {"type": "local"}}, "alertmanager": {"url": "{svc_obs}"},
            "expected": {"k8s-audit": ["lab", "prod"], "auth": ["web-1", "phone"], "codehost": ["acct-a"]},
            "windows": {"auth": "6h"}, "drill_max_age": "36500d"})}))

    write_case(DET, "unreachable-store-and-no-page-route", {
        "title": "An unreachable log store or alert history is a gap for every check that needed it (never a pass); "
                 "a severity=page route ending at a receiver that notifies nobody is a finding; no drill recorded is "
                 "a finding",
        "contract": C + " §4", "origin": "tests/test_detection_collector.py::test_store_down_is_a_gap_not_a_pass",
        "files": {"instance.json": "instance.json", "data/.keep": {"text": ""}},
        "services": det_service("obs.json", token=False),
        "steps": [collect(DET, protocol_checks("detection") + [
            coverage_has(DET_DOC,
                         {"asset": "log-source:auth/web-1", "status": "gap", "reason": {"$regex": "^log store query failed: URLError: "}},
                         {"asset": "log-source:auth/web-2", "status": "gap"},
                         {"asset": "detection-ruler:log-store", "status": "gap", "reason": {"$regex": "^ruler API: URLError: "}},
                         {"asset": "detection-alerts:history", "status": "gap",
                          "reason": {"$regex": "^alert history query: RuntimeError: curl rc=7\\b"}},
                         {"asset": "detection-alertmanager:routing", "status": "ok"}),
            findings_has(DET_DOC, {"check": "detection.page_route_missing", "asset": "detection-alertmanager:routing",
                                   "severity": "high"},
                         {"check": "detection.drill_overdue", "title": "no detection drill has been recorded"}),
            {"json": "run/raw/detection/routing.json", "subset": {"notifying_receivers": ["team"]}},
            prom(("security_detection_page_route", {}, 0)), {"absent": ".svc-obs-mutations.log"}])]},
        dict(common, **{"obs.json": {"am_original": AM_NO_PAGE}, "instance.json": det_instance({
            "log_store": {"url": "http://127.0.0.1:9"}, "alert_history": {"url": "http://127.0.0.1:9", "exec": {"type": "local"}},
            "alertmanager": {"url": "{svc_obs}/"}, "expected": {"auth": ["web-1", "web-2"]}})}))

    ds = lambda name, want, ready: {"metadata": {"name": name, "namespace": "security"},  # noqa: E731
                                    "status": {"desiredNumberScheduled": want, "numberReady": ready}}
    kube = {"in-cluster": {"daemonsets": [ds("falco", 3, 3), ds("node-logs", 3, 2), ds("other", 1, 0)],
                           "prometheusrules": [{"metadata": {"name": "security-detection"}, "spec": {"groups": [
                               {"rules": [{"alert": "a"}, {"alert": "b"}]}, {"rules": [{"alert": "c"}]}]}},
                               {"metadata": {"name": "unrelated"}, "spec": {"groups": [{"rules": [{"alert": "x"}]}]}}]},
            "prod.yaml": {"fail": "error: You must be logged in to the server (Unauthorized)"},
            "dev.yaml": {"daemonsets": [], "prometheusrules": []}}
    write_case(DET, "sensors-backstop-and-scope", {
        "title": "Sensors through read-only kubectl: a DaemonSet not ready on every node or absent is a finding, a "
                 "cluster kubectl cannot list is a gap, a cluster without in-cluster backstop rules is a finding, and "
                 "every cluster of the instance's kubernetes list must be under detection; no log store configured "
                 "is a gap",
        "contract": C, "origin": "collectors/detection check_scope/check_sensors/check_backstop",
        "files": {"instance.json": "instance.json", "bin/kubectl": wrapper("fake_kubectl.py"), "kc/dev.yaml": {"text": "{}\n"},
                  "home/kc/prod.yaml": {"text": "{}\n"}, "data/.keep": {"text": ""}},
        "steps": [collect(DET, protocol_checks("detection") + [
            coverage_has(DET_DOC, {"asset": "k8s-cluster:prod", "status": "gap",
                                   "reason": "cannot list DaemonSets: error: You must be logged in to the server (Unauthorized)"},
                         {"asset": "k8s-cluster:lab", "status": "ok"}, {"asset": "k8s-cluster:edge", "status": "ok"},
                         {"asset": "detection-ruler:log-store", "status": "gap", "reason": "no detection.log_store configured"}),
            findings_has(DET_DOC,
                         {"check": "detection.sensor_missing", "asset": "k8s-cluster:lab/node-logs", "severity": "high",
                          "title": "detection sensor node-logs is not ready on every node of cluster lab (2/3)"},
                         {"check": "detection.sensor_missing", "asset": "k8s-cluster:dev/falco",
                          "title": "detection sensor falco is not ready on every node of cluster dev (0/0)"},
                         {"check": "detection.backstop_missing", "asset": "k8s-cluster:dev/backstop", "severity": "medium"},
                         {"check": "detection.cluster_not_covered", "asset": "k8s-cluster:prod",
                          "title": "cluster prod is not under detection (audit log missing)"},
                         {"check": "detection.cluster_not_covered", "asset": "k8s-cluster:edge",
                          "title": "cluster edge is not under detection (runtime sensor, audit log missing)"}),
            {"json": DET_DOC, "subset": {"findings": {"$not_contains": [
                {"asset": "k8s-cluster:lab/falco"}, {"asset": "k8s-cluster:lab/backstop"},
                {"check": "detection.cluster_not_covered", "asset": "k8s-cluster:lab"}]}}},
            {"json": "run/raw/detection/sensors-dev.json", "subset": {"falco": {"desired": 0, "ready": 0, "present": False}}},
            {"json": DET_DOC, "subset": {"metrics": {"$contains": [
                {"name": "security_detection_sensor_ready_ratio", "labels": {"cluster": "lab", "kind": "node-logs"},
                 "value": {"$approx": [0.666667, 0.00001]}}]}}},
            prom(("security_detection_clusters_known", {}, 4), ("security_detection_clusters_covered", {}, 2),
                 ("security_detection_sensor_ready_ratio", {"cluster": "lab", "kind": "falco"}, 1),
                 ("security_detection_backstop_rules", {"cluster": "lab"}, 3),
                 ("security_detection_backstop_rules", {"cluster": "dev"}, 0))], path=True)]},
        {"fake_kubectl.py": tool("fake_kubectl.py"), "kubectl.json": kube, "instance.json": det_instance({
            "clusters": [{"name": "lab"}, {"name": "prod", "kubeconfig": "~/kc/prod.yaml"},
                         {"name": "dev", "kubeconfig": "{sandbox}/kc/dev.yaml", "sensors": ["falco"]}],
            "expected": {"k8s-audit": ["lab", "dev"]}},
            kubernetes=[{"name": "lab"}, {"name": "prod"}, {"name": "edge"}, {"name": "dev"}])})

    write_case(DET, "drill-failed-then-overdue", {
        "title": "The last drill (by action time) decides: detected later than the target time to detect is a failed "
                 "drill; a last drill older than drill_max_age is overdue",
        "contract": C, "origin": "tests/test_detection_collector.py::test_slow_drill_fails",
        "files": {"instance.json": "instance.json",
                  "data/detections/drills/a.yaml": {"text": 'id: old\naction_at: "2020-01-01T00:00:00"\nresult: pass\nttd_seconds: 30\n'},
                  "data/detections/drills/b.yaml": {"text": 'id: slow\naction_at: "2026-01-01T00:00:00"\nresult: pass\nttd_seconds: 900\n'}},
        "steps": [collect(DET, protocol_checks("detection") + [
                      findings_has(DET_DOC, {"check": "detection.drill_failed", "asset": "detection-drills:lab", "severity": "high"}),
                      {"json": "run/raw/detection/drills.json", "subset": {"last": "slow", "ttd_seconds": 900}},
                      prom(("security_detection_drill_pass", {}, 0), ("security_detection_drill_ttd_seconds", {}, 900))]),
                  collect(DET, [findings_has(DET_DOC, {"check": "detection.drill_overdue",
                                                       "title": "the last detection drill is older than 2d"}),
                                {"json": "run/raw/detection/drills.json", "subset": {"last": "old"}}],
                          name="only an old drill left", remove=["run", "data/detections/drills/b.yaml"],
                          files={"instance.json": "instance-2d.json"})]},
        {"instance.json": det_instance({"drill_max_age": "36500d", "ttd_target": "5m"}),
         "instance-2d.json": det_instance({"drill_max_age": "2d", "ttd_target": "5m"})})

    write_case(DET, "token-file-readable-by-others", {
        "title": "A log-store token_file that grants read access to group or others is refused: the checks that need "
                 "the store are gaps saying so, and the token is never sent",
        "contract": C + " §2", "origin": "collectors/detection HTTP: token_file read without a permission check",
        "deviation": "DETECTION-D1",
        "files": {"instance.json": "instance.json", "loki.token": {"text": "{canary_token}\n", "mode": "0644"},
                  "data/.keep": {"text": ""}},
        "services": det_service("obs.json"),
        "steps": [collect(DET, protocol_checks("detection", ["{canary_token}"]) + [
            coverage_has(DET_DOC, {"asset": "log-source:auth/web-1", "status": "gap", "reason": {"$regex": "token_file .*group/others"}},
                         {"asset": "detection-ruler:log-store", "status": "gap", "reason": {"$regex": "token_file .*group/others"}}),
            {"absent": ".svc-obs-token-seen"}])]},
        dict(common, **{"obs.json": {"sources": {"auth": {"web-1": 5}}}, "instance.json": det_instance({
            "log_store": {"url": "{svc_obs}", "token_file": "{sandbox}/loki.token"}, "expected": {"auth": ["web-1"]}})}))

    write_case(DET, "drill-time-is-utc", {
        "title": "Recorded times (drill action_at, verdict fired_at, catalog released) are UTC whatever the host's time "
                 "zone: a summer drill under TZ=Europe/Berlin is at its exact UTC epoch",
        "contract": C, "origin": "collectors/detection: time.mktime(...) - time.timezone (local time, an hour off under DST)",
        "deviation": "DETECTION-D2",
        "files": {"instance.json": "instance.json",
                  "data/detections/drills/a.yaml": {"text": 'id: summer\naction_at: "2026-07-01T10:00:00"\nresult: pass\nttd_seconds: 60\n'}},
        "steps": [collect(DET, protocol_checks("detection") + [
            {"json": DET_DOC, "subset": {"metrics": {"$contains": [
                {"name": "security_detection_drill_last_timestamp_seconds", "value": 1782900000}]}}}],
            env={"TZ": "Europe/Berlin"})]},
        {"instance.json": det_instance({"drill_max_age": "36500d"})})


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
