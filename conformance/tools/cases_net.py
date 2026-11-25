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
