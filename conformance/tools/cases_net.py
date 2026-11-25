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
