#!/usr/bin/env python3
"""Collector `agent-claude-code`: the AI-agent layer - what a coding agent is allowed to do. READ-ONLY.

Instance config `agents: [{type: claude-code, settings: [paths], memory_dirs: [paths], transcripts_dirs: [paths],
min_transcript_retention_days: 30}]`.
Reads only permission-related keys (never `env` values) and reports risky combinations. AI agents are treated as
personnel (the people pillar): their permissions, the credentials in their memory (pattern counts, never values),
whether credential paths are denied, and the audit trail of their actions (session transcripts: count, age,
retention - metadata only, never the content). Other agent types (Cursor, Copilot, Gemini CLI ...) are future
adapters behind the same checks.
"""
import glob
import json
import os
import re
import sys
import time

HERE = os.path.dirname(__file__)
ROOT = os.path.join(HERE, "..", "..")
sys.path[:0] = [os.path.join(ROOT, "sdk"), ROOT]
import spsdk  # noqa: E402

VERSION = open(os.path.join(HERE, "VERSION")).read().strip()
# allow-rules that effectively grant arbitrary execution, remote reach or credential access
BROAD = [(re.compile(r"^Bash(\(\*\)|\(\*:\*\))?$"), "any shell command"),
         (re.compile(r"^Bash\((ssh|scp|rsync)[ :]"), "remote shell to other hosts"),
         (re.compile(r"^Bash\((kubectl|helm|tofu|terraform|ansible|ansible-playbook)[ :]"), "infrastructure control"),
         (re.compile(r"^Bash\((gh|git push)[ :]"), "code-host write access"),
         (re.compile(r"^Bash\((curl|wget)[ :]"), "arbitrary network egress"),
         (re.compile(r"^Bash\((python3?|node|bash|sh|zsh|uv run)[ :]"), "arbitrary interpreter"),
         (re.compile(r"^Bash\((sudo|rm)[ :]"), "destructive/privileged"),
         (re.compile(r"^(Read|Edit|Write)\((~|/|\*\*)"), "file access outside the project")]


# high-confidence credential shapes (a count per file is reported, never the match); a keyword followed by prose
# ("password = same as the admin UI") is not a value: the value must be 8+ ASCII credential characters
SECRET_SHAPES = re.compile(r"(gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|AKIA[0-9A-Z]{16}|xox[abpr]-[A-Za-z0-9-]{10,}"
                           r"|sk-[A-Za-z0-9_-]{32,}|AIza[0-9A-Za-z_-]{35}|-----BEGIN [A-Z ]*PRIVATE KEY-----"
                           r"|(password|passwd|密码|口令|token|secret)\s*[:=：]\s*[A-Za-z0-9!@#%^&*._+/=-]{8,}(?![^\s,;)）。，]))",
                           re.I)
CRED_PATHS = re.compile(r"(\.ssh|\.kube|\.aws|\.config/gh|\.config/gcloud|\.docker/config|\.netrc|credentials|secrets?|token)", re.I)


def memory_scan(c, a):
    hits, files = {}, 0
    for d in a.get("memory_dirs", []):
        for p in glob.glob(os.path.join(os.path.expanduser(d), "**", "*.md"), recursive=True):
            files += 1
            try:
                n = sum(1 for line in open(p, errors="replace") if SECRET_SHAPES.search(line))
            except OSError:
                continue
            if n:
                hits[p] = n
    asset = "agent-memory:claude-code"
    if not a.get("memory_dirs"):
        c.gap(asset, "no memory_dirs configured")
        return
    c.ok(asset)
    ev = c.raw("memory-scan.json", {"files": files, "suspect_files": {os.path.basename(k): v for k, v in hits.items()}})
    for p, n in sorted(hits.items()):
        c.finding("ai-agents", f"{asset}/{os.path.basename(os.path.dirname(os.path.dirname(p)))}/{os.path.basename(p)}",
                  "agent.memory_secret_suspect", f"{n} line(s) shaped like a credential in agent memory file {os.path.basename(p)}",
                  "high", ev, "remove the value (keep where it lives, not what it is); rotate it if it was real", needs_human=True)
    c.metric("security_agent_memory_files", files, "Agent memory files scanned for credential shapes")


def audit_trail(c, a, retention_days):
    asset = "agent-audit:claude-code"
    dirs = [os.path.expanduser(d) for d in a.get("transcripts_dirs", ["~/.claude/projects"])]
    files = [p for d in dirs for p in glob.glob(os.path.join(d, "*", "*.jsonl"))]
    now = time.time()
    newest = max((os.path.getmtime(p) for p in files), default=None)
    oldest = min((os.path.getmtime(p) for p in files), default=None)
    info = {"transcripts": len(files), "newest_age_days": round((now - newest) / 86400, 1) if newest else None,
            "oldest_age_days": round((now - oldest) / 86400, 1) if oldest else None,
            "retention_days": retention_days, "size_mb": round(sum(os.path.getsize(p) for p in files) / 1e6, 1)}
    ev = c.raw("audit-trail.json", info)
    if not any(os.path.isdir(d) for d in dirs):
        c.gap(asset, "transcripts directory not found")
        return
    c.ok(asset)
    min_ret = int(a.get("min_transcript_retention_days", 30))
    if not files or now - newest > 7 * 86400:
        c.finding("ai-agents", asset, "agent.audit_trail_missing", "no agent session transcript in the last 7 days (audit trail off?)",
                  "medium", ev, "keep session transcripts (do not disable them); they are the agent's audit trail")
    elif retention_days < min_ret:
        c.finding("ai-agents", asset, "agent.audit_trail_missing",
                  f"agent transcripts are kept {retention_days} days (< {min_ret}): too short to investigate an incident",
                  "low", ev, f"set cleanupPeriodDays >= {min_ret}")
    c.metric("security_agent_transcripts", len(files), "Agent session transcripts kept (audit trail; metadata only)")


def main():
    inst = spsdk.load_instance()
    c = spsdk.Collector("agent-claude-code", VERSION)
    for a in inst.get("agents", []):
        if a["type"] != "claude-code":
            c.gap(f"agent:{a['type']}", "adapter not implemented (future)")
            continue
        merged_deny, hooks, retention = [], {}, 30
        for sp in a.get("settings", []):
            p = os.path.expanduser(sp)
            if os.path.exists(p):
                try:
                    dd = json.load(open(p))
                except ValueError:
                    continue
                merged_deny += (dd.get("permissions") or {}).get("deny") or []
                for ev_, hs in (dd.get("hooks") or {}).items():
                    hooks[ev_] = hooks.get(ev_, 0) + len(hs or [])
                if dd.get("cleanupPeriodDays") is not None:
                    retention = int(dd["cleanupPeriodDays"])
        guard = [r for r in merged_deny if CRED_PATHS.search(r)]
        gev = c.raw("guards.json", {"deny_rules": len(merged_deny), "credential_path_deny_rules": len(guard), "hooks": hooks})
        c.ok("agent-guard:claude-code")
        if not guard:
            c.finding("ai-agents", "agent-guard:claude-code", "agent.no_credential_deny_rules",
                      "no deny rule protects credential paths (~/.ssh, kubeconfigs, cloud and gh credentials) from the agent",
                      "medium", gev, "add deny rules such as Read(~/.ssh/**), Read(~/.kube/**), Read(~/.config/gh/**); "
                      "grant exceptions per project", needs_human=True)
        memory_scan(c, a)
        audit_trail(c, a, retention)
        for sp in a.get("settings", []):
            p = os.path.expanduser(sp)
            if not os.path.exists(p):
                continue
            A = f"agent:claude-code:{sp}"
            d = json.load(open(p))
            perms = d.get("permissions") or {}
            allow = perms.get("allow") or []
            broad = {}
            for r in allow:
                for rx, why in BROAD:
                    if rx.search(r):
                        broad.setdefault(why, []).append(r.split("(")[0] + "(" + r.split("(", 1)[1][:24] if "(" in r else r)
            info = dict(defaultMode=perms.get("defaultMode"),
                        blockReadsOutsideWorkingDirectories=perms.get("blockReadsOutsideWorkingDirectories"),
                        skipDangerousModePermissionPrompt=d.get("skipDangerousModePermissionPrompt"),
                        allow_rules=len(allow), deny_rules=len(perms.get("deny") or []),
                        additional_directories=len(perms.get("additionalDirectories") or []),
                        hooks=sorted((d.get("hooks") or {}).keys()), env_keys=len(d.get("env") or {}),
                        broad_allow={k: len(v) for k, v in broad.items()},
                        mode=oct(os.stat(p).st_mode & 0o777))
            ev = c.raw(re.sub(r"[^a-z0-9]+", "-", sp.lower()).strip("-") + ".json", info)
            c.ok(A)
            if info["defaultMode"] == "bypassPermissions":
                c.finding("ai-agents", A, "agent.bypass_permissions_default",
                          "agent runs in bypassPermissions by default (no per-action confirmation)"
                          + (" and the danger prompt is skipped" if info["skipDangerousModePermissionPrompt"] else ""),
                          "high", ev, "default to an allowlist mode; use bypass only in a sandbox/container", needs_human=True)
            if info["blockReadsOutsideWorkingDirectories"] is False:
                c.finding("ai-agents", A, "agent.reads_outside_workdir",
                          "agent may read outside its working directories (blockReadsOutsideWorkingDirectories=false): ~/.ssh, kubeconfigs, tokens are readable",
                          "high", ev, "turn it on; add needed dirs explicitly to additionalDirectories", needs_human=True)
            for why, rules in broad.items():
                c.finding("ai-agents", A, "agent.broad_allow." + re.sub(r"[^a-z]+", "_", why),
                          f"{len(rules)} allow rule(s) grant {why} without confirmation", "medium", ev,
                          "narrow to read-only subcommands; require confirmation for writes", needs_human=True)
            if int(info["mode"], 8) & 0o022:
                c.finding("ai-agents", A, "agent.settings_writable_by_others", f"settings file writable by others ({info['mode']})",
                          "high", ev, "chmod 600")
        # decision log presence (design: every AI judgment is logged) - phase 0: platform has no advisor yet
    c.write()


if __name__ == "__main__":
    main()
