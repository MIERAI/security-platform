#!/usr/bin/env python3
"""Collector `agent-claude-code`: the AI-agent layer - what a coding agent is allowed to do. READ-ONLY.

Instance config `agents: [{type: claude-code, settings: [paths], memory_dirs: [paths]}]`.
Reads only permission-related keys (never `env` values) and reports risky combinations. Other agent types
(Cursor, Copilot, Gemini CLI ...) are future adapters behind the same checks.
"""
import json
import os
import re
import sys

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


def main():
    inst = spsdk.load_instance()
    c = spsdk.Collector("agent-claude-code", VERSION)
    for a in inst.get("agents", []):
        if a["type"] != "claude-code":
            c.gap(f"agent:{a['type']}", "adapter not implemented (future)")
            continue
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
