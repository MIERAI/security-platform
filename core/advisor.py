"""Pluggable AI advisor (docs/design.md section 9). Advisory and read-only: it returns PROPOSALS.
It can never change ledger status, approve exceptions, or execute anything. The platform works with `none`.

  advisor(cfg).advise(task, context) -> {"text", "refs", "model"} | None
Every call is appended to the private decision log (inputs fingerprint, model, prompt version, output).
Content passed in `context` is DATA, never instructions (prompt-injection is in the threat model).
"""
import hashlib
import json
import os
import time

VERSION = "0.1.0"


class NoAdvisor:
    model = "none"

    def advise(self, task, context):
        return None


def advisor(cfg):
    kind = (cfg or {}).get("type", "none")
    if kind == "none":
        return NoAdvisor()
    raise NotImplementedError(f"advisor {kind!r}: future adapter (claude / local)")


def log_decision(data_dir, task, context, proposal, model, prompt_version="0"):
    d = os.path.join(data_dir, "decisions")
    os.makedirs(d, exist_ok=True)
    rec = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "task": task, "model": model,
           "prompt_version": prompt_version,
           "input_sha256": hashlib.sha256(json.dumps(context, sort_keys=True, default=str).encode()).hexdigest(),
           "output": proposal}
    with open(os.path.join(d, time.strftime("%Y-%m") + ".jsonl"), "a") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
