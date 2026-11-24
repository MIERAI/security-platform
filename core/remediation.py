#!/usr/bin/env python3
"""core remediation: every open finding gets an owner and an SLO-tracked path to closure (component `core`).

usage: remediation.py --data <private data dir> [--instance <instance config>] [--now EPOCH]

Reads <data>/ledger.json (the ledger already applied the human-approved exceptions and their expiry) and keeps one
TRACKING ITEM per finding that is, or was, open. Writes:
  <data>/tracker/...                  through the configured tracker adapter (default `files`: private, in the data dir)
  <data>/tracker/items.json           the items (schema security-platform/tracker/v1)
  <data>/metrics/remediation.prom     aggregates only (severity), picked up by the runner with ledger.prom

Rules (deterministic, docs/design.md section 13):
  - status mirrors the ledger: open | accepted (exception: approved_by + expires) | fixed | false_positive.
    An item is CLOSED only when the ledger says fixed, i.e. a collector run covered the asset and the finding was
    gone. Nothing here (and no advisor) can close, accept or merge anything.
  - an expired exception makes the ledger reopen the finding; the item reopens with it (reopened_at, reason).
  - a fixed finding that comes back (regression) reopens the item; the SLO clock restarts at reopened_at.
  - owner: first matching `remediation.owners` rule (layer_in / asset_prefix / check_prefix / severity_in), else the
    finding's own owner (a team name; the SDK role hints "platform"/"human" do not count), else
    `remediation.default_owner`, else "unassigned" (reported as a metric).
  - due_at = opened (or reopened) + SLO of the item's class: `kev_exposed` (KEV on an exposed asset) or its severity.
    Accepted items are not overdue while the exception is valid. Info findings have no SLO unless configured.
  - the advisor (remediation.advisor, default none) may DRAFT a runbook/PR text per open item without a draft:
    stored under tracker/drafts/<id>.md and in the decision log. A draft is a proposal only.
Instance config:
  remediation:
    tracker: {type: files}                  # or {type: github-issues, repo: owner/private-repo, enabled: true}
    default_owner: security-oncall
    owners: [{layer_in: [workload], owner: platform-team}, {asset_prefix: "repo:", owner: dev-team}]
    slo: {kev_exposed: 1d, critical: 7d, high: 30d, medium: 90d, low: 180d}
    advisor: {type: none}
"""
import argparse
import json
import os
import statistics
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path[:0] = [HERE, ROOT, os.path.join(ROOT, "sdk")]
import advisor as advisors  # noqa: E402
from adapters import trackers  # noqa: E402
from spsdk import load_config, render  # noqa: E402

VERSION = open(os.path.join(HERE, "VERSION")).read().strip()
SCHEMA = "security-platform/tracker/v1"
SEVERITIES = ("critical", "high", "medium", "low", "info")
DEFAULT_SLO = {"kev_exposed": "1d", "critical": "7d", "high": "30d", "medium": "90d", "low": "180d"}
UNIT = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
CLOSED = ("fixed", "false_positive")


def dur(v):
    if v is None or v == "":
        return None
    if isinstance(v, (int, float)):
        return int(v)
    v = str(v).strip()
    return int(float(v[:-1]) * UNIT[v[-1]]) if v[-1] in UNIT else int(v)


def ts(s):
    s = str(s)
    fmt, n = ("%Y-%m-%dT%H:%M:%S", 19) if "T" in s else ("%Y-%m-%d", 10)
    return time.mktime(time.strptime(s[:n], fmt)) - time.timezone


def iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def slo_seconds(cfg):
    slo = dict(DEFAULT_SLO, **{k: v for k, v in ((cfg or {}).get("slo") or {}).items()})
    return {k: dur(v) for k, v in slo.items() if dur(v)}


def slo_class(e):
    a = e.get("attributes") or {}
    return "kev_exposed" if a.get("kev") and a.get("exposed") else e["severity"]


# owner values that are not a team: the SDK's role hints ("platform" = a fix by configuration, "human" = needs_human)
# and placeholders. Real collectors always set one of them, so they must not shadow `default_owner`.
ROLE_HINTS = ("unknown", "unassigned", "platform", "human")


def owner_of(e, cfg):
    for r in (cfg or {}).get("owners") or []:
        if (("layer_in" not in r or e["layer"] in r["layer_in"])
                and ("severity_in" not in r or e["severity"] in r["severity_in"])
                and ("asset_prefix" not in r or e["asset"].startswith(r["asset_prefix"]))
                and ("check_prefix" not in r or e["check"].startswith(r["check_prefix"]))):
            return r["owner"], "rule"
    if e.get("owner") and e["owner"] not in ROLE_HINTS:
        return e["owner"], "finding"
    if (cfg or {}).get("default_owner"):
        return cfg["default_owner"], "default"
    return "unassigned", "none"


def update(items, ledger, cfg, now):
    """Mirror the ledger into tracking items. Pure function of (previous items, ledger, config, now)."""
    slo = slo_seconds(cfg)
    for fid, e in sorted(ledger.get("entries", {}).items()):
        st = e["status"]
        it = items.get(fid)
        if it is None:
            if st in CLOSED:
                continue                       # never open while tracked: nothing to remediate
            it = items[fid] = {"id": fid, "opened_at": e["first_seen"], "reopened_at": None, "reopen_reason": None,
                               "closed_at": None, "time_to_remediate_days": None, "history": []}
        prev = it.get("status")
        if prev in CLOSED and st not in CLOSED:      # regression, or a closed item whose exception expired
            it.update(reopened_at=iso(now), closed_at=None, time_to_remediate_days=None,
                      reopen_reason="regression" if prev == "fixed" else "reopened by the ledger")
        if prev == "accepted" and st == "open" and (e.get("exception") or {}).get("expired"):
            it.update(reopened_at=iso(now), reopen_reason="exception expired")
        owner, why = owner_of(e, cfg)
        cls = slo_class(e)
        start = ts(it["reopened_at"] or it["opened_at"])
        due = start + slo[cls] if cls in slo else None
        it.update(status=st, check=e["check"], layer=e["layer"], asset=e["asset"], title=e["title"],
                  severity=e["severity"], slo_class=cls, owner=owner, owner_source=why,
                  remediation=e.get("remediation", ""), needs_human=bool(e.get("needs_human")),
                  due_at=iso(due) if due else None,
                  exception=({k: (e.get("exception") or {}).get(k) for k in ("approved_by", "expires", "reason")}
                             if st == "accepted" else None))
        if st in CLOSED and prev not in CLOSED:
            closed = ts(e["fixed_at"]) if st == "fixed" and e.get("fixed_at") else now
            it["closed_at"] = iso(closed)
            it["time_to_remediate_days"] = round((closed - start) / 86400, 2)
        it["overdue"] = bool(st == "open" and due and now > due)
        if prev != st:
            it["history"].append({"at": iso(now), "status": st})
            it["history"] = it["history"][-20:]
    return items


def draft(items, data, cfg, now):
    """Advisor drafts for open items without one. Proposals only: status is never touched here."""
    adv = advisors.advisor((cfg or {}).get("advisor"))
    if adv.model == "none":
        return 0
    n = 0
    for it in items.values():
        if it["status"] != "open" or it.get("advisor_draft"):
            continue
        ctx = {k: it[k] for k in ("id", "check", "layer", "asset", "title", "severity", "remediation", "needs_human")}
        p = adv.advise("remediation-draft", ctx)
        advisors.log_decision(data, "remediation-draft", ctx, p, adv.model)
        if not p or not p.get("text"):
            continue
        rel = os.path.join("tracker", "drafts", f"{it['id']}.md")
        os.makedirs(os.path.join(data, "tracker", "drafts"), exist_ok=True)
        with open(os.path.join(data, rel), "w") as f:
            f.write(f"# DRAFT remediation for {it['id']} ({adv.model}, {iso(now)})\n\n"
                    "PROPOSAL ONLY: review before use. It is never applied, merged or used to close the item;\n"
                    "closure happens only when a collector run covers the asset and the finding is gone.\n\n"
                    + p["text"] + "\n")
        it["advisor_draft"] = rel
        n += 1
    return n


def series(items, cfg):
    slo = slo_seconds(cfg)
    s = []
    for sev in SEVERITIES:
        its = [i for i in items.values() if i["severity"] == sev]
        s.append(("security_remediation_open", {"severity": sev}, sum(1 for i in its if i["status"] == "open"),
                  "Open findings being remediated"))
        s.append(("security_remediation_overdue", {"severity": sev}, sum(1 for i in its if i["overdue"]),
                  "Open findings past their remediation SLO"))
        ttr = [i["time_to_remediate_days"] for i in its if i["status"] == "fixed" and i["time_to_remediate_days"] is not None]
        if ttr:
            s.append(("security_time_to_remediate_days", {"severity": sev, "quantile": "0.5"}, statistics.median(ttr),
                      "Time from opened (or reopened) to fixed, closed items"))
            s.append(("security_time_to_remediate_days", {"severity": sev, "quantile": "1"}, max(ttr),
                      "Time from opened (or reopened) to fixed, closed items"))
    for cls, sec in sorted(slo.items()):
        s.append(("security_remediation_slo_seconds", {"severity": cls}, sec, "Remediation SLO per class"))
    s.append(("security_remediation_unassigned", {}, sum(1 for i in items.values() if i["status"] == "open"
                                                          and i["owner"] == "unassigned"), "Open items without an owner"))
    s.append(("security_remediation_last_update_timestamp_seconds", {}, int(time.time()), "Remediation tracker heartbeat"))
    return s


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--instance")
    ap.add_argument("--now", type=float)
    a = ap.parse_args(argv)
    now = a.now or time.time()
    cfg = (load_config(a.instance) or {}).get("remediation") or {} if a.instance else {}
    ledger = json.load(open(os.path.join(a.data, "ledger.json")))
    sp = os.path.join(a.data, "tracker", "items.json")
    prev = json.load(open(sp)) if os.path.exists(sp) else {"schema": SCHEMA, "items": {}}
    items = update(prev.get("items", {}), ledger, cfg, now)
    drafts = draft(items, a.data, cfg, now)
    os.makedirs(os.path.dirname(sp), exist_ok=True)
    result = trackers.tracker(cfg.get("tracker"), a.data).sync(items)
    with open(sp + ".tmp", "w") as f:
        json.dump({"schema": SCHEMA, "core": VERSION, "updated_at": iso(now), "slo_seconds": slo_seconds(cfg),
                   "items": items}, f, indent=1, sort_keys=True, ensure_ascii=False)
    os.replace(sp + ".tmp", sp)
    mp = os.path.join(a.data, "metrics", "remediation.prom")
    os.makedirs(os.path.dirname(mp), exist_ok=True)
    with open(mp + ".tmp", "w") as f:
        f.write(render(series(items, cfg)))
    os.replace(mp + ".tmp", mp)
    op = [i for i in items.values() if i["status"] == "open"]
    print(f"[remediation {VERSION}] open={len(op)} overdue={sum(i['overdue'] for i in op)} "
          f"unassigned={sum(i['owner'] == 'unassigned' for i in op)} drafts={drafts} tracker={result}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
