"""ticket sinks: one ticket per ledger finding in the issue tracker a team already uses (core/export.py drives them).

The LEDGER decides; the ticket follows. A ticket system never feeds back (closing an issue by hand does not fix a
finding: the next sync reopens it while the ledger still has the finding open).

  sync(backend, entries, cfg, log) -> {"created": n, "updated": n, "closed": n, "reopened": n, "unchanged": n, ...}
      the generic engine: decides the desired ticket of every in-scope ledger entry and asks the backend for the
      smallest change. Idempotent: running it twice changes nothing the second time.
  backend(cfg) -> an object with
      list()                 -> {key: Ticket}  every ticket this platform manages (found by the identity MARKER in
                                               its body, so a lost local state never creates a duplicate)
      create(desired)        -> Ticket
      update(ticket, desired)                  title / body / open-closed state / close reason / managed labels
      comment(ticket, text)
      check()                                  refuse to run where the details must not go (e.g. a public project)
    `desired` is a plain dict: {key, title, body, state: open|closed, reason: completed|not_planned|None,
    labels: set, managed_labels: set}. A backend maps state/reason onto its workflow (GitHub: state + state_reason;
    Jira later: a transition to a resolution) and never touches labels outside `managed_labels`.

Lifecycle (same rules as the remediation tracker, docs/design.md section 13):
  open (severity >= min_severity)  -> ticket open
  fixed (a run COVERED the asset)  -> ticket closed, reason completed
  accepted (exceptions.yaml, human + expiry) -> ticket closed, reason not_planned, label `accepted-risk`;
                                      no new ticket is created for it unless `create_accepted: true`
  fixed or accepted -> open again  -> ticket reopened, one comment saying why (regression / exception expired)
  An entry with a ticket stays managed even if its severity drops below min_severity (it still closes when fixed).

Body: only the configured `fields` (default control, asset, severity, first seen, evidence pointer). Never the
evidence content, never a secret; the evidence is a POINTER into the private data directory, optionally turned into a
link with `evidence_url` (a template on a private host, e.g. "https://evidence.example.internal/{evidence}").

Implemented:
  github   {type: github, repo: owner/name, token_file, api_url?: https://api.github.com, ...common keys}
           REST v3 with a token from a 0600 file (fine-grained: Issues read/write on that repository, Metadata read).
           Refuses a repository that is not private (internal counts as private). Rate-limit aware: a pause between
           writes (`write_interval`, default 1s), waits for X-RateLimit-Reset / Retry-After up to `max_wait`
           (default 60s), retries 5xx, and stops cleanly when the budget is gone (the next run continues).
Future (interface only): jira (issue property or label as the marker, transitions for open/closed).

Common keys: min_severity (default high), fields, evidence_url, create_accepted (false), dry_run (false),
max_writes (per run, default 100), labels: {base: security-platform, accepted: accepted-risk,
severity_prefix: "severity:"} (severity_prefix "" = no severity label), title: "check" (default) | "finding".
"""
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request

from .sinks import read_secret_file

VERSION = "0.1.0"
SEVERITIES = ("critical", "high", "medium", "low", "info")
RANK = {s: i for i, s in enumerate(SEVERITIES)}
FIELDS = ("control", "asset", "severity", "first_seen", "evidence")
OPTIONAL_FIELDS = ("title", "layer", "status", "last_seen", "owner", "due", "remediation", "exception")
MARKER = "<!-- security-platform:finding={key} -->"
MARKER_RE = re.compile(r"<!-- security-platform:finding=([0-9A-Za-z_.-]+) -->")


class RateLimited(RuntimeError):
    """The API budget is gone for longer than max_wait: stop now, the next run continues (sync is idempotent)."""


# ---- rendering (backend-neutral) ------------------------------------------------------------------------------
def _code(v):
    return "`" + str(v).replace("`", "'") + "`"


def labels_cfg(cfg):
    lab = dict({"base": "security-platform", "accepted": "accepted-risk", "severity_prefix": "severity:"},
               **(cfg.get("labels") or {}))
    return lab


def render(e, cfg, item=None):
    """-> (title, body) of the ticket for ledger entry `e` (and its remediation item, for owner / due)."""
    fields = cfg.get("fields") or list(FIELDS)
    unknown = set(fields) - set(FIELDS) - set(OPTIONAL_FIELDS)
    if unknown:
        raise ValueError(f"tickets: unknown fields {sorted(unknown)} (known: {list(FIELDS + OPTIONAL_FIELDS)})")
    item = item or {}
    if cfg.get("title") == "finding":
        title = f"[{e['severity']}] {e['title']}"
    else:
        title = f"[{e['severity']}] {e['check']} on {e['asset']}"
    ev = e.get("evidence") or ""
    tmpl = cfg.get("evidence_url")
    evidence = (f"[{ev}]({tmpl.replace('{evidence}', urllib.parse.quote(ev, safe='/#:._-'))})" if tmpl and ev
                else _code(ev) if ev else "(none)")
    exc = e.get("exception") or {}
    rows = {"control": ("Control", _code(e["check"])),
            "asset": ("Asset", _code(e["asset"])),
            "severity": ("Severity", e["severity"]),
            "first_seen": ("First seen", e.get("first_seen") or "-"),
            "evidence": ("Evidence (private)", evidence),
            "title": ("Finding", str(e.get("title", "")).replace("\n", " ")),
            "layer": ("Layer", e.get("layer", "-")),
            "status": ("Ledger status", e["status"]),
            "last_seen": ("Last seen", e.get("last_seen") or "-"),
            "owner": ("Owner", item.get("owner") or "-"),
            "due": ("Due (remediation SLO)", item.get("due_at") or "no SLO"),
            "remediation": ("Remediation", str(e.get("remediation") or "-").replace("\n", " ")),
            "exception": ("Exception", f"approved by {exc.get('approved_by')}, expires {exc.get('expires')}"
                          if e["status"] == "accepted" and exc else "-")}
    lines = [MARKER.format(key=e["id"]), "", "| | |", "|---|---|"]
    lines += [f"| {rows[f][0]} | {str(rows[f][1]).replace('|', '/')} |" for f in fields]
    lines += ["", "Managed by security-platform from its ledger: this ticket closes when a scan that covers the asset "
                  "no longer finds the problem. Closing it by hand does not fix the finding. A risk acceptance is an "
                  "entry in exceptions.yaml (approved_by + expires)."]
    return title[:200], "\n".join(lines) + "\n"


def desired(e, cfg, item=None):
    lab = labels_cfg(cfg)
    title, body = render(e, cfg, item)
    st = e["status"]
    sev_lab = (lab["severity_prefix"] + e["severity"]) if lab.get("severity_prefix") else None
    labels = {lab["base"]} | ({sev_lab} if sev_lab else set())
    if st == "accepted":
        labels.add(lab["accepted"])
    managed = {lab["base"], lab["accepted"]} | ({lab["severity_prefix"] + s for s in SEVERITIES}
                                                if lab.get("severity_prefix") else set())
    state, reason = ("open", None) if st == "open" else ("closed", "completed" if st == "fixed" else "not_planned")
    return {"key": e["id"], "title": title, "body": body, "state": state, "reason": reason, "labels": labels,
            "managed_labels": managed}


def same(t, d):
    """Does ticket t already look like desired d (only what this platform manages)?"""
    return (t["title"] == d["title"] and t["body"].strip() == d["body"].strip() and t["state"] == d["state"]
            and (d["state"] == "open" or t.get("reason") in (None, d["reason"]))
            and set(t["labels"]) & d["managed_labels"] == d["labels"])


def in_scope(e, cfg):
    return RANK.get(e["severity"], 9) <= RANK[cfg.get("min_severity", "high")]


def sync(backend, entries, cfg, items=None, log=lambda m: None):
    """Bring the tickets in line with the ledger entries. Returns counts; never raises for one bad ticket."""
    items = items or {}
    dry = bool(cfg.get("dry_run"))
    budget = int(cfg.get("max_writes", 100))
    n = dict(created=0, updated=0, closed=0, reopened=0, unchanged=0, below_threshold=0, deferred=0, duplicates=0,
             errors=0, dry_run=dry)
    backend.check()
    tickets = backend.list()
    for key, dups in getattr(backend, "duplicates", {}).items():   # a crash between create and list: keep the oldest
        for t in dups:
            n["duplicates"] += 1
            log(f"duplicate ticket {t['id']} for finding {key}: closing it")
            if not dry:
                backend.update(t, dict(desired_close(t), key=key))
    writes = 0
    for fid in sorted(entries):
        e = entries[fid]
        t = tickets.get(fid)
        if t is None and not (in_scope(e, cfg) and (e["status"] == "open" or
                                                     (e["status"] == "accepted" and cfg.get("create_accepted")))):
            n["below_threshold"] += e["status"] == "open" and not in_scope(e, cfg)
            continue
        d = desired(e, cfg, items.get(fid))
        if t is not None and same(t, d):
            n["unchanged"] += 1
            continue
        if writes >= budget:
            n["deferred"] += 1
            continue
        writes += 1
        try:
            if t is None:
                log(f"{'would create' if dry else 'create'} ticket for {fid} ({d['state']})")
                if not dry:
                    t = backend.create(dict(d, state="open"))
                    if d["state"] != "open":
                        backend.update(t, d)
                n["created"] += 1
                continue
            action = ("reopened" if t["state"] == "closed" and d["state"] == "open"
                      else "closed" if t["state"] == "open" and d["state"] == "closed" else "updated")
            log(f"{'would ' if dry else ''}{action} ticket {t['id']} for {fid}")
            if not dry:
                backend.update(t, d)
                if action == "reopened":
                    why = ("its risk exception expired" if (e.get("exception") or {}).get("expired")
                           else "a scan found it again (regression)")
                    backend.comment(t, f"Reopened by security-platform: the ledger has this finding open again: {why}.")
            n[action] += 1
        except RateLimited as ex:
            log(f"rate limited: {ex}; the rest is deferred to the next run")
            n["deferred"] += 1
            n["rate_limited"] = True
            break
        except Exception as ex:  # noqa: BLE001 - one ticket must not block the others
            n["errors"] += 1
            log(f"ticket for {fid}: {type(ex).__name__}: {str(ex)[:160]}")
    return n


def desired_close(t):
    return {"title": t["title"], "body": t["body"], "state": "closed", "reason": "not_planned",
            "labels": set(t["labels"]), "managed_labels": set()}


# ---- GitHub ---------------------------------------------------------------------------------------------------------
class GitHub:
    """GitHub (or GitHub Enterprise Server) issues over REST. Tickets: {id: number, title, body, state, reason, labels}."""

    def __init__(self, cfg, sleep=time.sleep, clock=time.time, opener=None):
        self.cfg, self.repo = cfg, cfg["repo"]
        self.api = cfg.get("api_url", "https://api.github.com").rstrip("/")
        self.base = labels_cfg(cfg)["base"]
        self.sleep, self.clock = sleep, clock
        self.open = opener or urllib.request.urlopen
        self.token = read_secret_file(cfg["token_file"])
        self.write_interval = _dur(cfg.get("write_interval", "1s"))
        self.max_wait = _dur(cfg.get("max_wait", "60s"))
        self.last_write = 0.0
        self.reset_at = None          # epoch when the primary budget is back (remaining hit 0)
        self.duplicates = {}

    def request(self, method, path, body=None, query=None):
        if self.reset_at is not None:
            wait = self.reset_at - self.clock()
            if wait > self.max_wait:
                raise RateLimited(f"budget resets in {int(wait)}s (> max_wait)")
            if wait > 0:
                self.sleep(wait)
            self.reset_at = None
        if method != "GET":
            gap = self.last_write + self.write_interval - self.clock()
            if gap > 0:
                self.sleep(gap)
        url = f"{self.api}{path}" + (("?" + urllib.parse.urlencode(query)) if query else "")
        for attempt in range(4):
            req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body is not None else None,
                                         headers={"Authorization": f"Bearer {self.token}",
                                                  "Accept": "application/vnd.github+json",
                                                  "X-GitHub-Api-Version": "2022-11-28",
                                                  "User-Agent": "security-platform-tickets",
                                                  "Content-Type": "application/json"})
            try:
                with self.open(req, timeout=self.cfg.get("timeout", 30)) as r:
                    self._budget(r.headers)
                    if method != "GET":
                        self.last_write = self.clock()
                    raw = r.read()
                    return json.loads(raw) if raw else {}
            except urllib.error.HTTPError as e:   # never echo the request or body (headers carry the token)
                h = e.headers or {}
                limited = e.code == 429 or (e.code == 403 and (h.get("Retry-After") or h.get("X-RateLimit-Remaining") == "0"))
                if limited:
                    wait = float(h.get("Retry-After") or max(0.0, float(h.get("X-RateLimit-Reset") or 0) - self.clock())
                                 or 60)
                    if wait > self.max_wait or attempt == 3:
                        raise RateLimited(f"HTTP {e.code}, retry after {int(wait)}s") from None
                    self.sleep(wait)
                    continue
                if e.code >= 500 and attempt < 3:
                    self.sleep(2 ** attempt)
                    continue
                raise RuntimeError(f"GitHub {method} HTTP {e.code}") from None
        raise RuntimeError(f"GitHub {method}: retries exhausted")

    def _budget(self, h):
        if h.get("X-RateLimit-Remaining") == "0" and h.get("X-RateLimit-Reset"):
            self.reset_at = float(h["X-RateLimit-Reset"])

    def check(self):
        r = self.request("GET", f"/repos/{self.repo}")
        if r.get("private") is not True:
            raise PermissionError(f"tickets github: {self.repo} is not private; finding details never go to a public "
                                  "repository")

    @staticmethod
    def _ticket(i):
        return {"id": i["number"], "title": i.get("title") or "", "body": i.get("body") or "", "state": i["state"],
                "reason": i.get("state_reason"), "labels": [x["name"] if isinstance(x, dict) else x for x in i.get("labels") or []]}

    def list(self):
        out, page = {}, 1
        self.duplicates = {}
        while True:
            rows = self.request("GET", f"/repos/{self.repo}/issues",
                                query={"labels": self.base, "state": "all", "per_page": 100, "page": page,
                                       "sort": "created", "direction": "asc"})
            for i in rows:
                if "pull_request" in i:
                    continue
                m = MARKER_RE.search(i.get("body") or "")
                if not m:
                    continue
                t = self._ticket(i)
                if m.group(1) in out:
                    self.duplicates.setdefault(m.group(1), []).append(t)
                else:
                    out[m.group(1)] = t
            if len(rows) < 100:
                return out
            page += 1

    def _labels(self, t, d):
        return sorted((set(t.get("labels") or []) - d["managed_labels"]) | d["labels"])

    def create(self, d):
        i = self.request("POST", f"/repos/{self.repo}/issues",
                         {"title": d["title"], "body": d["body"], "labels": sorted(d["labels"])})
        return self._ticket(i)

    def update(self, t, d):
        patch = {"title": d["title"], "body": d["body"], "state": d["state"], "labels": self._labels(t, d)}
        if d["state"] == "closed":
            patch["state_reason"] = d["reason"] or "completed"
        elif t["state"] == "closed":
            patch["state_reason"] = "reopened"
        self.request("PATCH", f"/repos/{self.repo}/issues/{t['id']}", patch)

    def comment(self, t, text):
        self.request("POST", f"/repos/{self.repo}/issues/{t['id']}/comments", {"body": text})


def _dur(v):
    if isinstance(v, (int, float)):
        return float(v)
    v = str(v).strip()
    units = {"s": 1, "m": 60, "h": 3600}
    return float(v[:-1]) * units[v[-1]] if v and v[-1] in units else float(v)


def _future(cfg, **_):
    raise NotImplementedError(f"ticket backend {cfg.get('type')!r} is a documented future adapter (adapters/tickets.py)")


ADAPTERS = {"github": GitHub, "jira": _future}


def backend(cfg, **kw):
    return ADAPTERS[cfg["type"]](cfg, **kw)
