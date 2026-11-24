#!/usr/bin/env python3
"""events/ship.py: security events from hosts and SaaS control planes -> a Loki push endpoint (component `events`).

usage: ship.py --config FILE --state DIR [--summary FILE] [--now EPOCH] [--dry-run]

Config (JSON; the runner writes it from an `events` job, see runner/runner.py):
  {"loki": {"url": "http://host:3100/loki/api/v1/push", "token_file": "/path/0600", "batch": 500, "timeout": 15},
   "sources": [ {"name": "...", "type": "command" | "file-integrity" | "github-account" | "tailscale-audit", ...} ]}

For every source: read what is new since its cursor (state DIR/<name>.json), normalise, push, and only THEN store the
new cursor (at-least-once: a failed push keeps the cursor, the next run sends the events again). One failing source
never stops the others; the exit code is 1 if any source failed. The very first run of a source records a baseline
(cursor / snapshot / seen sources) and reports nothing as "new" or "novel".

Log contract (docs/detection.md "Log contract"; detections/catalog.yaml queries rely on it):
  stream labels        source = auth | codehost | overlay-network, host = the source's `host` (an asset name)
  line                 the raw log line (auth) or a compact JSON of the API record (never a token or key material)
  structured metadata  auth: event, user, src_ip, novel ("true"|"false"); codehost: event, actor, repo;
                       overlay-network: event, actor. Empty values are omitted.
Stdlib only: it runs on hosts without third-party packages (a phone, a router's neighbour, a CI runner).
"""
import argparse
import calendar
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path[:0] = [ROOT]
VERSION = open(os.path.join(HERE, "VERSION")).read().strip()


def log(msg):
    print(f"{time.strftime('%Y-%m-%dT%H:%M:%S%z')} events: {msg}", file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------------------------- classification
AUTH_RULES = [
    (re.compile(r"^Accepted \S+ for (?P<user>\S+) from (?P<src_ip>\S+) port"), "ssh_login_success"),
    (re.compile(r"^Failed \S+ for (?:invalid user )?(?P<user>\S+) from (?P<src_ip>\S+) port"), "ssh_login_failure"),
    (re.compile(r"^Invalid user (?P<user>\S*) from (?P<src_ip>\S+)"), "ssh_login_failure"),
    # dropbear
    (re.compile(r"^Bad password attempt for '(?P<user>[^']*)' from (?P<addr>\S+)"), "ssh_login_failure"),
    (re.compile(r"^Login attempt for nonexistent user(?: '(?P<user>[^']*)')? from (?P<addr>\S+)"), "ssh_login_failure"),
    (re.compile(r"^(?:Pubkey|Password) auth succeeded for '(?P<user>[^']*)'.* from (?P<addr>\S+)"), "ssh_login_success"),
    # sudo (failures first: they carry COMMAND= too)
    (re.compile(r"^\s*(?P<user>\S+) : .*(?:incorrect password|NOT in sudoers|password is required|authentication failure)"),
     "sudo_failure"),
    (re.compile(r"^\s*(?P<user>\S+) : .*COMMAND="), "sudo"),
]


def split_addr(addr):
    """dropbear 'A:P' / '[v6]:P' / 'v6:P' -> address."""
    addr = addr.strip().rstrip(",")
    if addr.startswith("["):
        return addr[1:addr.find("]")]
    if addr.count(":") == 1:
        return addr.split(":")[0]
    if addr.count(":") > 1 and re.search(r":\d+$", addr):
        return addr.rsplit(":", 1)[0]
    return addr


def classify(msg):
    """message (without the syslog prefix) -> {event, user, src_ip} or {} (kept as evidence, no event)."""
    for rx, ev in AUTH_RULES:
        m = rx.search(msg)
        if m:
            d = m.groupdict()
            out = {"event": ev, "user": d.get("user") or ""}
            ip = d.get("src_ip") or (split_addr(d["addr"]) if d.get("addr") else "")
            if ip:
                out["src_ip"] = ip
            return out
    return {}


# ---------------------------------------------------------------------------------------------- line parsers
PROG = r"(?P<prog>sshd(?:-session)?|sudo|dropbear|sshd-auth)(?:\[\d+\])?"
RX_LOGCAT = re.compile(r"^\s*(?P<ts>\d{9,}\.\d+)\s+\d+\s+\d+\s+[VDIWEF]\s+" + PROG + r"\s*:\s?(?P<msg>.*)$")
RX_ISO = re.compile(r"^(?P<ts>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d))\s+\S+\s+" + PROG + r":\s?(?P<msg>.*)$")
RX_BSD = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d\d:\d\d:\d\d)\s+(?:\S+\s+)?(?:\S+\.\S+\s+)?" + PROG + r":\s?(?P<msg>.*)$")


def parse_tz(s):
    if not s:
        return None
    m = re.fullmatch(r"([+-])(\d\d):?(\d\d)", s)
    if not m:
        raise ValueError(f"utc_offset {s!r}: expected +HH:MM")
    sec = (int(m.group(2)) * 3600 + int(m.group(3)) * 60) * (1 if m.group(1) == "+" else -1)
    return timezone(timedelta(seconds=sec))


def bsd_time(s, now, tz):
    """'Nov 24 19:17:01' (no year) -> epoch; the year that puts it closest to (and not after) now."""
    y0 = datetime.fromtimestamp(now).year
    for year in (y0, y0 - 1):
        try:
            dt = datetime.strptime(f"{year} " + " ".join(s.split()), "%Y %b %d %H:%M:%S")
        except ValueError:                          # Feb 29 in a non-leap year
            continue
        e = dt.replace(tzinfo=tz).timestamp() if tz else time.mktime(dt.timetuple())
        if e <= now + 86400:
            return e
    return e


def parse_syslog(line, now, opts):
    """openssh / dropbear / sudo lines in logcat (-v epoch), ISO-8601 (journalctl -o short-iso) or BSD syslog format."""
    if "avc:" in line:                      # Android SELinux audit noise around every exec
        return None
    m = RX_LOGCAT.match(line)
    if m:
        ts = float(m.group("ts"))
    else:
        m = RX_ISO.match(line)
        if m:
            ts = datetime.fromisoformat(m.group("ts").replace("Z", "+00:00")).timestamp()
        else:
            m = RX_BSD.match(line)
            if not m:
                return None
            ts = bsd_time(m.group("ts"), now, parse_tz(opts.get("utc_offset")))
    msg = m.group("msg")
    if m.group("prog") == "dropbear" and msg.startswith("Exit before auth"):
        return None
    return {"ts": ts, "line": line.rstrip("\n"), **classify(msg)}


def parse_macos(line, now, opts):
    """`log show --style ndjson` record -> event (sudo / sshd); unclassified records dropped unless keep_unclassified."""
    try:
        r = json.loads(line)
    except ValueError:
        return None
    if not isinstance(r, dict) or "eventMessage" not in r:
        return None
    ts = datetime.strptime(r["timestamp"], "%Y-%m-%d %H:%M:%S.%f%z").timestamp()
    proc = os.path.basename(r.get("processImagePath") or r.get("process") or "")
    msg = r["eventMessage"]
    ev = classify(msg)
    if not ev and not opts.get("keep_unclassified"):   # directory-service chatter around every sudo: not evidence
        return None
    keep = {"timestamp": r["timestamp"], "process": proc, "pid": r.get("processID"), "message": msg}
    return {"ts": ts, "line": json.dumps(keep, separators=(",", ":")), **ev}


PARSERS = {"openssh": parse_syslog, "dropbear": parse_syslog, "sudo": parse_syslog, "syslog": parse_syslog,
           "macos-unified": parse_macos}


# ---------------------------------------------------------------------------------------------- sources
class Source:
    label_source = "auth"

    def __init__(self, cfg, state, now):
        self.cfg, self.state, self.now = cfg, state, now
        self.first = not state
        self.host = cfg.get("host", cfg["name"])

    def collect(self):
        """-> (events [{ts, line, event?, ...metadata}], new_state)"""
        raise NotImplementedError


def executor(cfg):
    from adapters import exec as ex
    return ex.executor(cfg.get("exec") or {"type": "local"})


class CommandSource(Source):
    """Run argv (local or over ssh) and parse every output line. argv placeholders: {since_epoch}, {since_local}
    (YYYY-MM-DD HH:MM:SS, local time of this runner), from the cursor or `lookback` (default 1h) on the first run."""

    def collect(self):
        parser = PARSERS[self.cfg.get("parser", "syslog")]
        cursor = self.state.get("cursor")
        since = cursor if cursor is not None else self.now - parse_dur(self.cfg.get("lookback", "1h"))
        argv = [a.replace("{since_epoch}", f"{since:.3f}").replace("{since_local}", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(since)))
                for a in self.cfg["argv"]]
        rc, out, err = executor(self.cfg).run(argv, timeout=int(self.cfg.get("timeout", 120)))
        if rc != 0:
            raise RuntimeError(f"command rc={rc}: {err.strip()[-200:]}")
        edge = set(self.state.get("edge", []))
        evs = []
        for line in out.splitlines():
            if not line.strip():
                continue
            e = parser(line, self.now, self.cfg)
            if not e:
                continue
            h = hashlib.sha1(e["line"].encode()).hexdigest()[:16]
            if cursor is not None and (e["ts"] < cursor or (e["ts"] == cursor and h in edge)):
                continue
            e["_h"] = h
            evs.append(e)
        new = dict(self.state)
        if evs:
            top = max(e["ts"] for e in evs)
            new["cursor"] = max(top, cursor or 0)
            new["edge"] = sorted({e["_h"] for e in evs if e["ts"] == top} | (edge if cursor == top else set()))
        elif cursor is None:
            new["cursor"] = since
        if self.first:                               # baseline: remember the sources, report nothing as novel
            self.mark_novel(evs, new, seed=True)
        else:
            self.mark_novel(evs, new)
        for e in evs:
            e.pop("_h", None)
        return evs, new

    def mark_novel(self, evs, new, seed=False):
        seen = {k: set(v) for k, v in (self.state.get("seen") or {}).items()}
        for e in sorted(evs, key=lambda x: x["ts"]):
            if e.get("event") != "ssh_login_success" or not e.get("src_ip"):
                continue
            key = f"{self.host}|{e.get('user', '')}"
            s = seen.setdefault(key, set())
            e["novel"] = "false" if (seed or e["src_ip"] in s) else "true"
            s.add(e["src_ip"])
        new["seen"] = {k: sorted(v) for k, v in seen.items()}


FI_SCRIPT = ('p="$1"; case "$p" in "~/"*) p="$HOME/${p#\\~/}";; esac; '
             'if [ -f "$p" ]; then cat -- "$p"; else echo __absent__; fi')


class FileIntegritySource(Source):
    """sha256 of authorized_keys-style files on a host; a change = event authorized_keys_changed (user = the
    path's owner as configured). First run = baseline."""

    def collect(self):
        ex = executor(self.cfg)
        hashes = dict(self.state.get("hashes") or {})
        evs = []
        for p in self.cfg["paths"]:
            path, user = (p["path"], p.get("user", "")) if isinstance(p, dict) else (p, "")
            rc, out, err = ex.run(["sh", "-c", FI_SCRIPT, "_", path], timeout=60)
            if rc != 0:
                raise RuntimeError(f"{path}: rc={rc}: {err.strip()[-160:]}")
            absent = out.strip() == "__absent__"
            h = "absent" if absent else hashlib.sha256(out.encode()).hexdigest()
            nkeys = 0 if absent else sum(1 for ln in out.splitlines() if ln.strip() and not ln.lstrip().startswith("#"))
            old = hashes.get(path)
            if old is not None and old != h:
                evs.append({"ts": self.now, "event": "authorized_keys_changed", "user": user,
                            "line": f"authorized_keys changed: {path} sha256 {old[:12]} -> {h[:12]} ({nkeys} keys)"})
            hashes[path] = h
        return evs, dict(self.state, hashes=hashes)


class HTTP:
    """Tiny JSON client with conditional requests (ETag cache kept in the source state)."""

    def __init__(self, base, token, cache, timeout=20, opener=None):
        self.base, self.token, self.cache, self.timeout = base.rstrip("/"), token, cache, timeout
        self.calls = 0

    def get(self, path, conditional=True):
        url = path if path.startswith("http") else self.base + path
        req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": f"security-platform-events/{VERSION}"})
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        c = self.cache.get(url) if conditional else None
        if c and c.get("etag"):
            req.add_header("If-None-Match", c["etag"])
        self.calls += 1
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body = json.loads(r.read() or b"null")
                link = r.headers.get("Link", "")
                if conditional and r.headers.get("ETag"):
                    self.cache[url] = {"etag": r.headers["ETag"], "body": body, "link": link}
                return 200, body, link
        except urllib.error.HTTPError as e:
            if e.code == 304 and c:
                return 200, c["body"], c.get("link", "")
            return e.code, None, ""


def next_link(link):
    m = re.search(r'<([^>]+)>;\s*rel="next"', link or "")
    return m.group(1) if m else None


def token_from(cfg):
    if cfg.get("token_file"):
        return read_secret(cfg["token_file"])
    return os.environ.get(cfg.get("token_env", "GH_TOKEN"), "")


class GitHubAccountSource(Source):
    """Snapshot diff of a code host account: SSH/GPG/signing keys, repository visibility, deploy keys and hooks of
    the account's own repositories, app installations; plus the account's public events (PublicEvent). Endpoints the
    token cannot read (404/403) are recorded in `unsupported` and skipped, never a failure."""
    label_source = "codehost"
    KEYS = {"ssh_key": "/user/keys", "gpg_key": "/user/gpg_keys", "signing_key": "/user/ssh_signing_keys"}

    def collect(self):
        cache = dict(self.state.get("http_cache") or {})
        api = HTTP(self.cfg.get("api", "https://api.github.com"), token_from(self.cfg), cache)
        unsupported = {}
        snap = {}
        st, me, _ = api.get("/user")
        if st != 200:
            raise RuntimeError(f"/user: HTTP {st}")
        login = me["login"]
        for kind, path in self.KEYS.items():
            st, body, _ = api.get(path)
            if st == 200:
                snap[kind] = {str(k["id"]): {"id": k["id"], "title": k.get("title") or k.get("name") or k.get("key_id", ""),
                                             "created_at": k.get("created_at")} for k in body}
            else:
                unsupported[path] = st
        repos, url = [], f"/user/repos?affiliation=owner&per_page=100"
        while url:
            st, body, link = api.get(url)
            if st != 200:
                raise RuntimeError(f"/user/repos: HTTP {st}")
            repos += body
            url = next_link(link)
        snap["repo"] = {r["full_name"]: {"full_name": r["full_name"], "visibility": r.get("visibility") or
                                         ("private" if r.get("private") else "public")} for r in repos}
        cap = int(self.cfg.get("max_repos", 50))
        owned = sorted((r for r in repos if r.get("owner", {}).get("login") == login and not r.get("archived")),
                       key=lambda r: r.get("pushed_at") or "", reverse=True)[:cap]
        for kind, sub in (("deploy_key", "keys"), ("hook", "hooks")):
            items = {}
            for r in owned:
                st, body, _ = api.get(f"/repos/{r['full_name']}/{sub}?per_page=100")
                if st != 200:
                    unsupported[f"/repos/*/{sub}"] = st
                    continue
                for k in body:
                    rec = {"id": k["id"], "repo": r["full_name"], "created_at": k.get("created_at")}
                    if kind == "deploy_key":
                        rec.update(title=k.get("title"), read_only=k.get("read_only"))
                    else:
                        u = urllib.parse.urlsplit((k.get("config") or {}).get("url") or "")
                        rec.update(events=k.get("events"), active=k.get("active"), target=u.netloc)
                    items[f"{r['full_name']}#{k['id']}"] = rec
            snap[kind] = items
        st, body, _ = api.get("/user/installations")
        if st == 200:
            snap["app_installation"] = {str(i["id"]): {"id": i["id"], "app_slug": i.get("app_slug"), "created_at": i.get("created_at")}
                                        for i in body.get("installations", [])}
        else:
            unsupported["/user/installations"] = st
        prev = self.state.get("snapshot")
        evs = [] if prev is None else self.diff(prev, snap, login)
        pub, ids = self.public_events(api, login)
        evs += pub
        new = dict(self.state, snapshot=snap, http_cache=cache, unsupported=unsupported, api_calls=api.calls)
        new["events_seen"] = sorted(set(self.state.get("events_seen", [])) | ids)[-500:]
        return evs, new

    def public_events(self, api, login):
        """PublicEvent = a repository became public (second signal, independent of the snapshot)."""
        st, body, _ = api.get(f"/users/{login}/events?per_page=100")
        if st != 200 or not isinstance(body, list):
            return [], set()
        seen, ids, out = set(self.state.get("events_seen", [])), set(), []
        for e in body:
            if e.get("type") != "PublicEvent":
                continue
            ids.add(e["id"])
            if self.first or e["id"] in seen:
                continue
            rec = {"type": "PublicEvent", "repo": e.get("repo", {}).get("name"), "created_at": e.get("created_at")}
            out.append({"ts": iso_ts(e.get("created_at")) or self.now, "event": "repo_made_public",
                        "actor": e.get("actor", {}).get("login", ""), "repo": rec["repo"] or "",
                        "line": json.dumps(rec, separators=(",", ":"))})
        return out, ids

    def diff(self, prev, snap, login):
        evs = []
        for kind in sorted(set(prev) | set(snap)):
            old, cur = prev.get(kind, {}), snap.get(kind, {})
            if kind not in snap or kind not in prev:      # newly (un)readable: no diff on a missing side
                continue
            if kind == "repo":
                for name, r in cur.items():
                    was = old.get(name)
                    if was and was["visibility"] != r["visibility"]:
                        ev = "repo_made_public" if r["visibility"] == "public" else f"repo_made_{r['visibility']}"
                        evs.append(self.ev(ev, login, name, {"repo": name, "from": was["visibility"], "to": r["visibility"]}))
                    elif not was and r["visibility"] == "public":
                        evs.append(self.ev("repo_created_public", login, name, r))
                continue
            for k in sorted(set(cur) - set(old)):
                evs.append(self.ev(f"{kind}_added", login, cur[k].get("repo", ""), cur[k]))
            for k in sorted(set(old) - set(cur)):
                evs.append(self.ev(f"{kind}_removed", login, old[k].get("repo", ""), old[k]))
        return evs

    def ev(self, event, actor, repo, rec):
        return {"ts": self.now, "event": event, "actor": actor, "repo": repo or "",
                "line": json.dumps(dict(rec, event=event), separators=(",", ":"), default=str)}


def iso_ts(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


class TailscaleAuditSource(Source):
    """Overlay network configuration audit log (Tailscale API, logging/configuration). Credentials, 0600 files:
    preferred `oauth_client_id` + `oauth_client_secret_file` (an OAuth client whose scopes include
    logs:configuration:read; exchanged for a short-lived token), else `token_file` (an API access token)."""
    label_source = "overlay-network"

    @staticmethod
    def map(r):
        t = (r.get("target") or {})
        tt, prop, act = (t.get("type") or "").upper(), (t.get("property") or "").upper(), (r.get("type") or r.get("action") or "").upper()
        new = r.get("new")
        if tt == "NODE" and act == "CREATE":
            return "node_added"
        if tt == "NODE" and "KEY_EXPIRY" in prop and (
                ("DISABLED" in prop and new in (True, "true")) or ("DISABLED" not in prop and new in (False, "false", "disabled"))):
            return "node_key_expiry_disabled"
        if tt == "NODE" and ("ROUTE" in prop or "EXIT" in prop):
            return "exit_node_enabled" if ("0.0.0.0/0" in json.dumps(new) or "::/0" in json.dumps(new) or "EXIT" in prop) else "subnet_routes_changed"
        if tt in ("ACL", "POLICY", "POLICY_FILE") or prop in ("ACL", "POLICY"):
            return "policy_changed"
        if tt in ("API_KEY", "AUTH_KEY", "KEY") and act == "CREATE":
            return "auth_key_created"
        if tt == "USER" and act == "CREATE":
            return "user_added"
        if tt == "USER" and "ROLE" in prop:
            return "user_role_changed"
        return re.sub(r"[^a-z0-9]+", "_", f"{tt}_{act}".lower()).strip("_") or "other"

    def token(self):
        if self.cfg.get("oauth_client_secret_file"):
            body = urllib.parse.urlencode({"client_id": self.cfg["oauth_client_id"],
                                           "client_secret": read_secret(self.cfg["oauth_client_secret_file"])}).encode()
            req = urllib.request.Request(self.cfg.get("api", "https://api.tailscale.com") + "/api/v2/oauth/token", data=body,
                                         headers={"Content-Type": "application/x-www-form-urlencoded"})
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read())["access_token"]
        return read_secret(self.cfg["token_file"])

    def collect(self):
        cursor = self.state.get("cursor")
        start = cursor if cursor is not None else self.now - parse_dur(self.cfg.get("lookback", "1h"))
        fmt = lambda e: datetime.fromtimestamp(e, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")  # noqa: E731
        api = HTTP(self.cfg.get("api", "https://api.tailscale.com"), self.token(), {})
        q = urllib.parse.urlencode({"start": fmt(start), "end": fmt(self.now)})
        st, body, _ = api.get(f"/api/v2/tailnet/{self.cfg.get('tailnet', '-')}/logging/configuration?{q}", conditional=False)
        if st != 200:
            raise RuntimeError(f"configuration log: HTTP {st}")
        seen = set(self.state.get("edge", []))
        evs = []
        for r in (body or {}).get("logs", []):
            rid = str(r.get("eventGroupID", "")) + "|" + json.dumps(r.get("target"), sort_keys=True)
            ts = iso_ts(r.get("eventTime")) or self.now
            if rid in seen:
                continue
            a = r.get("actor") or {}
            rec = {k: r.get(k) for k in ("eventTime", "origin", "type", "target", "old", "new", "eventGroupID")}
            rec["actor"] = a.get("loginName") or a.get("displayName") or a.get("id")
            evs.append({"ts": ts, "event": self.map(r), "actor": rec["actor"] or "", "line": json.dumps(rec, separators=(",", ":"), default=str),
                        "_id": rid})
        new = dict(self.state, cursor=self.now - 300)     # the API can be late by a little: overlap 5 min, dedupe by id
        new["edge"] = sorted({e["_id"] for e in evs} | {x for x in seen})[-1000:]
        for e in evs:
            e.pop("_id")
        if self.first:
            evs = []                                       # baseline: history before the first run is not "new"
        return evs, new


SOURCES = {"command": CommandSource, "file-integrity": FileIntegritySource,
           "github-account": GitHubAccountSource, "tailscale-audit": TailscaleAuditSource}


# ---------------------------------------------------------------------------------------------- sink
def read_secret(path):
    path = os.path.expanduser(path)
    st = os.stat(path)
    if st.st_mode & 0o077:
        raise PermissionError(f"{path}: readable by group/others (chmod 600)")
    return open(path).read().strip()


META = {"auth": ("event", "user", "src_ip", "novel"), "codehost": ("event", "actor", "repo"),
        "overlay-network": ("event", "actor")}


def to_streams(label_source, host, evs):
    vals = []
    for e in sorted(evs, key=lambda x: x["ts"]):
        md = {k: str(e[k]) for k in META[label_source] if e.get(k) not in (None, "")}
        vals.append([str(int(e["ts"] * 1e9)), e["line"], md] if md else [str(int(e["ts"] * 1e9)), e["line"]])
    return {"stream": {"source": label_source, "host": host}, "values": vals}


def push(loki, streams):
    if not streams:
        return
    token = read_secret(loki["token_file"]) if loki.get("token_file") else ""
    batch = int(loki.get("batch", 500))
    for s in streams:
        for i in range(0, len(s["values"]), batch):
            body = json.dumps({"streams": [{"stream": s["stream"], "values": s["values"][i:i + batch]}]}).encode()
            req = urllib.request.Request(loki["url"], data=body, method="POST", headers={"Content-Type": "application/json"})
            if token:
                req.add_header("Authorization", f"Bearer {token}")
            with urllib.request.urlopen(req, timeout=int(loki.get("timeout", 15))) as r:
                if r.status // 100 != 2:
                    raise RuntimeError(f"push: HTTP {r.status}")


def parse_dur(s):
    m = re.fullmatch(r"(\d+)([smhd])", str(s))
    if not m:
        raise ValueError(f"duration {s!r}")
    return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--state", required=True)
    ap.add_argument("--summary")
    ap.add_argument("--now", type=float)
    ap.add_argument("--dry-run", action="store_true", help="print the push body instead of sending; state unchanged")
    a = ap.parse_args(argv)
    cfg = json.load(open(a.config))
    now = a.now or time.time()
    os.makedirs(a.state, exist_ok=True)
    summary, failed = {"version": VERSION, "sources": {}}, 0
    for sc in cfg.get("sources", []):
        name = sc["name"]
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
            raise SystemExit(f"source name {name!r}: letters, digits, . _ - only")
        sp = os.path.join(a.state, f"{name}.json")
        try:
            state = json.load(open(sp)) if os.path.exists(sp) else {}
            src = SOURCES[sc["type"]](sc, state, now)
            evs, new = src.collect()
            streams = [to_streams(src.label_source, src.host, evs)] if evs else []
            if a.dry_run:
                print(json.dumps({"streams": streams}, indent=1))
            else:
                push(cfg["loki"], streams)
                with open(sp + ".tmp", "w") as f:
                    json.dump(new, f, sort_keys=True)
                os.chmod(sp + ".tmp", 0o600)
                os.replace(sp + ".tmp", sp)
            counts = {}
            for e in evs:
                counts[e.get("event") or "-"] = counts.get(e.get("event") or "-", 0) + 1
            summary["sources"][name] = {"ok": True, "shipped": len(evs), "events": counts, "baseline": src.first,
                                        "unsupported": new.get("unsupported", {})}
            log(f"{name}: shipped {len(evs)} {counts if counts else ''}{' (baseline)' if src.first else ''}")
        except Exception as e:  # noqa: BLE001 - one broken source must not stop the others; cursor kept
            failed += 1
            summary["sources"][name] = {"ok": False, "error": f"{type(e).__name__}: {str(e)[:200]}"}
            log(f"{name}: FAILED {type(e).__name__}: {str(e)[:200]} (cursor kept)")
    if a.summary:
        with open(a.summary, "w") as f:
            json.dump(summary, f, indent=1, sort_keys=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
