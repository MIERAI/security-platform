#!/usr/bin/env python3
"""sp: the day-to-day command line of security-platform (component `cli`, see cli/VERSION). Stdlib (+PyYAML for
YAML configs).

    sp init DIR [--name NAME]          create a private data directory with a starter instance.yaml
    sp doctor                          check the config, the tools each configured collector needs, file permissions
    sp run [JOB ...]                   run jobs now (default: every job in the config), then publish the metrics
    sp status                          one screen: jobs, open findings, overdue fixes, coverage, scorecard
    sp findings [--open] [--severity high] [--layer L] [--check C] [--overdue] [--json|--ids]
    sp explain ID                      what it is, why it matters, how to fix it, how to verify, how to accept it
    sp digest [--daily]                the short summary that notifiers send (aggregates only)
    sp notify [--dry-run]              send the digest through the configured notifiers

Where the data is: --data DIR, else $SP_DATA. The instance config: --instance FILE, else $SP_INSTANCE, else
DIR/instance.yaml (or .json). Nothing here changes a finding's status: fixes are confirmed by the next scan, risk
acceptance is a human edit of exceptions.yaml (sp explain prints the snippet).
"""
import argparse
import glob
import json
import os
import shutil
import stat
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path[:0] = [HERE, ROOT, os.path.join(ROOT, "sdk")]
import explanations  # noqa: E402
from spsdk import load_config  # noqa: E402

VERSION = open(os.path.join(HERE, "VERSION")).read().strip()
SEV = ["critical", "high", "medium", "low", "info"]
COLLECTOR_TOOLS = {"exposure": ["nmap"], "host": [], "k8s": ["kubectl"], "codehost-github": ["gh"],
                   "vuln-intel": ["trivy"], "secrets-files": [], "agent-claude-code": [], "codehost-gitea": [],
                   "identity": [], "host-sbom": [], "cloud": []}     # cloud: engine paths are in the instance (cloud.engines)
NON_COLLECTOR = ("remediation", "export", "digest", "snapshot", "push", "pull-snapshot", "notify")
TTY = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def c(code, s):
    return f"\033[{code}m{s}\033[0m" if TTY else s


def sev_c(s):
    return c({"critical": "1;31", "high": "31", "medium": "33", "low": "36"}.get(s, "0"), s)


def ts(s):
    s = str(s)
    fmt, n = ("%Y-%m-%dT%H:%M:%S", 19) if "T" in s else ("%Y-%m-%d", 10)
    return time.mktime(time.strptime(s[:n], fmt)) - time.timezone


def ago(t, now=None):
    d = (now or time.time()) - t
    for unit, n in (("d", 86400), ("h", 3600), ("m", 60)):
        if d >= n:
            return f"{int(d // n)}{unit} ago"
    return "just now"


def die(msg, rc=2):
    print(f"sp: {msg}", file=sys.stderr)
    sys.exit(rc)


# ---- context ------------------------------------------------------------------------------------------------
class Ctx:
    def __init__(self, a):
        d = a.data or os.environ.get("SP_DATA")
        if not d:
            die("where is your data directory? pass --data DIR or set SP_DATA (create one with `sp init DIR`)")
        self.data = os.path.abspath(os.path.expanduser(d))
        if not os.path.isdir(self.data):
            die(f"{self.data} does not exist (create it with `sp init {d}`)")
        inst = a.instance or os.environ.get("SP_INSTANCE")
        if not inst:
            inst = next((os.path.join(self.data, f) for f in ("instance.yaml", "instance.yml", "instance.json")
                         if os.path.exists(os.path.join(self.data, f))), os.path.join(self.data, "instance.yaml"))
        self.instance_path = inst
        self._inst = None

    @property
    def inst(self):
        if self._inst is None:
            try:
                self._inst = load_config(self.instance_path) or {}
            except FileNotFoundError:
                die(f"no instance config at {self.instance_path} (sp init writes a starter one)")
        return self._inst

    def ledger(self):
        p = os.path.join(self.data, "ledger.json")
        if not os.path.exists(p):
            return {"entries": {}, "sli": {}, "collectors": {}}
        return json.load(open(p))

    def items(self):
        p = os.path.join(self.data, "tracker", "items.json")
        if not os.path.exists(p):
            return {}
        d = json.load(open(p))
        return d.get("items", d) if isinstance(d, dict) else {i["id"]: i for i in d}

    def scorecard(self):
        for p in ("scorecard/latest.json", "scorecard.json", "reports/scorecard.json"):
            f = os.path.join(self.data, p)
            if os.path.exists(f):
                try:
                    return json.load(open(f))
                except ValueError:
                    return None
        return None

    def job_states(self):
        out = {}
        for p in glob.glob(os.path.join(self.data, "state", "runner", "*.json")):
            n = os.path.basename(p)[:-5]
            if n in ("sinks",):
                continue
            try:
                out[n] = json.load(open(p))
            except ValueError:
                pass
        return out


# ---- init / doctor ------------------------------------------------------------------------------------------
STARTER = """# security-platform instance config: what to look at, and when. PRIVATE (it describes your environment).
# Every section is optional: delete what you do not have. Reference with all defaults: docs/instance-reference.md
name: {name}

# 1. Machines (read-only checks; key login only, never a password prompt). The first entry is THIS machine, so the
#    first `sp run` already has something to show.
hosts:
  - {{name: {host}, exec: {{type: local}}, profile: {profile}}}
#  - {{name: web-1, exec: {{type: ssh, host: web-1}}, profile: linux}}       # profile: linux | macos | windows | busybox | termux

# 2. What can an outsider reach? (needs nmap where `vantage` runs; then add the `exposure` job below)
# exposure:
#   discovery:
#     - {{type: static, targets: [{{name: web-1, address: 192.0.2.10}}], cidrs: ["192.0.2.0/28"]}}
#   vantage: {{type: local}}         # better: a host OUTSIDE the network, {{type: ssh, host: <ssh alias>}}

# 3. Kubernetes clusters (get/list only)
kubernetes: []
#  - {{name: prod, kubeconfig: ~/.kube/prod-readonly.yaml, role: prod}}

# 4. Code hosts
codehost: []
#  - {{type: github, owner: your-org, gh_user: your-bot}}
#  - {{type: gitea, url: https://git.example.com, owner: your-org, token_file: ~/.config/security-platform/gitea.token}}

# Who fixes what, and how fast (defaults: critical 7d, high 30d, medium 90d, low 180d)
remediation:
  default_owner: security-oncall

# Notifications: a short daily summary (counts only, never asset details). Default: none.
notify: []
#  - {{type: telegram, token_file: ~/.config/security-platform/telegram.token, chat_id_file: ~/.config/security-platform/telegram.chat}}
#  - {{type: webhook, url_file: ~/.config/security-platform/webhook.url}}     # Slack / Mattermost / Teams / ntfy

# When things run (cron syntax, local time). `sp run` runs them all now.
runner:
  site: hub
  role: hub
  sinks: []                          # where metrics go; see docs/runner.md "Metrics delivery"
  jobs:
    host:        {{schedule: "15 2 * * *", timeout: 30m}}
    remediation: {{type: remediation, schedule: "50 * * * *"}}
    digest:      {{type: digest, schedule: "0 9 * * 1"}}
#   exposure:        {{schedule: "30 3 * * *", timeout: 2h}}
#   k8s:             {{schedule: "45 2 * * *", timeout: 45m}}
#   codehost-github: {{schedule: "0 7 * * *"}}
#   codehost-gitea:  {{schedule: "0 7 * * *"}}
#   notify:          {{type: notify, schedule: "0 8 * * *"}}
"""


def cmd_init(a):
    d = os.path.abspath(os.path.expanduser(a.dir))
    os.makedirs(d, exist_ok=True)
    os.chmod(d, 0o700)
    p = os.path.join(d, "instance.yaml")
    if os.path.exists(p) and not a.force:
        print(f"{p} exists: left as it is (--force overwrites)")
    else:
        with open(p, "w") as f:
            import platform
            prof = {"Darwin": "macos", "Windows": "windows"}.get(platform.system(), "linux")
            if os.path.isdir("/data/data/com.termux"):
                prof = "termux"
            f.write(STARTER.format(name=a.name or os.path.basename(d.rstrip("/")), profile=prof,
                                   host=(platform.node().split(".")[0] or "this-machine").lower()))
        os.chmod(p, 0o600)
        print(f"wrote {p}")
    ex = os.path.join(d, "exceptions.yaml")
    if not os.path.exists(ex):
        with open(ex, "w") as f:
            f.write("# Human-approved risk acceptances. `sp explain <id>` prints a ready-to-edit entry.\n"
                    "exceptions: {}\n")
    gi = os.path.join(d, ".gitignore")
    if not os.path.exists(gi):
        open(gi, "w").write("state/locks/\ncache/\n")
    print(f"""
Next:
  1. edit {p}  (keep what you have, delete the rest)
  2. sp doctor --data {a.dir}     checks tools and permissions
  3. sp run --data {a.dir}        first scan, then: sp status / sp findings --open
This directory holds attacker-relevant information: keep it private (mode 0700, never in a public repository).""")


def which(tool):
    return shutil.which(tool) is not None


def cmd_doctor(a):
    ctx = Ctx(a)
    problems, notes = [], []

    def ok(msg):
        print(f"  {c('32', 'ok')}    {msg}")

    def bad(msg, fix):
        problems.append(msg)
        print(f"  {c('31', 'FIX')}   {msg}\n        -> {fix}")

    print(f"config {ctx.instance_path}")
    inst = ctx.inst
    ok(f"loads ({len(inst)} sections, name={inst.get('name', '?')})")
    mode = stat.S_IMODE(os.stat(ctx.data).st_mode)
    if mode & 0o077:
        bad(f"data directory is readable by others (mode {oct(mode)})", f"chmod 700 {ctx.data}")
    else:
        ok("data directory is private (0700)")
    jobs = ((inst.get("runner") or {}).get("jobs") or {})
    if not jobs:
        bad("no jobs in runner.jobs", "add jobs (sp init writes examples)")
    for name, j in jobs.items():
        typ = (j or {}).get("type", "collector")
        col = (j or {}).get("collector", name)
        if typ == "collector":
            if not os.path.exists(os.path.join(ROOT, "collectors", col, "collector.py")):
                bad(f"job {name}: unknown collector {col}", f"one of: {', '.join(sorted(COLLECTOR_TOOLS))}")
                continue
            for t in COLLECTOR_TOOLS.get(col, []):
                if col == "exposure" and ((inst.get("exposure") or {}).get("vantage") or {}).get("type") != "local":
                    continue   # nmap runs on the remote vantage host
                (ok if which(t) else lambda m: bad(m, f"install {t} (see docs/quickstart.md)"))(
                    f"job {name}: needs `{t}`" + ("" if which(t) else " - not found"))
    for h in inst.get("hosts") or []:
        if ((h.get("exec") or {}).get("type")) == "ssh" and not which("ssh"):
            bad("hosts use ssh but `ssh` is not installed", "install an OpenSSH client")
            break
    secret_files = []
    for sect in ("codehost", "notify"):
        for e in inst.get(sect) or []:
            secret_files += [(sect, k, e[k]) for k in e if k.endswith("_file")]
    for s in (inst.get("runner") or {}).get("sinks") or []:
        secret_files += [("sink", k, s[k]) for k in s if k.endswith("_file") and k != "ca_file"]
    for sect, k, path in secret_files:
        if k == "ca_file":
            continue
        p = os.path.expanduser(path)
        if not os.path.exists(p):
            bad(f"{sect}: {k} {path} does not exist", "create it (one line, the secret only) with mode 0600")
        elif stat.S_IMODE(os.stat(p).st_mode) & 0o077:
            bad(f"{sect}: {k} {path} is readable by others", f"chmod 600 {path}")
        else:
            ok(f"{sect}: {k} is private")
    try:
        import yaml  # noqa: F401
    except ImportError:
        if ctx.instance_path.endswith((".yaml", ".yml")):
            bad("PyYAML is missing (needed for a YAML config)", "pip install -r deploy/requirements.lock, or use JSON")
    for n in notes:
        print("  note  " + n)
    print(("\n" + c("31", f"{len(problems)} thing(s) to fix")) if problems else "\n" + c("32", "ready: sp run"))
    return 1 if problems else 0


# ---- run --------------------------------------------------------------------------------------------------------
def cmd_run(a):
    ctx = Ctx(a)
    jobs = ((ctx.inst.get("runner") or {}).get("jobs") or {})
    names = a.jobs or [n for n, j in jobs.items() if (j or {}).get("type", "collector") not in
                       ("digest", "snapshot", "push", "pull-snapshot", "notify")]
    unknown = [n for n in names if n not in jobs]
    if unknown:
        die(f"not in runner.jobs: {', '.join(unknown)} (configured: {', '.join(jobs) or 'none'})")
    # collectors and ingests first, then what derives from the ledger
    names.sort(key=lambda n: (jobs[n] or {}).get("type", "collector") in NON_COLLECTOR)
    print(f"running {len(names)} job(s): {', '.join(names)}  (each job's log: {ctx.data}/runs/<date>/)")
    t0 = time.time()
    rc = subprocess.call([sys.executable, os.path.join(ROOT, "runner", "runner.py"), "run", *names,
                          "--instance", ctx.instance_path, "--data", ctx.data])
    st = ctx.job_states()
    for n in names:
        s = st.get(n, {})
        good = s.get("last_rc") == 0 and (s.get("last_success") or 0) >= t0 - 1
        print(f"  {c('32', 'ok') if good else c('31', 'FAILED')}  {n:<20} {s.get('last_duration', 0):>6.0f}s  "
              f"{'' if good else (s.get('last_note') or '')[:100]}")
    print("next: sp status   |   sp findings --open --severity high")
    return rc


# ---- status / findings / explain -------------------------------------------------------------------------------
def open_entries(L):
    return [e for e in L.get("entries", {}).values() if e.get("status") == "open"]


def cmd_status(a):
    ctx = Ctx(a)
    L, items, now = ctx.ledger(), ctx.items(), time.time()
    op = open_entries(L)
    print(c("1", f"security-platform status - {ctx.inst.get('name', '')}"))
    if not L.get("entries") and not L.get("collectors"):
        print("  no scan yet: run `sp run`")
        return 0
    by = {s: sum(1 for e in op if e["severity"] == s) for s in SEV}
    print("\nOpen findings: " + ", ".join(f"{sev_c(s)} {n}" for s, n in by.items() if n) if op else "\nOpen findings: none")
    overdue = [i for i in items.values() if i.get("overdue")]
    if overdue:
        print(c("31", f"Overdue fixes: {len(overdue)}") + " (past their remediation SLO; `sp findings --overdue`)")
    unassigned = [i for i in items.values() if i.get("status") == "open" and i.get("owner") == "unassigned"]
    if unassigned:
        print(f"Without an owner: {len(unassigned)} (set remediation.default_owner)")
    fixed7 = [e for e in L.get("entries", {}).values() if e.get("status") == "fixed" and e.get("fixed_at")
              and now - ts(e["fixed_at"]) < 7 * 86400]
    reopened = [e for e in op if e.get("reopened_count")]
    print(f"Fixed in the last 7 days: {len(fixed7)}" + (f"   Came back (regressions): {len(reopened)}" if reopened else ""))
    sc = ctx.scorecard()
    if sc:
        print("\nScorecard: " + scorecard_line(sc) + f"  ({sc.get('status', '?')}, threshold {sc.get('threshold', 75)})")
        pil = sc.get("pillars") or {}
        if pil:
            print("  pillars: " + ", ".join(f"{k} {v.get('score') if isinstance(v, dict) else v}" for k, v in pil.items()))
    sli = L.get("sli") or {}
    bad = [k for k, v in sli.items() if not v.get("ok")]
    if sli:
        print(f"\nSecurity SLIs: {len(sli) - len(bad)}/{len(sli)} on target" +
              (": off target " + ", ".join(f"{k}={sli[k].get('value')}" for k in bad) if bad else ""))
    print("\nJobs:")
    jobs = ((ctx.inst.get("runner") or {}).get("jobs") or {})
    st = ctx.job_states()
    for n in jobs:
        s = st.get(n)
        if not s or not s.get("runs_total"):
            print(f"  {c('33', 'never')}   {n}")
            continue
        good = s.get("last_rc") == 0
        last = s.get("last_success")
        print(f"  {c('32', 'ok') if good else c('31', 'FAILING')}  {n:<20} last good run "
              f"{ago(last, now) if last else 'never'}" + ("" if good else f"  ({(s.get('last_note') or '')[:80]})"))
    gaps = []
    for p in glob.glob(os.path.join(ctx.data, "latest", "*.findings.json")):
        try:
            d = json.load(open(p))
        except ValueError:
            continue
        gaps += [(d["collector"]["name"], g.get("reason", "")) for g in d.get("coverage", []) if g.get("status") == "gap"]
    if gaps:
        print(c("33", f"\nCould not check {len(gaps)} thing(s)") + " (no finding there does NOT mean safe):")
        for col, why in gaps[:8]:
            print(f"  {col}: {why[:100]}")
    top = sorted(op, key=lambda e: (SEV.index(e["severity"]), e["first_seen"]))[:5]
    if top:
        print("\nTop risks (sp explain <id>):")
        for e in top:
            print(f"  {e['id']}  {sev_c(e['severity']):<8} {explanations.headline(e['check'], e['title'])[:90]}")
    return 0


def scorecard_line(sc):
    """The scorecard document (docs/scorecard.md, reports/scorecard.json): the overall (weakest) score and the
    dimensions' scores."""
    total = sc.get("overall", sc.get("score"))
    dims = sc.get("dimensions") or {}
    if isinstance(dims, list):
        dims = {d.get("id", d.get("name")): d for d in dims}
    worst = sorted(((k, (v.get("score") if isinstance(v, dict) else v)) for k, v in dims.items()),
                   key=lambda kv: (kv[1] is None, kv[1]))[:3]
    s = f"{total}/100" if total is not None else "?"
    if worst:
        s += "   weakest: " + ", ".join(f"{k} {v}" for k, v in worst)
    return s


def matches(e, a, items):
    if a.open and e.get("status") != "open":
        return False
    if a.severity:
        floor = SEV.index(a.severity)
        if SEV.index(e["severity"]) > floor:
            return False
    if a.layer and e["layer"] != a.layer:
        return False
    if a.check and not e["check"].startswith(a.check):
        return False
    if a.overdue and not (items.get(e["id"]) or {}).get("overdue"):
        return False
    return True


def cmd_findings(a):
    ctx = Ctx(a)
    L, items = ctx.ledger(), ctx.items()
    rows = [e for e in L.get("entries", {}).values() if matches(e, a, items)]
    rows.sort(key=lambda e: (SEV.index(e["severity"]), e["layer"], e["asset"]))
    if a.json:
        print(json.dumps(rows, indent=1, sort_keys=True))
        return 0
    if a.ids:
        print("\n".join(e["id"] for e in rows))
        return 0
    if not rows:
        print("no matching findings")
        return 0
    now = time.time()
    print(f"{'ID':<13}{'SEVERITY':<10}{'STATUS':<9}{'DUE':<12}{'LAYER':<13}{'ASSET':<38}WHAT")
    for e in rows:
        it = items.get(e["id"]) or {}
        due = it.get("due_at")
        due_s = ("OVERDUE" if it.get("overdue") else (time.strftime("%Y-%m-%d", time.localtime(ts(due))) if due else "-"))
        print(f"{e['id']:<13}{sev_c(e['severity']):<{10 + (len(sev_c(e['severity'])) - len(e['severity']))}}"
              f"{e['status']:<9}{c('31', due_s) if due_s == 'OVERDUE' else due_s:<12}{e['layer']:<13}"
              f"{e['asset'][:37]:<38}{e['title'][:70]}")
    print(f"\n{len(rows)} finding(s). Details and how to fix: sp explain <ID>")
    _ = now
    return 0


def cmd_explain(a):
    ctx = Ctx(a)
    L, items = ctx.ledger(), ctx.items()
    ent = L.get("entries", {})
    e = ent.get(a.id) or next((v for k, v in ent.items() if k.startswith(a.id)), None)
    if not e:
        die(f"no finding {a.id} (list them with `sp findings`)")
    x = explanations.explain(e["check"])
    it = items.get(e["id"]) or {}
    print(c("1", f"{e['title']}"))
    print(f"id {e['id']}   check {e['check']}   {sev_c(e['severity'])} ({explanations.SEVERITY_WORDS.get(e['severity'], '')})")
    print(f"where: {e['asset']}   area: {e['layer']} - {explanations.LAYER_WORDS.get(e['layer'], '')}")
    print(f"status: {e['status']}   first seen {e['first_seen'][:10]}   last seen {e['last_seen'][:10]}"
          + (f"   came back {e['reopened_count']}x" if e.get("reopened_count") else ""))
    if it:
        print(f"owner: {it.get('owner', '-')}   fix by: {str(it.get('due_at') or '-')[:10]}"
              + (c("31", "   OVERDUE") if it.get("overdue") else ""))
    print()
    if x.get("what"):
        print(c("1", "What it means") + "\n  " + x["what"])
    if x.get("why"):
        print(c("1", "Why it matters") + "\n  " + x["why"])
    print(c("1", "How to fix"))
    for line in (x.get("fix") or "").splitlines():
        print("  " + line)
    if e.get("remediation"):
        print(f"  (collector's note: {e['remediation']})")
    print(c("1", "How to verify") + "\n  " + x.get("verify", explanations.NEXT_SCAN))
    if e.get("needs_human"):
        print("\n  This one needs a person (a password, an account setting or a physical step); no automation can do it.")
    print(c("1", "\nIf you decide to accept the risk instead") + " (a human decision with an end date), add to "
          f"{os.path.join(ctx.data, 'exceptions.yaml')}:")
    print(f"""  exceptions:
    {e['id']}:
      approved_by: <your name>
      reason: <why this is acceptable for now>
      expires: '{time.strftime('%Y-%m-%d', time.localtime(time.time() + 90 * 86400))}'""")
    print(f"\nevidence (private): {os.path.join(ctx.data, 'runs')}/.../{e.get('evidence', '').split('#')[0]}")
    return 0


# ---- digest / notify ------------------------------------------------------------------------------------------------
def digest(ctx, days=1, now=None):
    """The short summary for notifiers. AGGREGATES ONLY: counts, check families and plain words. No asset names,
    addresses, ports or evidence: notifications leave the private boundary (chat services, phones)."""
    now = now or time.time()
    L, items = ctx.ledger(), ctx.items()
    ent = list(L.get("entries", {}).values())
    op = [e for e in ent if e.get("status") == "open"]
    since = now - days * 86400
    new = [e for e in op if ts(e["first_seen"]) >= since]
    fixed = [e for e in ent if e.get("status") == "fixed" and e.get("fixed_at") and ts(e["fixed_at"]) >= since]
    back = [e for e in op if e.get("reopened_count") and ts(e["last_seen"]) >= since]
    overdue = [i for i in items.values() if i.get("overdue")]
    by = {s: sum(1 for e in op if e["severity"] == s) for s in SEV}
    period = "today" if days == 1 else f"last {days} days"
    lines = [f"Security {time.strftime('%Y-%m-%d', time.localtime(now))} ({ctx.inst.get('name', '')})"]
    lines.append("Open: " + (", ".join(f"{n} {s}" for s, n in by.items() if n and s != "info") or "nothing above info"))
    lines.append(f"{period}: {len(new)} new, {len(fixed)} fixed" + (f", {len(back)} came back" if back else ""))
    if overdue:
        lines.append(f"Overdue fixes: {len(overdue)}")
    sc = ctx.scorecard()
    if sc:
        lines.append("Scorecard: " + scorecard_line(sc))
    stale = []
    for n, s in ctx.job_states().items():
        if s.get("runs_total") and s.get("last_rc") not in (0, None):
            stale.append(n)
    if stale:
        lines.append(f"Jobs failing: {len(stale)} (sp status)")
    worst = sorted([e for e in new or op if e["severity"] in ("critical", "high")],
                   key=lambda e: (SEV.index(e["severity"]), e["first_seen"]))
    if worst:
        lines.append("Top:" if not new else "New and serious:")
        seen = set()
        for e in worst:
            h = explanations.headline(e["check"], e["check"])
            if h in seen:
                continue
            seen.add(h)
            n = sum(1 for x in (new or op) if x["check"] == e["check"])
            lines.append(f"- {e['severity']}: {h}" + (f" (x{n})" if n > 1 else "") + f"  [sp explain {e['id']}]")
            if len(seen) == 5:
                break
    if not op and not overdue and not stale:
        lines.append("All clear.")
    return "\n".join(lines)


def cmd_digest(a):
    ctx = Ctx(a)
    print(digest(ctx, days=1 if a.daily else a.days))
    return 0


def cmd_notify(a):
    ctx = Ctx(a)
    sys.path.insert(0, ROOT)
    from notifier import notifiers
    cfgs = ctx.inst.get("notify") or []
    if not cfgs:
        die("no notifiers configured (instance `notify:`; see docs/instance-reference.md)", 1)
    text = digest(ctx, days=a.days)
    if a.dry_run:
        print(text)
        print(f"\n(dry run: {len(cfgs)} notifier(s) not called)")
        return 0
    rc = 0
    for i, cfg in enumerate(cfgs):
        try:
            notifiers.send(cfg, text)
            print(f"sent via {i}-{cfg.get('type')}")
        except Exception as e:  # noqa: BLE001 - one failing notifier must not stop the others
            print(f"notifier {i}-{cfg.get('type')} failed: {type(e).__name__}: {str(e)[:160]}", file=sys.stderr)
            rc = 1
    return rc


def main(argv=None):
    ap = argparse.ArgumentParser(prog="sp", description="security-platform command line",
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__.split("\n\n")[1])
    ap.add_argument("--version", action="version", version=f"sp {VERSION}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def p(name, fn, help_):
        s = sub.add_parser(name, help=help_)
        s.set_defaults(fn=fn)
        if name != "init":
            s.add_argument("--data", help="private data directory (default $SP_DATA)")
            s.add_argument("--instance", help="instance config (default DATA/instance.yaml)")
        return s

    s = p("init", cmd_init, "create a private data directory with a starter config")
    s.add_argument("dir")
    s.add_argument("--name")
    s.add_argument("--force", action="store_true")
    p("doctor", cmd_doctor, "check the config, tools and permissions")
    s = p("run", cmd_run, "run jobs now")
    s.add_argument("jobs", nargs="*")
    p("status", cmd_status, "one-screen overview")
    s = p("findings", cmd_findings, "list findings")
    s.add_argument("--open", action="store_true", help="only open findings")
    s.add_argument("--severity", choices=SEV, help="this severity or worse")
    s.add_argument("--layer")
    s.add_argument("--check", help="check name or prefix")
    s.add_argument("--overdue", action="store_true", help="past the remediation SLO")
    s.add_argument("--json", action="store_true")
    s.add_argument("--ids", action="store_true", help="only the ids")
    s = p("explain", cmd_explain, "explain one finding in plain language")
    s.add_argument("id")
    s = p("digest", cmd_digest, "print the short summary")
    s.add_argument("--daily", action="store_true")
    s.add_argument("--days", type=int, default=1)
    s = p("notify", cmd_notify, "send the summary to the configured notifiers")
    s.add_argument("--dry-run", action="store_true")
    s.add_argument("--days", type=int, default=1)
    a = ap.parse_args(argv)
    return a.fn(a) or 0


if __name__ == "__main__":
    sys.exit(main())
