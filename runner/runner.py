#!/usr/bin/env python3
"""runner: run an instance's jobs continuously (component `runner`, see runner/VERSION). Stdlib only.

    runner.py tick   --instance F --data DIR [--now EPOCH] [JOB ...]   run whatever is due (only these jobs), then exit
    runner.py run    --instance F --data DIR [JOB ...]                  run these jobs (all when none) now, ignoring the schedule
    runner.py status --instance F --data DIR                                  print the job states (JSON)
    runner.py metrics --instance F --data DIR                                 (re)publish the metrics to the sinks
    runner.py serve-metrics --dir D [--port 9851]                             HTTP /metrics from text files (exporter)

`tick` is meant to be called often (every 5-15 minutes) by ANY trigger: cron, launchd, Android JobScheduler, a
Kubernetes CronJob, systemd timers (deploy/ renders them). The schedule itself lives in the instance config, so the
trigger stays dumb and the same everywhere:

  runner:
    site: hub                       # label of this runner in the metrics (a role, not a device name)
    role: hub                       # hub: keeps the ledger and publishes metrics; site: only fills an outbox
    outbox: {type: local, dir: ...} # role site: where finished findings documents go (a spool adapter, or a list);
                                    # role hub: optional, a copy for another hub (parallel run, federation)
    state_outbox: {...}             # role site: where job states go (a spool or a list), for the hub's metrics
    forward:                        # store and forward, every tick, both roles: drain a LOCAL spool into a remote
      - {from: {type: local, dir: ...}, to: {type: kubernetes-secret, ...}}   # one; ack only what was delivered
    sinks: [ ... ]                  # role hub: metric sinks (adapters/sinks.py); a failing sink is retried every
                                    # tick and reported (security_runner_sink_*), it never fails the tick
    retention: 14d                  # optional: delete runs/<date>/ older than this (default: keep everything)
    tick_stale_after: 1h            # the trigger's heartbeat is overdue after this (alert SecurityRunnerStale); a
                                    # hub that sleeps at night (a laptop) sets e.g. 12h
    implementations:                # which implementation runs a component (docs/contracts.md): python (default),
      ledger: shadow                # go, or shadow (python writes, go runs on a copy, outputs diffed); ledger,
      remediation: python           # remediation
    go_binary: /usr/local/bin/sp    # optional: the Go `sp` binary (default: /usr/local/bin/sp, then `sp` on PATH)
    jobs:
      <name>:
        type: collector | command | ingest | digest | remediation | export | snapshot | push | pull-snapshot | events
              | notify                         (default collector; collector = job name unless `collector:`)
                                               remediation: core/remediation.py (owners, SLO due dates, tracker)
                                               export: core/export.py, the instance's `export:` ticket and SIEM
                                               sinks (`dry_run: true` plans only)
                                               notify: the short summary (`sp digest`, aggregates only) to the
                                               instance's `notify:` adapters (notifier/); `days:` default 1
                                               snapshot: commit the private data directory if it is a git
                                               repository (`paths:` default ledger.json, reports, exceptions.yaml,
                                               tracker); with `to: {kubernetes Secret}` publish a tar.gz of the same
                                               paths there instead (an in-cluster hub; pulled by pull-snapshot)
                                               pull-snapshot: `from: {kubernetes Secret}`, `into: <dir>`: extract the
                                               hub's snapshot into the data directory and commit it (off-cluster copy)
                                               push: `files: {exceptions: exceptions.yaml, ...}` send human-approved
                                               control files to the outbox when they change (the hub's ingest
                                               accepts them only from sites listed with `accept_control`)
                                               ingest: `source:` a spool; `site_state:` a dir on the source host or a
                                               spool; `accept_control: [exceptions, catalog-review, attestations]`
                                               events: `sources: [...]`, `loki: {url, token_file}`: ship security
                                               events (auth logs, code host / overlay network audit) to a log
                                               store with events/ship.py; cursors and baselines in
                                               <data>/state/events/<job>/; success = every source shipped
                                               command: `argv: [...]` any program that writes <collector>.findings.json
                                               into $SP_RUN_DIR (e.g. a wrapper around a third-party scanner)
        schedule: "30 3 * * *"                 cron, local time of the host (TZ)
        jitter: 20m                            deterministic per job and slot: spreads load, stays reproducible
        timeout: 2h                            the whole process group is killed after it
        retries: 2                             extra attempts per slot after a failure ...
        retry_delay: 20m                       ... at least this far apart
        max_delay: 3h                          optional: skip a slot older than this (e.g. keep a scan off-peak);
                                               default: a missed slot is caught up once (laptops sleep)
        env: {NAME: value}                     non-secret environment for the job
        as: <name>                             report under another collector name (SP_COLLECTOR_NAME): the same
                                               collector deployed twice with different scopes
Locking: one lock per job (no overlapping runs of the same job) and one ledger lock (merges are serialized).
"""
import argparse
import fcntl
import glob
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path[:0] = [HERE, ROOT, os.path.join(ROOT, "sdk"), os.path.join(ROOT, "core")]
import cron  # noqa: E402
from adapters import sinks, spool  # noqa: E402
from spsdk import load_config, render  # noqa: E402

VERSION = open(os.path.join(HERE, "VERSION")).read().strip()
# the product release this tree was installed as (RELEASE: written by bin/sp-install, or by the image build); "" in a checkout
try:
    with open(os.path.join(ROOT, "RELEASE")) as _f:
        RELEASE = dict(ln.strip().split("=", 1) for ln in _f if "=" in ln).get("version", "")
except OSError:
    RELEASE = ""
STATE_SCHEMA = "security-platform/runner-state/v1"
CONTROL_SCHEMA = "security-platform/control/v1"


def log(msg):
    print(f"{time.strftime('%Y-%m-%dT%H:%M:%S%z')} runner: {msg}", file=sys.stderr, flush=True)


class Runner:
    def __init__(self, instance_path, data):
        self.instance_path = os.path.abspath(os.path.expanduser(instance_path))
        self.inst = load_config(self.instance_path)
        self.cfg = self.inst.get("runner") or {}
        self.data = os.path.abspath(os.path.expanduser(data))
        self.site = self.cfg.get("site", "hub")
        self.role = self.cfg.get("role", "hub")
        self.state_dir = os.path.join(self.data, "state", "runner")
        self.latest = os.path.join(self.data, "latest")
        for d in (self.state_dir, os.path.join(self.state_dir, "locks"), self.latest):
            os.makedirs(d, exist_ok=True)
        self._once, self._probed = set(), {}
        impls = self.cfg.get("implementations") or {}
        if not isinstance(impls, dict):
            self.log_once("implementations", f"runner.implementations is not a mapping ({type(impls).__name__}): python everywhere")
            impls = {}
        for comp, v in impls.items():
            if comp not in COMPONENTS or v not in IMPLS:
                self.log_once(f"impl:{comp}", f"runner.implementations.{comp}: {v!r} ignored (components "
                                              f"{sorted(COMPONENTS)}, values {list(IMPLS)}): python")
        self.impls = {c: v for c, v in impls.items() if c in COMPONENTS and v in IMPLS}
        self.jobs = {}
        for name, j in (self.cfg.get("jobs") or {}).items():
            j = dict(j or {})
            j.setdefault("type", "collector")
            if j["type"] in ("collector", "command"):
                j.setdefault("collector", name)
            j["_cron"] = cron.Cron(j["schedule"])
            self.jobs[name] = j

    # ---- state ------------------------------------------------------------------------------------------
    def state_path(self, job):
        return os.path.join(self.state_dir, f"{job}.json")

    def load_state(self, job):
        try:
            return json.load(open(self.state_path(job)))
        except (OSError, ValueError):
            return {"schema": STATE_SCHEMA, "job": job, "runs_total": 0, "failures_total": 0}

    def save_state(self, job, st):
        p = self.state_path(job)
        with open(p + ".tmp", "w") as f:
            json.dump(st, f, indent=1, sort_keys=True)
        os.replace(p + ".tmp", p)

    # ---- scheduling -------------------------------------------------------------------------------------
    @staticmethod
    def offset(job, slot, jitter):
        if jitter <= 0:
            return 0
        return int(hashlib.sha1(f"{job}|{slot}".encode()).hexdigest()[:8], 16) % jitter

    def due(self, name, now):
        """-> (slot, reason) when the job should run now, else (None, reason)."""
        j, st = self.jobs[name], self.load_state(name)
        c = j["_cron"]
        jitter = cron.parse_duration(j.get("jitter"))
        slot = c.prev(now)
        if slot is None:
            return None, "no slot"
        if now < slot + self.offset(name, slot, jitter):     # this slot's jittered start is still ahead
            slot = c.prev(slot - 60)
            if slot is None:
                return None, "no slot"
        if st.get("done_slot", -1) >= slot:
            return None, "done"
        max_delay = cron.parse_duration(j.get("max_delay"))
        if max_delay and now - slot > max_delay:
            return None, "missed (older than max_delay)"
        if st.get("slot") == slot:                           # attempted this slot already and failed
            if st.get("attempts", 0) > int(j.get("retries", 0)):
                return None, "retries exhausted"
            if now < st.get("last_attempt", 0) + cron.parse_duration(j.get("retry_delay", "15m")):
                return None, "waiting to retry"
            return slot, f"retry {st.get('attempts')}"
        return slot, "due"

    # ---- locking ----------------------------------------------------------------------------------------
    def lock(self, name, blocking=False):
        f = open(os.path.join(self.state_dir, "locks", f"{name}.lock"), "w")
        try:
            fcntl.flock(f, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        except BlockingIOError:
            f.close()
            return None
        return f

    # ---- execution --------------------------------------------------------------------------------------
    def env(self, j, run_dir):
        e = dict(os.environ, SP_INSTANCE=self.instance_path, SP_DATA=self.data, SP_RUN_DIR=run_dir,
                 SP_INPUT_DIR=self.latest, SP_INSTANCE_NAME=str(self.inst.get("name", "")))
        e.update({k: str(v) for k, v in (j.get("env") or {}).items()})
        if j.get("as"):
            e["SP_COLLECTOR_NAME"] = j["as"]
        return e

    def spawn(self, argv, env, timeout, logf):
        with open(logf, "a") as lf:
            p = subprocess.Popen(argv, env=env, stdout=lf, stderr=lf, start_new_session=True)
            try:
                return p.wait(timeout=timeout or None)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, signal.SIGTERM)
                try:
                    p.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    os.killpg(p.pid, signal.SIGKILL)
                    p.wait()
                lf.write(f"\nrunner: killed after timeout {timeout}s\n")
                return 124

    def run_dir(self, name):
        d = os.path.join(self.data, "runs", time.strftime("%Y-%m-%d"), f"{time.strftime('%H%M%S')}-{name}")
        os.makedirs(d, exist_ok=True)
        return d

    def job_command(self, name, j, run_dir):
        return self.job_collector(name, j, run_dir, argv=[os.path.expanduser(x) for x in j["argv"]])

    def job_collector(self, name, j, run_dir, argv=None):
        col = j.get("as") or j["collector"]
        argv = argv or [sys.executable, os.path.join(ROOT, "collectors", j["collector"], "collector.py")]
        rc = self.spawn(argv, self.env(j, run_dir), cron.parse_duration(j.get("timeout", "1h")),
                        os.path.join(run_dir, f"{col}.log"))
        doc = os.path.join(run_dir, f"{col}.findings.json")
        if rc != 0 or not os.path.exists(doc):
            return rc or 1, f"collector exited rc={rc}, document={'yes' if os.path.exists(doc) else 'no'}"
        import validate
        errs = validate.validate_findings(json.load(open(doc)))
        if errs:
            return 65, f"contract violation: {errs[:3]}"
        self.promote(run_dir)
        if self.role == "site":
            self.to_outbox(run_dir, name)
            return 0, "document to outbox"
        if self.cfg.get("outbox"):           # a hub that also feeds another hub (parallel run, federation)
            try:
                self.to_outbox(run_dir, name)
            except Exception as e:  # noqa: BLE001 - the local ledger is this hub's job; the copy is best effort
                log(f"{name}: copy to outbox: {type(e).__name__}: {str(e)[:160]}")
        return self.ledger(run_dir)

    def promote(self, run_dir):
        """latest/ = the newest valid outputs of every collector (consumers read contracts from here). The generic
        per-collector metrics are (re)derived from the document itself, so any program honouring the contract works."""
        from spsdk import to_prom
        for p in glob.glob(os.path.join(run_dir, "*.findings.json")):
            col = os.path.basename(p)[:-len(".findings.json")]
            prom = os.path.join(run_dir, f"{col}.prom")
            if not os.path.exists(prom):
                with open(prom, "w") as f:
                    f.write(to_prom(json.load(open(p))))
        for p in glob.glob(os.path.join(run_dir, "*.findings.json")) + glob.glob(os.path.join(run_dir, "inventory.*.json")) \
                + glob.glob(os.path.join(run_dir, "*.prom")):
            if os.path.basename(p) in ("sli.prom", "all.prom"):
                continue
            shutil.copy2(p, os.path.join(self.latest, os.path.basename(p) + ".tmp"))
            os.replace(os.path.join(self.latest, os.path.basename(p) + ".tmp"), os.path.join(self.latest, os.path.basename(p)))

    @staticmethod
    def spools(cfg):
        return [spool.spool(c) for c in (cfg if isinstance(cfg, list) else [cfg] if cfg else [])]

    def to_outbox(self, run_dir, name):
        stamp = time.strftime("%Y%m%dT%H%M%S")
        for sp in self.spools(self.cfg.get("outbox")):
            for p in sorted(glob.glob(os.path.join(run_dir, "inventory.*.json")) + glob.glob(os.path.join(run_dir, "*.findings.json"))):
                sp.put(f"{stamp}-{name}.{os.path.basename(p)}", open(p).read())

    def prune(self, now):
        keep = cron.parse_duration(self.cfg.get("retention"))
        if not keep:
            return
        cutoff = time.strftime("%Y-%m-%d", time.localtime(now - keep))
        for d in glob.glob(os.path.join(self.data, "runs", "????-??-??")):
            if os.path.basename(d) < cutoff:
                shutil.rmtree(d, ignore_errors=True)

    def forward(self):
        """Store and forward: deliver what local spools hold to remote ones; a failure keeps the documents queued
        for the next tick. Each forward reports like a job (state forward-<i>), so a stuck queue is visible."""
        for i, f in enumerate(self.cfg.get("forward") or []):
            name, st, t0 = f"forward-{i}", None, time.time()
            st = self.load_state(name)
            st.update(last_attempt=int(t0), runs_total=st.get("runs_total", 0) + 1)
            sent, err = 0, ""
            try:
                src, dst = spool.spool(f["from"]), spool.spool(f["to"])
                for n in src.list():
                    dst.put(n, src.get(n))
                    src.ack(n)
                    sent += 1
                st["pending"] = len(src.list())
            except Exception as e:  # noqa: BLE001 - offline, remote down: retried next tick
                err = f"{type(e).__name__}: {str(e)[:200]}"
            st.update(last_rc=0 if not err else 75, last_duration=round(time.time() - t0, 1), runner_version=VERSION,
                      last_note=err or f"delivered {sent}")
            if err:
                st["failures_total"] = st.get("failures_total", 0) + 1
                log(f"{name}: {err} (delivered {sent}; the rest stays queued, retried next tick)")
            else:
                st["last_success"] = int(time.time())
                if sent:
                    log(f"{name}: delivered {sent}")
            self.save_state(name, st)
            self.send_state(name, st)

    def ledger(self, run_dir):
        lk = self.lock("ledger", blocking=True)
        try:
            return self.component("ledger", {"run_dir": run_dir, "data": self.data, "latest": self.latest,
                                             "instance": self.instance_path})
        finally:
            lk.close()

    def exec_ledger(self, argv, a):
        p = subprocess.run(argv, capture_output=True, text=True, timeout=600)
        with open(os.path.join(a["run_dir"], "ledger.log"), "w") as f:
            f.write(p.stdout + p.stderr)
        return (0, "ledger merged") if p.returncode == 0 else (p.returncode, f"ledger rc={p.returncode}: {p.stderr.strip()[-200:]}")

    def job_ingest(self, name, j, run_dir):
        """Pull a site's outbox into the ledger (and publish an asset list to it, if configured)."""
        src = spool.spool(j["source"])
        notes = []
        if j.get("publish_assets"):
            from adapters import discovery
            devices = []
            for dcfg in j["publish_assets"].get("discovery", []):
                devices += discovery.discover(dcfg)
            devices = discovery.apply_scope(devices, self.inst.get("scope"))   # sites with older code honour it too
            src_pub = spool.spool(dict(j["source"], dir=j["publish_assets"]["dir"]))
            src_pub.put(j["publish_assets"].get("name", "assets.json"), json.dumps(devices))
            notes.append(f"published {len(devices)} assets")
        if j.get("site_state"):
            ss = j["site_state"]
            st_sp = spool.spool(ss if isinstance(ss, dict) else dict(j["source"], dir=ss))
            sp_path = os.path.join(self.data, "state", "sites", f"{j.get('site', name)}.json")
            try:
                states = json.load(open(sp_path)).get("jobs") or {}
            except (OSError, ValueError):
                states = {}
            for n in st_sp.list():
                try:
                    states[n[:-5]] = json.loads(st_sp.get(n))
                    if isinstance(ss, dict):       # a queue (one document per send): keep the newest, drop the rest
                        st_sp.ack(n)
                except ValueError:
                    pass
            os.makedirs(os.path.dirname(sp_path), exist_ok=True)
            with open(sp_path + ".tmp", "w") as f:
                json.dump({"site": j.get("site", name), "fetched_at": int(time.time()), "jobs": states}, f, indent=1)
            os.replace(sp_path + ".tmp", sp_path)
        names = src.list()
        for n in [x for x in names if x.endswith(".control.json")]:
            notes.append(self.accept_control(j, src, n))
            src.ack(n)
        docs = [n for n in names if n.endswith(".findings.json")]
        invs = [n for n in names if ".inventory." in n]
        for n in invs:   # inventories first: consumers read them from latest/
            open(os.path.join(run_dir, n.split(".", 1)[1]), "w").write(src.get(n))
        if invs:
            self.promote(run_dir)
            for n in invs:
                src.ack(n)
        import validate
        rc_all = 0
        for n in docs:   # oldest first: the ledger sees the site's history in order
            d = os.path.join(run_dir, n.rsplit(".findings.json", 1)[0].replace(".", "_"))
            os.makedirs(d, exist_ok=True)
            text = src.get(n)
            doc = json.loads(text)
            errs = validate.validate_findings(doc)
            col = doc.get("collector", {}).get("name", "unknown")
            if errs:
                notes.append(f"{n}: contract violation, kept in the outbox")
                rc_all = 65
                continue
            with open(os.path.join(d, f"{col}.findings.json"), "w") as f:
                f.write(text)
            # the site's per-collector metrics are regenerated from the document (heartbeat = its finished_at)
            from spsdk import to_prom
            with open(os.path.join(d, f"{col}.prom"), "w") as f:
                f.write(to_prom(doc))
            self.promote(d)
            rc, note = self.ledger(d)
            if rc != 0:
                return rc, note
            src.ack(n)
            notes.append(f"ingested {n}")
        return rc_all, "; ".join(notes) or "outbox empty"

    CONTROL = {"exceptions": "exceptions.yaml", "catalog-review": "catalog-review.yaml", "attestations": "attestations.yaml"}

    def accept_control(self, j, src, n):
        """A human-approved control file (exceptions, catalog review) sent by a trusted site: replaces the hub's copy.
        Accepted only if this ingest job lists the kind in `accept_control` (the site label itself is enforced by the
        inbox's admission policy). JSON is YAML, so the hub's readers need nothing new."""
        try:
            doc = json.loads(src.get(n))
        except ValueError:
            return f"{n}: not JSON, dropped"
        kind = doc.get("kind")
        if doc.get("schema") != CONTROL_SCHEMA or kind not in self.CONTROL or not isinstance(doc.get("content"), dict):
            return f"{n}: not a {CONTROL_SCHEMA} document, dropped"
        if kind not in (j.get("accept_control") or []):
            return f"{n}: {kind} not accepted from site {j.get('site')}, dropped"
        p = os.path.join(self.data, self.CONTROL[kind])
        with open(p + ".tmp", "w") as f:
            f.write(f"# {kind}: received from site {j.get('site')} at {time.strftime('%Y-%m-%dT%H:%M:%S%z')} "
                    f"(sent {doc.get('sent_at')}); the source of truth is the site's copy\n")
            json.dump(doc["content"], f, indent=1, sort_keys=True)
        os.replace(p + ".tmp", p)
        return f"{kind} updated"

    def job_push(self, name, j, run_dir):
        """Send control files to the outbox when their content changed (or `every` run with force: true)."""
        st, sent = self.load_state(name), []
        hashes = dict(st.get("pushed") or {})
        for kind, rel in (j.get("files") or {}).items():
            if kind not in self.CONTROL:
                return 64, f"unknown control kind {kind!r} (known: {sorted(self.CONTROL)})"
            p = os.path.join(self.data, os.path.expanduser(rel))
            content = load_config(p) if os.path.exists(p) else {}
            h = hashlib.sha256(json.dumps(content, sort_keys=True, default=str).encode()).hexdigest()
            if hashes.get(kind) == h and not j.get("force"):
                continue
            doc = {"schema": CONTROL_SCHEMA, "kind": kind, "sent_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                   "content": json.loads(json.dumps(content, default=str))}
            for sp in self.spools(self.cfg.get("outbox")):
                sp.put(f"{time.strftime('%Y%m%dT%H%M%S')}-{name}.{kind}.control.json", json.dumps(doc))
            hashes[kind] = h
            sent.append(kind)
        st = self.load_state(name)
        st["pushed"] = hashes
        self.save_state(name, st)
        return 0, ("sent " + ", ".join(sent)) if sent else "unchanged"

    def job_events(self, name, j, run_dir):
        """Security events -> log store (events/ship.py). Not a findings document: success = exit 0 (every source
        collected and pushed); a failing source keeps its cursor and is retried on the next slot."""
        cfg = {"loki": j["loki"], "sources": j.get("sources") or []}
        cf = os.path.join(run_dir, "events.config.json")
        with open(cf, "w") as f:
            json.dump(cfg, f, indent=1)
        summary = os.path.join(run_dir, "events.summary.json")
        rc = self.spawn([sys.executable, os.path.join(ROOT, "events", "ship.py"), "--config", cf,
                         "--state", os.path.join(self.data, "state", "events", name), "--summary", summary],
                        self.env(j, run_dir), cron.parse_duration(j.get("timeout", "10m")), os.path.join(run_dir, "events.log"))
        try:
            srcs = json.load(open(summary))["sources"]
            note = ", ".join(f"{k}: {v['shipped']}" if v.get("ok") else f"{k}: FAILED" for k, v in sorted(srcs.items()))
        except (OSError, ValueError, KeyError):
            note = "no summary"
        return rc, f"events {note}" if rc == 0 else f"events rc={rc} ({note}; see events.log)"

    def job_digest(self, name, j, run_dir):
        return self.spawn([sys.executable, os.path.join(ROOT, "core", "digest.py"), "--data", self.data] +
                          (["--days", str(j["days"])] if j.get("days") else []),
                          self.env(j, run_dir), cron.parse_duration(j.get("timeout", "10m")),
                          os.path.join(run_dir, "digest.log")), "digest written"

    def job_notify(self, name, j, run_dir):
        """The short summary (cli/sp.py digest: aggregates only) to the instance's notifiers (notifier/)."""
        rc = self.spawn([sys.executable, os.path.join(ROOT, "cli", "sp.py"), "notify", "--data", self.data,
                         "--instance", self.instance_path, "--days", str(j.get("days", 1))], self.env(j, run_dir),
                        cron.parse_duration(j.get("timeout", "5m")), os.path.join(run_dir, "notify.log"))
        return rc, "summary sent" if rc == 0 else f"notify rc={rc} (see notify.log)"

    def job_remediation(self, name, j, run_dir):
        return self.component("remediation", {"run_dir": run_dir, "data": self.data, "instance": self.instance_path, "job": j})

    def exec_remediation(self, argv, a):
        rc = self.spawn(argv, self.env(a["job"], a["run_dir"]), cron.parse_duration(a["job"].get("timeout", "10m")),
                        os.path.join(a["run_dir"], "remediation.log"))
        return rc, "tracker synced" if rc == 0 else f"remediation rc={rc} (see remediation.log)"

    # ---- implementation switch: python | go | shadow per component (docs/contracts.md) -------------------
    def log_once(self, key, msg):
        if key not in self._once:
            self._once.add(key)
            log(msg)

    def go_binary(self, comp):
        """The Go `sp` binary that implements this component's subcommand, or None. A candidate must PROVE it is the Go
        binary (`version --json`, schema version/v1, the subcommand in go_subcommands): the tree's bin/sp is the
        Python CLI and an unrelated `sp` on PATH must never be run as the ledger. Probed once per process."""
        sub = COMPONENTS[comp]["subcommand"]
        cands = [os.path.expanduser(str(self.cfg["go_binary"]))] if self.cfg.get("go_binary") else \
            list(GO_CANDIDATES) + [shutil.which("sp")]
        for c in cands:
            if not c:
                continue
            if c not in self._probed:
                self._probed[c] = probe_go(c)
            if sub in self._probed[c]:
                return c
        return None

    def component(self, comp, a):
        """Run a component (spec COMPONENTS[comp]) with the implementation the instance selects; returns (rc, note).
        go without a Go binary falls back to python (logged once). shadow: python writes, go runs on a copy."""
        spec, mode = COMPONENTS[comp], self.impls.get(comp, "python")
        run = getattr(self, spec["exec"])
        if mode == "python":
            return run(spec["python"](a), a)
        binp = self.go_binary(comp)
        if binp is None:
            self.log_once(f"nogo:{comp}", f"implementation {mode} requested for {comp} but no Go sp binary with "
                                          f"`{spec['subcommand']}` was found; using python" +
                                          (" (no shadow comparison)" if mode == "shadow" else ""))
            if mode == "shadow":
                self.save_shadow(comp, a, {"go_available": False})
            return run(spec["python"](a), a)
        if mode == "go":
            return run([binp] + spec["go"](a), a)
        return self.shadow(comp, spec, a, binp, run)

    def shadow(self, comp, spec, a, binp, run):
        tmp = tempfile.mkdtemp(prefix=f"sp-shadow-{comp}-")
        try:
            try:
                ga = shadow_copy(spec, a, os.path.join(tmp, "go"))   # BEFORE python runs: same inputs on both sides
                gr = [shadow_copy(spec, a, os.path.join(tmp, f"ref{i}")) for i in range(len(spec.get("reference", ())))]
            except Exception as e:  # noqa: BLE001 - the shadow never decides the job's result
                log(f"shadow {comp}: copying the inputs: {type(e).__name__}: {str(e)[:200]}")
                ga, gr = None, []
            now = int(time.time())
            if spec.get("python_now"):
                a = dict(a, now=now)
            rc, note = run(spec["python"](a), a)        # the source of truth, exactly as without shadow
            if ga is not None:
                try:
                    self.compare(comp, spec, a, dict(ga, now=now, shadow=True), binp, rc,
                                 [dict(g, now=now, shadow=True) for g in gr])
                except Exception as e:  # noqa: BLE001
                    log(f"shadow {comp}: {type(e).__name__}: {str(e)[:200]}")
            return rc, note
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def go_diffs(self, spec, a, g, binp, py_rc, extra=()):
        """Run the Go implementation on the copy g; its exit status, output and differences from the python side."""
        env = dict(os.environ, SP_DATA=g["data"], SP_RUN_DIR=g["run_dir"])   # never the real directories
        try:
            p = subprocess.run([binp] + spec["go"](g) + list(extra), capture_output=True, text=True, env=env,
                               timeout=spec["timeout"](a))
            go_rc, out = p.returncode, p.stdout + p.stderr
        except subprocess.TimeoutExpired:
            go_rc, out = 124, "timeout"
        diffs = [] if go_rc == py_rc else [{"file": "exit status", "path": "", "python": py_rc, "go": go_rc}]
        for label, base, rel, kind in spec["outputs"](self, a):
            diffs += diff_output(label, kind, [os.path.join(x[base], rel) for x in (a, g)], spec)
        return go_rc, out, diffs

    def compare(self, comp, spec, a, ga, binp, py_rc, gr=()):
        go_rc, out, diffs = self.go_diffs(spec, a, ga, binp, py_rc)
        with open(os.path.join(a["run_dir"], f"shadow-{comp}.log"), "w") as f:
            f.write(out)
        # attribution: the same Go program with known deviations switched back to the reference behaviour
        # (--reference-behaviour), one run per entry of spec["reference"]. A difference that disappears in such a run
        # IS that deviation's target behaviour; one that stays in all of them is unexplained.
        refs = [({(d["file"], d["path"]) for d in self.go_diffs(spec, a, g, binp, py_rc, args)[2]}, reason)
                for g, (args, reason) in zip(gr, spec.get("reference", ()))]
        failed = self.reference_failure(spec, a, py_rc)
        for d in diffs:
            why = [r for f, pat, side, r in spec.get("explained", ()) if f == d["file"] and re.match(pat, d["path"])
                   and d[side] == ABSENT]
            if failed:
                d["explained"] = failed
            elif why:
                d["explained"] = why[0]
            else:
                d["explained"] = next((r for keys, r in refs if (d["file"], d["path"]) not in keys), None)
                if d["explained"] is None:
                    del d["explained"]
        n_exp = sum(1 for d in diffs if d.get("explained"))
        by = {}
        for d in diffs:
            if d.get("explained"):
                by[d["explained"]] = by.get(d["explained"], 0) + 1
        rep = {"schema": SHADOW_SCHEMA, "at": int(time.time()), "component": comp, "go_binary": binp, "go_available": True,
               "python_rc": py_rc, "go_rc": go_rc, "unexplained": len(diffs) - n_exp, "explained": n_exp, "explained_by": by,
               "differences": diffs[:SHADOW_MAX_DIFFS], "truncated": len(diffs) > SHADOW_MAX_DIFFS}
        with open(os.path.join(a["run_dir"], f"shadow-{comp}.json"), "w") as f:
            json.dump(rep, f, indent=1, sort_keys=True, ensure_ascii=False)
        self.save_shadow(comp, a, {k: v for k, v in rep.items() if k not in ("differences", "truncated")})
        if rep["unexplained"]:
            log(f"shadow {comp}: {rep['unexplained']} unexplained difference(s), {n_exp} explained "
                f"(see {os.path.relpath(os.path.join(a['run_dir'], f'shadow-{comp}.json'), self.data)})")

    @staticmethod
    def reference_failure(spec, a, py_rc):
        """The known deviation that made the reference fail (e.g. LEDGER-D1: a finding without `kind`), from its log;
        every difference of such a run follows from it. None when python succeeded or failed for another reason."""
        if py_rc == 0 or not spec.get("python_failures"):
            return None
        text = _read(spec["python_log"](a))
        return next((r for pat, r in spec["python_failures"] if re.search(pat, text)), None)

    def save_shadow(self, comp, a, summary):
        d = os.path.join(self.state_dir, "shadow")
        os.makedirs(d, exist_ok=True)
        summary = dict(summary, component=comp, at=summary.get("at", int(time.time())),
                       run_dir=os.path.relpath(a["run_dir"], self.data))
        with open(os.path.join(d, f"{comp}.json.tmp"), "w") as f:
            json.dump(summary, f, indent=1, sort_keys=True)
        os.replace(os.path.join(d, f"{comp}.json.tmp"), os.path.join(d, f"{comp}.json"))

    def shadow_series(self):
        s = []
        for p in sorted(glob.glob(os.path.join(self.state_dir, "shadow", "*.json"))):
            try:
                st = json.load(open(p))
            except ValueError:
                continue
            if not st.get("go_available"):
                continue      # nothing compared: the comparison heartbeat goes stale, which is what should show
            lab = {"site": self.site, "component": st["component"]}
            s += [("security_impl_shadow_diffs", lab, st.get("unexplained", 0),
                   "Unexplained differences between the Python and the Go implementation (last shadow comparison)"),
                  ("security_impl_shadow_explained_diffs", lab, st.get("explained", 0),
                   "Differences explained by a known deviation's target behaviour (last shadow comparison)"),
                  ("security_impl_shadow_last_run_timestamp_seconds", lab, st["at"], "When the last shadow comparison ran")]
        return s

    def job_export(self, name, j, run_dir):
        """Ledger -> the team's issue tracker and SIEM (core/export.py, instance `export:`)."""
        rc = self.spawn([sys.executable, os.path.join(ROOT, "core", "export.py"), "--data", self.data,
                         "--instance", self.instance_path] + (["--dry-run"] if j.get("dry_run") else []),
                        self.env(j, run_dir), cron.parse_duration(j.get("timeout", "15m")),
                        os.path.join(run_dir, "export.log"))
        return rc, "exported" if rc == 0 else f"export rc={rc} (see export.log)"

    SNAPSHOT_PATHS = ["ledger.json", "reports", "exceptions.yaml", "catalog-review.yaml", "tracker", "attestations.yaml"]

    def job_snapshot(self, name, j, run_dir):
        """Audit trail of the ledger: a local commit (never pushed by the runner), or (`to:`) a tar.gz in a private
        Kubernetes Secret of the hub's own namespace that the operator's site pulls off the cluster (pull-snapshot)."""
        paths = j.get("paths") or self.SNAPSHOT_PATHS
        if j.get("to"):
            import snapshot
            blob = snapshot.pack(self.data, paths, site=self.site)
            snapshot.put_secret(j["to"], blob)
            return 0, f"snapshot published ({len(blob)} bytes gzip)"
        return self.git_commit(paths, j.get("message", "ledger snapshot (runner)"))

    def job_pull_snapshot(self, name, j, run_dir):
        import snapshot
        into = os.path.join(self.data, j["into"])
        manifest = snapshot.unpack(snapshot.get_secret(j["from"]), into)
        st = self.load_state(name)
        if manifest.get("created_at") == st.get("last_snapshot"):
            return 0, "no new snapshot"
        st["last_snapshot"] = manifest.get("created_at")
        self.save_state(name, st)
        rc, note = self.git_commit([j["into"]], j.get("message", f"hub snapshot {manifest.get('site')} {manifest.get('created_at')}"))
        return rc, f"snapshot of {manifest.get('created_at')} from {manifest.get('site')}: {note}"

    def git_commit(self, paths, message):
        g = ["git", "-C", self.data]
        if subprocess.run(g + ["rev-parse", "--git-dir"], capture_output=True).returncode != 0:
            return 0, "data directory is not a git repository: nothing to do"
        subprocess.run(g + ["add", "--"] + [p for p in paths if os.path.exists(os.path.join(self.data, p))], check=True,
                       capture_output=True)
        if subprocess.run(g + ["diff", "--cached", "--quiet"]).returncode == 0:
            return 0, "no changes"
        p = subprocess.run(g + ["commit", "-q", "-m", message], capture_output=True, text=True)
        return p.returncode, "committed" if p.returncode == 0 else p.stderr.strip()[-200:]

    def execute(self, name, slot=None):
        j = self.jobs[name]
        lk = self.lock(name)
        if lk is None:
            log(f"{name}: already running (lock held), skipped")
            return None
        try:
            st = self.load_state(name)
            start = time.time()
            if slot is not None:
                if st.get("slot") != slot:
                    st.update(slot=slot, attempts=0)
                st["attempts"] = st.get("attempts", 0) + 1
            st["last_attempt"] = int(start)
            self.save_state(name, st)
            run_dir = self.run_dir(name)
            log(f"{name}: start ({j['type']}) -> {os.path.relpath(run_dir, self.data)}")
            try:
                rc, note = getattr(self, "job_" + j["type"].replace("-", "_"))(name, j, run_dir)
            except Exception as e:  # noqa: BLE001 - a broken job must not stop the others
                rc, note = 70, f"{type(e).__name__}: {str(e)[:200]}"
            dur = time.time() - start
            st = self.load_state(name)
            st.update(last_rc=rc, last_duration=round(dur, 1), last_note=note[:500], runs_total=st.get("runs_total", 0) + 1,
                      last_run_dir=os.path.relpath(run_dir, self.data), runner_version=VERSION)
            if rc == 0:
                st["last_success"] = int(time.time())
                if slot is not None:
                    st["done_slot"] = slot
            else:
                st["failures_total"] = st.get("failures_total", 0) + 1
                if slot is not None and st.get("attempts", 0) > int(j.get("retries", 0)):
                    st["done_slot"] = slot      # give up on this slot; the next slot tries again
            self.save_state(name, st)
            log(f"{name}: rc={rc} in {dur:.0f}s: {note[:200]}")
            self.send_state(name, st)
            return rc
        finally:
            lk.close()

    def send_state(self, name, st):
        for sp in self.spools(self.cfg.get("state_outbox")):
            try:
                sp.put(f"{name}.json", json.dumps(self.public_state(name, st)))
            except Exception as e:  # noqa: BLE001 - the hub then sees a stale state; the job result stands
                log(f"{name}: state outbox: {type(e).__name__}: {str(e)[:160]}")

    @staticmethod
    def public_state(name, st):
        keep = ("last_success", "last_attempt", "last_rc", "last_duration", "runs_total", "failures_total", "runner_version")
        return {k: st.get(k) for k in keep}

    # ---- metrics ----------------------------------------------------------------------------------------
    def runner_series(self, now):
        s = [("security_runner_tick_timestamp_seconds", {"site": self.site}, int(now),
              "Heartbeat of the trigger: when the runner last ticked"),
             ("security_runner_tick_max_gap_seconds", {"site": self.site},
              cron.parse_duration(self.cfg.get("tick_stale_after", "1h")),
              "The tick heartbeat is overdue after this many seconds (broken trigger, environment or host)")]
        for key, st in sorted(self.sink_state().items()):
            lab = {"site": self.site, "sink": key}
            if st.get("last_success"):
                s.append(("security_runner_sink_last_success_timestamp_seconds", lab, st["last_success"],
                          "When the sink last accepted the metrics"))
            s.append(("security_runner_sink_failures_total", lab, st.get("failures_total", 0), "Failed deliveries (counter)"))
            s.append(("security_runner_sink_consecutive_failures", lab, st.get("consecutive_failures", 0),
                      "Deliveries failed in a row (0 = the last one worked); retried every tick"))
        rows = [(self.site, name, self.load_state(name), j) for name, j in self.jobs.items()]
        rows += [(self.site, f"forward-{i}", self.load_state(f"forward-{i}"), None) for i in range(len(self.cfg.get("forward") or []))]
        for sf in glob.glob(os.path.join(self.data, "state", "sites", "*.json")):
            try:
                site = json.load(open(sf))
            except ValueError:
                continue
            for name, st in (site.get("jobs") or {}).items():
                rows.append((site["site"], name, st, None))
        for site, name, st, j in rows:
            lab = {"site": site, "job": name}
            if st.get("last_success"):
                s.append(("security_runner_job_last_success_timestamp_seconds", lab, st["last_success"], "When the job last succeeded"))
            if st.get("last_attempt"):
                s.append(("security_runner_job_last_attempt_timestamp_seconds", lab, st["last_attempt"], "When the job last started"))
            if st.get("last_duration") is not None:
                s.append(("security_runner_job_duration_seconds", lab, float(st["last_duration"]), "Duration of the last run"))
            if st.get("last_rc") is not None:
                s.append(("security_runner_job_last_exit_code", lab, st["last_rc"], "Exit code of the last run (0 = ok)"))
            s.append(("security_runner_job_runs_total", lab, st.get("runs_total", 0), "Runs (counter)"))
            s.append(("security_runner_job_failures_total", lab, st.get("failures_total", 0), "Failed runs (counter)"))
            if j is not None:
                s.append(("security_runner_job_expected_interval_seconds", lab, j["_cron"].interval(now),
                          "Seconds between scheduled runs (staleness thresholds derive from it)"))
        # expected interval per collector, wherever it runs (sites declare theirs in the hub's ingest job)
        for name, j in self.jobs.items():
            if j["type"] in ("collector", "command"):
                s.append(("security_collector_expected_interval_seconds", {"collector": j.get("as") or j["collector"]}, j["_cron"].interval(now),
                          "Seconds between scheduled runs of the collector"))
            for col, sched in (j.get("site_collectors") or {}).items():
                s.append(("security_collector_expected_interval_seconds", {"collector": col}, cron.Cron(sched).interval(now),
                          "Seconds between scheduled runs of the collector"))
        s += self.shadow_series()
        s.append(("security_runner_info", {"site": self.site, "version": VERSION, "release": RELEASE}, 1,
                  "Runner version and the product release it was installed as"))
        return s

    def metrics_text(self, now):
        parts = []
        for p in sorted(glob.glob(os.path.join(self.latest, "*.prom"))):
            parts.append(open(p).read())
        for lp in (os.path.join(self.data, "metrics", f) for f in ("ledger.prom", "remediation.prom", "export.prom", "scorecard.prom")):
            if os.path.exists(lp):
                parts.append(open(lp).read())
        parts.append(render(self.runner_series(now)))
        parts.append(render([("security_metrics_published_timestamp_seconds", {"site": self.site}, int(now),
                              "When the hub last published these metrics")]))
        return merge_families("".join(parts))

    def scorecard(self, now):
        """Recompute the scorecard on every publish (attestations expire by the clock, not by runs). Off with
        `scorecard: {enabled: false}` in the instance. A failure is logged; the previous scorecard.prom stays."""
        if (self.inst.get("scorecard") or {}).get("enabled") is False:
            return
        p = subprocess.run([sys.executable, os.path.join(ROOT, "scorecard", "scorecard.py"), "compute", "--data", self.data,
                            "--instance", self.instance_path, "--now", str(int(now))],
                           capture_output=True, text=True, timeout=300)
        if p.returncode != 0:
            log(f"scorecard: rc={p.returncode}: {p.stderr.strip()[-300:]}")

    def sink_state(self):
        try:
            return json.load(open(os.path.join(self.state_dir, "sinks.json")))
        except (OSError, ValueError):
            return {}

    def publish(self, now):
        """Hand the metrics to every sink. A failing sink (cluster unreachable, namespace not created yet, offline
        host) is logged, counted and retried on the next tick; it never fails the tick or blocks the other sinks."""
        if self.role != "hub":
            return
        self.scorecard(now)
        text = self.metrics_text(now)
        local = {"path": os.path.join(self.data, "metrics", "security-platform.prom")}
        sinks.textfile(local, text)
        states = self.sink_state()
        for i, s in enumerate(self.cfg.get("sinks") or []):
            key = f"{i}-{s.get('type')}"
            st = states.setdefault(key, {"failures_total": 0, "consecutive_failures": 0})
            st["last_attempt"] = int(time.time())
            try:
                sinks.publish(s, text)
                if st.get("consecutive_failures"):
                    log(f"sink {key}: delivered again after {st['consecutive_failures']} failed tick(s)")
                st.update(last_success=int(time.time()), consecutive_failures=0, last_error="")
            except Exception as e:  # noqa: BLE001 - one sink down must not block the others
                st["failures_total"] = st.get("failures_total", 0) + 1
                st["consecutive_failures"] = st.get("consecutive_failures", 0) + 1
                st["last_error"] = f"{type(e).__name__}: {str(e)[:200]}"
                log(f"sink {key}: {st['last_error']} (failed {st['consecutive_failures']}x in a row; retried next tick)")
        p = os.path.join(self.state_dir, "sinks.json")
        with open(p + ".tmp", "w") as f:
            json.dump(states, f, indent=1, sort_keys=True)
        os.replace(p + ".tmp", p)
        if self.cfg.get("sinks"):
            sinks.textfile(local, self.metrics_text(now))   # the local copy carries this tick's sink results


# ---- implementation switch ------------------------------------------------------------------------------------------
# One entry per component that has more than one implementation. Everything component-specific lives here, so a new
# component (scorecard, ...) is one more entry: argv of each implementation, how the runner executes it (log file,
# timeout, result note), what a shadow run copies, which outputs it compares and how they are normalized, and which
# differences are the TARGET behaviour of a known deviation (contracts/*/SPEC.md) rather than a defect.
IMPLS = ("python", "go", "shadow")
GO_CANDIDATES = ("/usr/local/bin/sp",)            # then `sp` on PATH
SHADOW_SCHEMA = "security-platform/shadow-diff/v1"
SHADOW_MAX_DIFFS = 200                             # stored per report; all of them are counted
ABSENT = "<absent>"
RUN = "{run}"                                      # in `inputs`: the run directory (copied without subdirectories)


def probe_go(path):
    """The Go subcommands of the binary at `path` ([] when it is not the Go sp binary or cannot run)."""
    try:
        p = subprocess.run([path, "version", "--json"], capture_output=True, text=True, timeout=10,
                           stdin=subprocess.DEVNULL)
        v = json.loads(p.stdout) if p.returncode == 0 else {}
    except (OSError, ValueError, subprocess.SubprocessError):
        return []
    if not isinstance(v, dict) or v.get("schema") != "security-platform/version/v1":
        return []
    return [x for x in v.get("go_subcommands") or [] if isinstance(x, str)]


def shadow_copy(spec, a, tmp):
    """Copy the component's inputs into tmp/data with the same layout (relative paths, e.g. ledger runs[].run_dir,
    stay equal) and return the arguments that point the Go implementation at the copy."""
    data = os.path.join(tmp, "data")
    os.makedirs(data)
    run = a["run_dir"]
    rel = os.path.relpath(run, a["data"])
    grun = os.path.join(data, rel) if not rel.startswith("..") else os.path.join(tmp, "run")
    for x in spec["inputs"]:
        src, dst = (run, grun) if x == RUN else (os.path.join(a["data"], x), os.path.join(data, x))
        if x == RUN:
            os.makedirs(dst, exist_ok=True)
            for f in os.listdir(src):
                if os.path.isfile(os.path.join(src, f)):
                    shutil.copy2(os.path.join(src, f), os.path.join(dst, f))
        elif os.path.isdir(src):
            shutil.copytree(src, dst, symlinks=True)
        elif os.path.exists(src):
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
    os.makedirs(grun, exist_ok=True)
    return dict(a, data=data, run_dir=grun, latest=os.path.join(data, "latest"))


def _show(v):
    return v if v == ABSENT else json.dumps(v, sort_keys=True, ensure_ascii=False)[:200]


def jdiff(p, g, path, out, file):
    """Path-level differences of two JSON values (numbers compare by value: 14 == 14.0)."""
    if isinstance(p, dict) and isinstance(g, dict):
        for k in sorted(set(p) | set(g), key=str):
            jdiff(p.get(k, ABSENT), g.get(k, ABSENT), f"{path}.{k}" if path else str(k), out, file)
    elif isinstance(p, list) and isinstance(g, list):
        for i in range(max(len(p), len(g))):
            jdiff(p[i] if i < len(p) else ABSENT, g[i] if i < len(g) else ABSENT, f"{path}[{i}]", out, file)
    elif p != g or (type(p) is bool) != (type(g) is bool):   # True == 1 in Python, not in JSON
        out.append({"file": file, "path": path, "python": _show(p), "go": _show(g)})


def _read(path):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return ABSENT


def prom_samples(text, volatile):
    """{series: value} and the set of comment lines; samples of `volatile` families (heartbeats) are dropped."""
    samples, comments = {}, set()
    for ln in text.splitlines():
        if not ln.strip():
            continue
        if ln.startswith("#"):
            comments.add(ln)
            continue
        key, _, val = ln.rpartition(" ")
        if key.split("{", 1)[0] not in volatile:
            samples[key] = val
    return samples, comments


def diff_output(label, kind, paths, spec):
    """Differences of one output between the python (paths[0]) and the go (paths[1]) side."""
    out = []
    if kind == "text":                             # a glob: every matching file, by name
        names = sorted({os.path.basename(x) for p in paths for x in glob.glob(p)})
        for n in names:
            a, b = (_read(os.path.join(os.path.dirname(p), n)) for p in paths)
            if a != b:
                out.append({"file": f"{os.path.dirname(label)}/{n}".lstrip("/"), "path": "",
                            "python": "<present>" if a != ABSENT else ABSENT, "go": "<present>" if b != ABSENT else ABSENT})
        return out
    texts = [_read(p) for p in paths]
    if ABSENT in texts:
        if texts[0] != texts[1]:
            out.append({"file": label, "path": "", "python": "<present>" if texts[0] != ABSENT else ABSENT,
                        "go": "<present>" if texts[1] != ABSENT else ABSENT})
        return out
    if kind == "json":
        p, g = (json.loads(t) for t in texts)
        p, g = spec.get("normalize", {}).get(label, lambda x, y: (x, y))(p, g)
        jdiff(p, g, "", out, label)
    elif kind == "jsonl":                          # one object per line, keyed by spec["jsonl_key"]
        sides = [{}, {}]
        for side, t in zip(sides, texts):
            for i, ln in enumerate(x for x in t.splitlines() if x.strip()):
                o = json.loads(ln)
                side[str(spec["jsonl_key"](o) if spec.get("jsonl_key") else i)] = o
        jdiff(sides[0], sides[1], "", out, label)
    elif kind == "prom":
        (ps, pc), (gs, gc) = (prom_samples(t, spec.get("volatile", ())) for t in texts)
        jdiff(ps, gs, "", out, label)
        for ln in sorted(pc ^ gc):
            out.append({"file": label, "path": ln, "python": "<present>" if ln in pc else ABSENT,
                        "go": "<present>" if ln in gc else ABSENT})
    return out


def _drop(doc, keys):
    return {k: v for k, v in doc.items() if k not in keys} if isinstance(doc, dict) else doc


def norm_ledger(p, g):
    """Write times differ by construction; a run record may carry implementation-specific keys (core version, ...)."""
    p, g = _drop(p, ("updated_at",)), _drop(g, ("updated_at",))
    pr, gr = p.get("runs") or [], g.get("runs") or []
    for i in range(min(len(pr), len(gr))):
        one_side = set(pr[i]) ^ set(gr[i])
        pr[i], gr[i] = (_drop(r, {"at", "core"} | one_side) for r in (pr[i], gr[i]))
    return p, g


def norm_items(p, g):
    return _drop(p, ("updated_at", "core", "implementation")), _drop(g, ("updated_at", "core", "implementation"))


def _files_tracker(r):
    t = (r.inst.get("remediation") or {}).get("tracker") or {}
    return not isinstance(t, dict) or t.get("type", "files") == "files"


COMPONENTS = {
    "ledger": {
        "subcommand": "ledger",
        "exec": "exec_ledger",
        "timeout": lambda a: 600,
        "python": lambda a: [sys.executable, os.path.join(ROOT, "core", "ledger.py"), "--run", a["run_dir"],
                             "--data", a["data"], "--latest", a["latest"]],
        "go": lambda a: ["ledger", "merge", "--run", a["run_dir"], "--data", a["data"], "--latest", a["latest"],
                         "--instance", a["instance"]] + (["--now", str(int(a["now"]))] if a.get("now") else []),
        "inputs": ["ledger.json", "exceptions.yaml", "catalog-review.yaml", "latest", RUN],
        "outputs": lambda r, a: [("ledger.json", "data", "ledger.json", "json"),
                                 ("metrics/ledger.prom", "data", os.path.join("metrics", "ledger.prom"), "prom"),
                                 ("sli.prom", "run_dir", "sli.prom", "prom"), ("ocsf.jsonl", "run_dir", "ocsf.jsonl", "jsonl")],
        "normalize": {"ledger.json": norm_ledger},
        "jsonl_key": lambda o: (o.get("finding_info") or {}).get("uid"),
        "volatile": ("security_ledger_last_update_timestamp_seconds",),
        # (file, path regex, side that lacks the value, reason): the TARGET behaviour of a known deviation
        "explained": [("ledger.json", r"^entries\.[0-9a-f]{12}\.due_at$", "python", "LEDGER-D2")],
        # attribution of the other differences: Go runs with deviations switched back to the reference behaviour, one
        # deviation at a time, then together (a difference only both together remove); LEDGER-D1 and D4 cannot be
        # switched back: D1 makes the reference fail (python_failures), D4 only shows outside UTC
        "reference": [(["--reference-behaviour", "LEDGER-D5"], "LEDGER-D5"),
                      (["--reference-behaviour", "LEDGER-D3"], "LEDGER-D3"),
                      (["--reference-behaviour", "LEDGER-D2,LEDGER-D3,LEDGER-D5"], "LEDGER-D3+D5")],
        # (regex on the reference's log, reason): a known deviation that makes the reference fail the whole merge
        "python_log": lambda a: os.path.join(a["run_dir"], "ledger.log"),
        "python_failures": [(r"KeyError: 'kind'", "LEDGER-D1")],
    },
    "remediation": {
        "subcommand": "ledger",
        "exec": "exec_remediation",
        "timeout": lambda a: cron.parse_duration(a["job"].get("timeout", "10m")),
        "python_now": True,                         # shadow: both sides get the same --now, so items are comparable
        "python": lambda a: [sys.executable, os.path.join(ROOT, "core", "remediation.py"), "--data", a["data"],
                             "--instance", a["instance"]] + (["--now", str(int(a["now"]))] if a.get("now") else []),
        "go": lambda a: ["ledger", "track", "--data", a["data"], "--instance", a["instance"]] +
                        (["--now", str(int(a["now"]))] if a.get("now") else []) +
                        (["--no-external-sync"] if a.get("shadow") else []),
        "inputs": ["ledger.json", "tracker"],
        "outputs": lambda r, a: [("tracker/items.json", "data", os.path.join("tracker", "items.json"), "json"),
                                 ("metrics/remediation.prom", "data", os.path.join("metrics", "remediation.prom"), "prom")] +
                                ([("tracker/*.md", "data", os.path.join("tracker", "*.md"), "text")] if _files_tracker(r) else []),
        "normalize": {"tracker/items.json": norm_items},
        "volatile": ("security_remediation_last_update_timestamp_seconds",),
        "explained": [],
    },
}


def merge_families(text):
    """Concatenated .prom files repeat HELP/TYPE per family; keep the first, group samples by family."""
    fam, order, meta = {}, [], {}
    for line in text.splitlines():
        if not line.strip():
            continue
        if line.startswith("# HELP ") or line.startswith("# TYPE "):
            n = line.split()[2]
            meta.setdefault((n, line[2:6]), line)
            if n not in fam:
                fam[n] = []
                order.append(n)
            continue
        n = line.split("{", 1)[0].split()[0]
        if n not in fam:
            fam[n] = []
            order.append(n)
        if line not in fam[n]:
            fam[n].append(line)
    out = []
    for n in order:
        for k in ("HELP", "TYPE"):
            if (n, k) in meta:
                out.append(meta[(n, k)])
        out += fam[n]
    return "\n".join(out) + "\n"


def serve_metrics(directory, port, addr="0.0.0.0"):
    """Minimal exporter: GET /metrics = every *.prom file under `directory` (e.g. a mounted ConfigMap)."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path in ("/healthz", "/ready"):
                body, code = b"ok\n", 200
            elif self.path.split("?")[0] == "/metrics":
                files = sorted(glob.glob(os.path.join(directory, "*.prom")))
                text = "".join(open(f).read() for f in files)
                text += f"# TYPE security_exporter_files gauge\nsecurity_exporter_files {len(files)}\n"
                body, code = text.encode(), 200
            else:
                body, code = b"not found\n", 404
            self.send_response(code)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    ThreadingHTTPServer((addr, port), H).serve_forever()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("cmd", choices=["tick", "run", "status", "metrics", "serve-metrics", "version"])
    ap.add_argument("jobs", nargs="*")
    ap.add_argument("--instance")
    ap.add_argument("--data")
    ap.add_argument("--now", type=float)
    ap.add_argument("--dir")
    ap.add_argument("--port", type=int, default=9851)
    a = ap.parse_args(argv)
    if a.cmd == "version":
        print(VERSION)
        return 0
    if a.cmd == "serve-metrics":
        serve_metrics(a.dir, a.port)
        return 0
    try:
        r = Runner(a.instance, a.data)
    except Exception as e:  # noqa: BLE001 - say why in the log; the missing heartbeat is what alerts
        log(f"cannot start: {type(e).__name__}: {str(e)[:300]}")
        return 78
    now = a.now or time.time()
    if a.cmd == "status":
        print(json.dumps({n: dict(r.load_state(n), due=r.due(n, now)[1], schedule=j["schedule"]) for n, j in r.jobs.items()},
                         indent=1, sort_keys=True))
        return 0
    if a.cmd == "metrics":
        r.publish(now)
        return 0
    rc = 0
    tick_lock = r.lock("tick")
    if a.cmd == "tick" and tick_lock is None:
        log("another tick is still running; this one exits")   # long jobs keep the tick lock; triggers may overlap
        return 0
    try:
        names = a.jobs or list(r.jobs)
        for name in names:
            if a.cmd == "run":
                rc = max(rc, r.execute(name) or 0)
                continue
            slot, why = r.due(name, time.time() if not a.now else now)
            if slot is not None:
                rc = max(rc, r.execute(name, slot) or 0)
        if a.cmd == "tick" and not a.jobs:
            r.forward()
            r.prune(time.time())
        try:
            r.publish(time.time())
        except Exception as e:  # noqa: BLE001 - e.g. the local metrics file; the stale heartbeat alerts
            log(f"publish: {type(e).__name__}: {str(e)[:300]}")
            rc = max(rc, 1)
    finally:
        if tick_lock:
            tick_lock.close()
    return 0 if a.cmd == "tick" else rc


if __name__ == "__main__":
    sys.exit(main())
