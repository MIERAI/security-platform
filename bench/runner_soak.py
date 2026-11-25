#!/usr/bin/env python3
"""Soak: the Go runner (`sp runner`) and the Python runner fed the same inputs over simulated days, compared.

    python3 bench/runner_soak.py --sp /path/to/sp [--days 3] [--findings 1000 --assets 100] [--out DIR]

A hub instance with realistic jobs (synthetic collectors from bench/scale.py with churn, a flaky collector with
retries, one with `max_delay`, one reporting under `as:`, the real remediation, digest and scorecard programs, a
textfile sink) runs on two copies of the same data directory (seeded with the conformance fixture's ledger). A fake clock (`--now`) ticks every 15 minutes for --days days in a non-UTC zone, with a --downtime gap (the
host is off: no ticks). Both runners tick at the same instants; after every tick their state files, `status`,
published metrics, tick logs, ledger, tracker and latest/ are compared.

Every difference is classified: identical, explained by a documented target behaviour of the Go runner (RUNNER-D1
one clock, RUNNER-D2 missed/pending slots, RUNNER-D7 withheld environment names), or UNEXPLAINED. Exit 1 when
anything is unexplained. Writes <out>/soak.json and prints a summary. Python ≥ 3.10 with PyYAML (the ledger).
"""
import argparse
import calendar
import concurrent.futures
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import scale  # noqa: E402

COLS = {"host": "0 * * * *", "k8s": "*/30 * * * *", "vuln-intel": "15 6 * * *", "exposure": "30 3 * * *",
        "secrets-files": "0 */4 * * *"}
EMIT = """#!/bin/sh
# soak collector: the next prepared document of $COL (deterministic per run count), or a failure when asked
set -e
n=$(cat "$SOAK_STATE/$COL.n" 2>/dev/null || echo 0)
echo $((n + 1)) > "$SOAK_STATE/$COL.n"
case " $FAIL_RUNS " in *" $n "*) echo "simulated failure of run $n" >&2; exit 3;; esac
cp "$SOAK_DOCS/$COL/$((n % NDOCS)).json" "$SP_RUN_DIR/${SP_COLLECTOR_NAME:-$COL}.findings.json"
"""
NDOCS = 6
# documented target behaviour of the Go runner (contracts/runner/SPEC.md "Known deviations")
D1 = "RUNNER-D1 one clock: the Python runner records wall-clock times under --now"
D2 = "RUNNER-D2 missed/pending slots: emitted by the Go runner only"
D7 = "RUNNER-D7 the Go runner logs the names of credential-like variables it withholds from jobs"
VOLATILE = "timing: durations measured on the real clock"
LEDGER_WALL = ("the ledger and remediation programs and the shadow comparison (the same code for both runners) stamp "
               "their updates with the wall clock")
D1_SCORECARD = ("RUNNER-D1 one clock: the scorecard is computed with --now = the runner clock (Python: wall clock); "
                "every control that differs is judged by an age (checked after every tick)")
D8 = ("RUNNER-D8 the Python runner reuses a run directory when a job runs twice within one wall-clock second "
      "(compressed time) and promotes the previous run's .prom with the new document")
REAL_START = time.time()


def epoch(s):
    return calendar.timegm(time.strptime(s, "%Y-%m-%dT%H:%M:%SZ"))


def make_docs(work, n_findings, n_assets, t0):
    """NDOCS documents per collector with churn (bench/scale.py's universe), finished at increasing times."""
    U = scale.Universe(n_findings, n_assets, seed=3)
    current = {c: U.draw(c, U.target[c], set()) for c in scale.MIX}
    cov = {c: U.coverage(c) for c in scale.MIX}
    for r in range(NDOCS):
        if r:
            for c in scale.MIX:
                ids = sorted(current[c])
                k = int(len(ids) * 0.05)
                gone = set(U.rng.sample(ids, k))
                keep = {i: v for i, v in current[c].items() if i not in gone}
                keep.update(U.draw(c, k, set(current[c])))
                current[c] = keep
        gaps = {f"host:{U.host(i)}" for i in U.rng.sample(range(U.n_hosts), max(1, U.n_hosts // 50))}
        for c in scale.MIX:
            d = os.path.join(work, "docs", c)
            os.makedirs(d, exist_ok=True)
            scale.write_doc(d, c, current[c], cov[c], gaps if c in ("host", "secrets-files") else set(), t0 + r * 3600)
            os.replace(os.path.join(d, f"{c}.findings.json"), os.path.join(d, f"{r}.json"))


def instance(work, impl, implementations=None, go_binary=None):
    emit = os.path.join(work, "emit.sh")
    jobs = {}
    for c, sched in COLS.items():
        j = {"type": "command", "collector": c, "argv": ["/bin/sh", emit], "schedule": sched,
             "env": {"COL": c, "SOAK_DOCS": os.path.join(work, "docs"), "SOAK_STATE": os.path.join(work, impl, "emit"),
                     "NDOCS": str(NDOCS)}}
        jobs[c] = j
    jobs["host"]["jitter"] = "20m"
    jobs["vuln-intel"].update(retries=2, retry_delay="10m")
    jobs["vuln-intel"]["env"]["FAIL_RUNS"] = "1"           # day 2: fails once, the retry succeeds
    jobs["exposure"]["max_delay"] = "1h"                    # its slot falls into the downtime: skipped
    jobs["secrets-files"].update({"as": "secrets-b", "retries": 1, "retry_delay": "10m"})
    jobs["secrets-files"]["env"]["FAIL_RUNS"] = "4 5"       # fails twice in a row: given up
    jobs["remediation"] = {"type": "remediation", "schedule": "*/30 * * * *"}
    jobs["digest"] = {"type": "digest", "schedule": "0 9 * * *"}
    extra = {"implementations": implementations, "go_binary": go_binary} if implementations else {}
    return {"name": "soak", "runner": {**extra, "site": "hub", "role": "hub", "tick_stale_after": "1h", "retention": "2d",
                                       "sinks": [{"type": "textfile", "path": os.path.join(work, impl, "sink", "sp.prom")}],
                                       "jobs": jobs}}


def seed(work):
    """A data directory that already holds a ledger (the conformance fixture's) and exceptions; the remediation job
    builds the tracker from it (the fixture's minimal tracker items are for `sp status` only)."""
    d = os.path.join(work, "seed")
    os.makedirs(d)
    fx = os.path.join(ROOT, "conformance", "cases", "cli", "status")
    shutil.copy(os.path.join(fx, "ledger.json"), os.path.join(d, "ledger.json"))
    with open(os.path.join(d, "exceptions.yaml"), "w") as f:
        f.write("exceptions: {}\n")
    return d


def tick(impl, argv, now, data, env):
    p = subprocess.run(argv + ["tick", "--instance", os.path.join(os.path.dirname(data), "instance.json"), "--data", data,
                               "--now", str(now)], env=env, capture_output=True, text=True, timeout=1800)
    log = os.path.join(data, "state", "runner", "tick.log")
    os.makedirs(os.path.dirname(log), exist_ok=True)
    with open(log, "a") as f:
        f.write(p.stdout + p.stderr)
        if p.returncode:
            f.write(f"tick.sh: runner exited rc={p.returncode}\n")
    st = subprocess.run(argv + ["status", "--instance", os.path.join(os.path.dirname(data), "instance.json"), "--data", data,
                                "--now", str(now)], env=env, capture_output=True, text=True, timeout=300)
    return {"rc": p.returncode, "log": p.stdout + p.stderr, "status": json.loads(st.stdout or "{}")}


# ---- comparison ------------------------------------------------------------------------------------------------
class Diffs:
    def __init__(self):
        self.counts, self.examples, self.unexplained, self.kinds = {}, {}, [], {}

    def add(self, why, what):
        self.counts[why] = self.counts.get(why, 0) + 1
        kind = why + " | " + re.sub(r"[0-9.]+", "N", what)[:100]
        self.kinds[kind] = self.kinds.get(kind, 0) + 1
        self.examples.setdefault(why, [])
        if len(self.examples[why]) < 5:
            self.examples[why].append(what)
        if why == "UNEXPLAINED":
            self.unexplained.append(what)


def compare_state(job, p, g, now, diffs):
    for k in sorted(set(p) | set(g)):
        a, b = p.get(k), g.get(k)
        if a == b:
            continue
        if k in ("missed_slots_total", "missed_slot") and a is None:
            diffs.add(D2, f"{job}.{k} = {b} (Go only)")
        elif k == "last_duration":
            diffs.add(VOLATILE, f"{job}.last_duration {a} / {b}")
        elif k in ("last_attempt", "last_success") and is_wall(a) and isinstance(b, int) and b <= now + 900:
            diffs.add(D1, f"{job}.{k}: Python {a} (wall clock), Go {b} (--now {now})")
        elif k == "last_run_dir" and a and b and a.rsplit("-", 1)[-1] == b.rsplit("-", 1)[-1]:
            diffs.add(D1, f"{job}.last_run_dir {a} / {b}")
        else:
            diffs.add("UNEXPLAINED", f"state {job}.{k}: Python {a!r} / Go {b!r} at {now}")


def compare_shadow(sp, sg, now, diffs):
    """state/runner/shadow/<component>.json (contract runner §7): the same comparison result on both sides."""
    names = set()
    for d in (sp, sg):
        if os.path.isdir(os.path.join(d, "shadow")):
            names |= set(os.listdir(os.path.join(d, "shadow")))
    for n in sorted(names):
        sides = []
        for d in (sp, sg):
            try:
                with open(os.path.join(d, "shadow", n)) as f:
                    sides.append(json.load(f))
            except (OSError, ValueError):
                sides.append(None)
        if None in sides:
            diffs.add("UNEXPLAINED", f"shadow state {n} only on one side at {now}")
            continue
        for k in sorted(set(sides[0]) | set(sides[1])):
            a, b = sides[0].get(k), sides[1].get(k)
            if a == b:
                continue
            if k == "at" and is_wall(a) and is_wall(b):
                diffs.add(LEDGER_WALL, f"shadow {n}.at")
            elif k == "run_dir" and a.rsplit("-", 1)[-1] == b.rsplit("-", 1)[-1]:
                diffs.add(D1, f"shadow {n}.run_dir {a} / {b}")
            else:
                diffs.add("UNEXPLAINED", f"shadow state {n}.{k}: Python {a!r} / Go {b!r} at {now}")


def is_wall(v):
    """A time the Python runner took from the wall clock during this soak (RUNNER-D1)."""
    return isinstance(v, (int, float)) and REAL_START - 60 <= v <= time.time() + 60


def compare_status(ps, gs, now, diffs):
    for job in sorted(set(ps) | set(gs)):
        a, b = ps.get(job, {}), gs.get(job, {})
        if re.match(r"retry \d+$", str(a.get("due"))) and b.get("due") == "waiting to retry":
            diffs.add(D1, f"status {job}: Python {a.get('due')!r} (retry_delay measured on the wall clock) / Go "
                          f"'waiting to retry' at {now}")
        elif a.get("due") != b.get("due"):
            diffs.add("UNEXPLAINED", f"status {job}.due: Python {a.get('due')!r} / Go {b.get('due')!r} at {now}")


SAMPLE = re.compile(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})?\s+(\S+)$")


def prom(path):
    out = []
    for line in open(path):
        m = SAMPLE.match(line.strip())
        if m:
            out.append((m.group(1), m.group(2) or "", m.group(3)))
        elif line.startswith("#"):
            out.append(("#", line.strip(), ""))
    return out


def stale_proms(dp):
    """Collectors whose latest/<c>.prom in the Python copy does not belong to latest/<c>.findings.json (RUNNER-D8)."""
    sys.path.insert(0, os.path.join(ROOT, "sdk"))
    from spsdk import to_prom
    out = set()
    for f in os.listdir(os.path.join(dp, "latest")):
        if f.endswith(".findings.json"):
            c = f[:-len(".findings.json")]
            pp = os.path.join(dp, "latest", c + ".prom")
            if os.path.exists(pp) and open(pp).read() != to_prom(json.load(open(os.path.join(dp, "latest", f)))):
                out.add(c)
    return out


def compare_metrics(pp, gp, now, diffs, stale=(), scorecard_ok=False):
    a = [x for x in prom(pp)]
    b = [x for x in prom(gp)]
    go_only = ("security_runner_job_missed_slots_total", "security_runner_job_pending_slot_timestamp_seconds")
    b = [x for x in b if x[0] not in go_only and not any(f" {n} " in x[1] for n in go_only)]
    diffs.add(D2, "missed/pending series removed before comparing") if len(b) != len(prom(gp)) else None
    if [x[:2] for x in a] != [x[:2] for x in b]:
        sa, sb = {x[:2] for x in a}, {x[:2] for x in b}
        diffs.add("UNEXPLAINED", f"metrics series differ at {now}: only Python {sorted(sa - sb)[:5]}, only Go {sorted(sb - sa)[:5]}")
        return
    for (n, lab, va), (_, _, vb) in zip(a, b):
        if va == vb:
            continue
        if n in ("security_runner_tick_timestamp_seconds", "security_metrics_published_timestamp_seconds",
                 "security_runner_job_last_attempt_timestamp_seconds", "security_runner_job_last_success_timestamp_seconds",
                 "security_runner_sink_last_success_timestamp_seconds") and is_wall(float(va)) and float(vb) <= now + 900:
            diffs.add(D1, f"{n}{lab} Python {va} / Go {vb}")
        elif n == "security_runner_job_duration_seconds":
            diffs.add(VOLATILE, f"{n}{lab}")
        elif any(f'collector="{c}"' in lab for c in stale):
            diffs.add(D8, f"{n}{lab} Python {va} / Go {vb}")
        elif n in ("security_ledger_last_update_timestamp_seconds", "security_remediation_last_update_timestamp_seconds",
                   "security_impl_shadow_last_run_timestamp_seconds") \
                and is_wall(float(va)) and is_wall(float(vb)):
            diffs.add(LEDGER_WALL, f"{n} Python {va} / Go {vb}")
        elif n.startswith("security_score") and scorecard_ok:
            diffs.add(D1_SCORECARD, f"{n}{lab} Python {va} / Go {vb}")
        else:
            diffs.add("UNEXPLAINED", f"metric {n}{lab}: Python {va} / Go {vb} at {now}")


LOGTS = re.compile(r"^\S+ runner: ")


def norm_log(text):
    out = []
    for line in text.splitlines():
        line = LOGTS.sub("runner: ", line)
        line = re.sub(r" in \d+s:", " in Ns:", line)
        line = re.sub(r"runs/\S+", "runs/X", line)
        out.append(line)
    return out


def compare_logs(pl, gl, now, diffs):
    a = norm_log(pl)
    b = []
    for line in norm_log(gl):
        if re.match(r"runner: \S+: slot \S+ missed \(older than max_delay\)$", line):
            diffs.add(D2, line)
        elif line.startswith("runner: environment: not passed to jobs"):
            diffs.add(D7, line)
        else:
            b.append(line)
    if a != b:
        diffs.add("UNEXPLAINED", f"tick log at {now}: Python {a} / Go {b}")


def ledger_view(data):
    try:
        L = json.load(open(os.path.join(data, "ledger.json")))
    except (OSError, ValueError):
        return None
    return {i: (e.get("status"), e.get("severity"), e.get("first_seen"), e.get("fixed_at"), e.get("reopened_count"))
            for i, e in L.get("entries", {}).items()}


def tracker_view(data):
    try:
        items = json.load(open(os.path.join(data, "tracker", "items.json")))
    except (OSError, ValueError):
        return None
    items = items.get("items", items) if isinstance(items, dict) else items
    return {k: (v.get("status"), v.get("due"), v.get("overdue")) for k, v in items.items()} if isinstance(items, dict) else items


def compare_data(dp, dg, now, diffs, stale=()):
    if ledger_view(dp) != ledger_view(dg):
        diffs.add("UNEXPLAINED", f"ledger entries differ at {now}")
    if tracker_view(dp) != tracker_view(dg):
        diffs.add("UNEXPLAINED", f"tracker items differ at {now}")
    lp, lg = os.path.join(dp, "latest"), os.path.join(dg, "latest")
    names = sorted(set(os.listdir(lp)) | set(os.listdir(lg)))
    for n in names:
        a, b = os.path.join(lp, n), os.path.join(lg, n)
        if not (os.path.exists(a) and os.path.exists(b) and open(a, "rb").read() == open(b, "rb").read()):
            if n.endswith(".prom") and n[:-5] in stale:
                diffs.add(D8, f"latest/{n} (Python: the previous run's) at {now}")
            else:
                diffs.add("UNEXPLAINED", f"latest/{n} differs at {now}")


def compare_tick(work, now, rp, rg, diffs):
    dp, dg = os.path.join(work, "python", "data"), os.path.join(work, "go", "data")
    sp, sg = os.path.join(dp, "state", "runner"), os.path.join(dg, "state", "runner")
    for name in sorted(set(os.listdir(sp)) | set(os.listdir(sg))):
        if not name.endswith(".json") or name == "sinks.json":
            continue
        if not os.path.exists(os.path.join(sp, name)):
            g = json.load(open(os.path.join(sg, name)))
            if g.get("runs_total") == 0 and g.get("missed_slots_total"):
                diffs.add(D2, f"{name}: only the Go runner keeps a state for a job whose only slot was missed")
                continue
        try:
            p, g = json.load(open(os.path.join(sp, name))), json.load(open(os.path.join(sg, name)))
        except (OSError, ValueError) as e:
            diffs.add("UNEXPLAINED", f"state {name}: {e}")
            continue
        compare_state(name[:-5], p, g, now, diffs)
    compare_shadow(sp, sg, now, diffs)
    compare_status(rp["status"], rg["status"], now, diffs)
    stale = stale_proms(dp)
    scorecard_ok = verify_scorecard(work, diffs)
    compare_metrics(os.path.join(dp, "metrics", "security-platform.prom"), os.path.join(dg, "metrics", "security-platform.prom"),
                    now, diffs, stale, scorecard_ok)
    compare_logs(rp["log"], rg["log"], now, diffs)
    compare_data(dp, dg, now, diffs, stale)
    if rp["rc"] != rg["rc"]:
        diffs.add("UNEXPLAINED", f"tick exit {rp['rc']} / {rg['rc']} at {now}")


# ---- driver ----------------------------------------------------------------------------------------------------
def prepare(work, a):
    t0 = epoch(a.start)
    make_docs(work, a.findings, a.assets, t0)
    with open(os.path.join(work, "emit.sh"), "w") as f:
        f.write(EMIT)
    sd = seed(work)
    for impl in ("python", "go"):
        os.makedirs(os.path.join(work, impl, "emit"))
        shutil.copytree(sd, os.path.join(work, impl, "data"))
        with open(os.path.join(work, impl, "instance.json"), "w") as f:
            json.dump(instance(work, impl, a.implementations, a.sp), f, indent=1)
    return t0


TIME_PHRASE = re.compile(r"\bage\b|\bago\b|not reviewed for|last good run|no success within|expired|until \d{4}-")


def controls(data):
    with open(os.path.join(data, "reports", "scorecard.json")) as f:
        c = json.load(f)["controls"]
    rows = c if isinstance(c, list) else [dict(v, id=k) for k, v in c.items()]
    # the data directory's own path differs between the two copies
    return {x["id"]: (x.get("status"), str(x.get("detail", "")).replace(data, "<data>")) for x in rows}


def verify_scorecard(work, diffs):
    """The scorecard differences are RUNNER-D1 only if every control that differs between the two copies is judged
    by an age (the scorecard compares file, heartbeat and job times with its --now: the Go runner passes its clock,
    the Python runner the wall clock). Run after every tick, so the claim covers every scorecard series compared."""
    a, b = controls(os.path.join(work, "python", "data")), controls(os.path.join(work, "go", "data"))
    bad = [k for k in sorted(set(a) | set(b)) if a.get(k) != b.get(k)
           and not (TIME_PHRASE.search(a.get(k, ("", ""))[1]) or TIME_PHRASE.search(b.get(k, ("", ""))[1]))]
    for k in bad:
        diffs.add("UNEXPLAINED", f"scorecard control {k}: Python {a.get(k)} / Go {b.get(k)}")
    return not bad


def run(a):
    work = a.out or tempfile.mkdtemp(prefix="sp-runner-soak-")
    os.makedirs(work, exist_ok=True)
    t0 = prepare(work, a)
    down_from, down_len = a.downtime.split("/")
    down0, down1 = epoch(down_from), epoch(down_from) + int(down_len[:-1]) * 3600
    env = {k: v for k, v in os.environ.items() if not k.startswith("SP_") or k in ("SP_PYTHON",)}
    env.update(TZ=a.tz, LC_ALL="C", SP_PY_HOME=ROOT, SP_PYTHON=a.python, PYTHONDONTWRITEBYTECODE="1")
    argv = {"python": [a.python, os.path.join(ROOT, "runner", "runner.py")], "go": [a.sp, "runner"]}
    diffs, ticks, skipped = Diffs(), 0, 0
    with concurrent.futures.ThreadPoolExecutor(2) as ex:
        for now in range(t0, t0 + a.days * 86400, a.step * 60):
            if down0 <= now < down1:
                skipped += 1
                continue
            fp = ex.submit(tick, "python", argv["python"], now, os.path.join(work, "python", "data"), env)
            fg = ex.submit(tick, "go", argv["go"], now, os.path.join(work, "go", "data"), env)
            rp, rg = fp.result(), fg.result()
            compare_tick(work, now, rp, rg, diffs)
            ticks += 1
            if ticks % 24 == 0:
                print(f"  {time.strftime('%Y-%m-%d %H:%M', time.gmtime(now))}Z: {ticks} ticks, "
                      f"unexplained {len(diffs.unexplained)}", file=sys.stderr, flush=True)
    runs = {impl: {n[:-5]: json.load(open(os.path.join(work, impl, "data", "state", "runner", n))).get("runs_total")
                   for n in sorted(os.listdir(os.path.join(work, impl, "data", "state", "runner"))) if n.endswith(".json") and n != "sinks.json"}
            for impl in ("python", "go")}
    res = {"work": work, "ticks": ticks, "skipped_ticks_downtime": skipped, "tz": a.tz, "days": a.days,
           "runs_total": runs, "differences": diffs.counts, "kinds": dict(sorted(diffs.kinds.items())),
           "examples": diffs.examples, "unexplained": diffs.unexplained[:50]}
    with open(os.path.join(work, "soak.json"), "w") as f:
        json.dump(res, f, indent=1)
    with open(os.path.join(work, "unexplained.txt"), "w") as f:
        f.write("".join(u + "\n" for u in diffs.unexplained))
    return res


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--sp", required=True, help="the sp binary (Go runner: `sp runner`)")
    ap.add_argument("--python", default=sys.executable, help="interpreter of the Python runner and the jobs")
    ap.add_argument("--days", type=int, default=3)
    ap.add_argument("--step", type=int, default=15, help="minutes between ticks")
    ap.add_argument("--start", default="2030-01-07T00:00:00Z")
    ap.add_argument("--downtime", default="2030-01-08T02:00:00Z/2h", help="START/<n>h: no ticks (host off)")
    ap.add_argument("--tz", default="Europe/Berlin")
    ap.add_argument("--findings", type=int, default=1000)
    ap.add_argument("--assets", type=int, default=100)
    ap.add_argument("--out")
    ap.add_argument("--implementations", help="runner.implementations for both runners, e.g. ledger=shadow,remediation=go "
                                              "(go_binary = --sp)")
    a = ap.parse_args(argv)
    a.implementations = dict(x.split("=", 1) for x in a.implementations.split(",")) if a.implementations else None
    res = run(a)
    print(json.dumps({k: res[k] for k in ("work", "ticks", "skipped_ticks_downtime", "runs_total", "differences")}, indent=1))
    for u in res["unexplained"][:20]:
        print("UNEXPLAINED:", u)
    return 1 if res["unexplained"] else 0


if __name__ == "__main__":
    sys.exit(main())
