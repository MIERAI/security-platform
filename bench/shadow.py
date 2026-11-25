#!/usr/bin/env python3
"""Shadow run on realistic data: the runner's `implementations: shadow` mode (docs/contracts.md) end to end.

    python bench/shadow.py --sp /path/to/sp [--size 10000:1000] [--rounds 6] [--work DIR] [--tz UTC]

Builds a private data directory and an instance whose collectors are `command` jobs replaying prepared findings
documents, then drives the REAL runner (`runner.py run <job>`) for several rounds with `runner.implementations:
{ledger: shadow, remediation: shadow}`: Python stays the source of truth, the Go `sp` binary runs on a copy of the same
inputs, and every merge and track leaves a diff report (`<run>/shadow-<component>.json`). The documents are:

  - bench/scale.py's synthetic estate (findings:assets): five collectors, churn between rounds (fixed findings, new
    ones), a few hosts offline (coverage gaps), ~1% of the findings under a human exception, re-drawn every round
    (so exceptions also disappear: LEDGER-D5) and one in five already expired; a coverage exception;
  - every findings document of the conformance suite's ledger cases (contracts' edge cases: narrow gaps, retirement,
    umbrella coverage, advisories, unknown fields, an invalid document, a finding without `kind`), each case under
    its own collector name `cf-<n>`, spread over the rounds.

Prints, per round and component, the differences of the shadow reports: unexplained ones (must be 0) and the
explained ones by reason (LEDGER-D1..D5 target behaviour), and exits 1 if anything is unexplained.
"""
import argparse
import glob
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COPY = "import os, shutil, sys\nshutil.copy(sys.argv[1], os.path.join(os.environ['SP_RUN_DIR'], sys.argv[2]))\n"


def load_scale():
    spec = importlib.util.spec_from_file_location("scale", os.path.join(ROOT, "bench", "scale.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def conformance_docs():
    """[(collector name, [document paths in step order])] of every ledger case that has findings documents."""
    out = []
    for i, case in enumerate(sorted(glob.glob(os.path.join(ROOT, "conformance", "cases", "ledger", "*", "case.json")))):
        c = json.load(open(case))
        docs = []
        for st in c["steps"]:
            for dst, src in (st.get("files") or {}).items():
                if dst.endswith(".findings.json") and isinstance(src, str) and dst.split("/")[0].startswith("run"):
                    docs.append(os.path.join(os.path.dirname(case), src))
        if docs:
            out.append((f"cf-{i:02d}", docs))
    return out


def write_feed(work, name, doc_path, collector):
    """Stage one document for job `name`, renamed to collector `collector` (the job copies it into its run dir)."""
    d = json.load(open(doc_path))
    if isinstance(d.get("collector"), dict):
        d["collector"]["name"] = collector
    p = os.path.join(work, "feed", f"{name}.findings.json")
    with open(p, "w") as f:
        json.dump(d, f)
    return p


def instance(work, jobs, sp):
    inst = {"name": "shadow-bench",
            "runner": {"role": "hub", "implementations": {"ledger": "shadow", "remediation": "shadow"}, "go_binary": sp,
                       "jobs": dict({n: {"type": "command", "collector": n, "schedule": "0 3 * * *", "timeout": "30m",
                                         "argv": [sys.executable, os.path.join(work, "copy.py"),
                                                  os.path.join(work, "feed", f"{n}.findings.json"), f"{n}.findings.json"]}
                                     for n in jobs},
                                    remediation={"type": "remediation", "schedule": "0 4 * * *", "timeout": "30m"})},
            "remediation": {"default_owner": "security-oncall", "owners": [{"layer_in": ["workload"], "owner": "platform-team"}],
                            "slo": {"critical": "5d"}}}
    p = os.path.join(work, "instance.json")
    with open(p, "w") as f:
        json.dump(inst, f, indent=1)
    return p


def run_job(inst, data, job, env):
    p = subprocess.run([sys.executable, os.path.join(ROOT, "runner", "runner.py"), "run", "--instance", inst, "--data", data, job],
                       capture_output=True, text=True, env=env, timeout=3600)
    return p.returncode, p.stderr


def reports(data, seen):
    out = []
    for p in sorted(glob.glob(os.path.join(data, "runs", "*", "*", "shadow-*.json"))):
        if p not in seen:
            seen.add(p)
            out.append((p, json.load(open(p))))
    return out


def prepare(work, n_findings, n_assets, rounds):
    """Feed per round: {job: document path}, and the exceptions.yaml text of each round."""
    scale = load_scale()
    U = scale.Universe(n_findings, n_assets, 7)
    current = {c: U.draw(c, U.target[c], set()) for c in scale.MIX}
    cov = {c: U.coverage(c) for c in scale.MIX}
    cf = conformance_docs()
    plan = []
    for r in range(rounds):
        if r:
            for c in scale.MIX:
                ids = sorted(current[c])
                k = int(len(ids) * 0.05)
                gone = set(U.rng.sample(ids, k))
                keep = {i: v for i, v in current[c].items() if i not in gone}
                keep.update(U.draw(c, k, set(current[c])))
                current[c] = keep
        gaps = {f"host:{U.host(i)}" for i in U.rng.sample(range(U.n_hosts), max(1, U.n_hosts // 100))}
        rd = os.path.join(work, "gen", f"r{r}")
        os.makedirs(rd)
        for c in scale.MIX:
            scale.write_doc(rd, c, current[c], cov[c], gaps if c in ("host", "secrets-files") else set(), 1_900_000_000 + r * 86400)
        docs = {c: (os.path.join(rd, f"{c}.findings.json"), c) for c in scale.MIX}
        for name, paths in cf:                     # case documents in their step order, one per round
            if r < len(paths):
                docs[name] = (paths[r], name)
        allids = sorted(i for c in scale.MIX for i in current[c])
        ex = U.rng.sample(allids, max(1, len(allids) // 100))
        exc = "exceptions:\n" + "".join(f"  '{i}': {{reason: bench, approved_by: reviewer, expires: "
                                        f"'{'2001-01-01' if j % 5 == 0 else '2999-01-01'}'}}\n" for j, i in enumerate(ex))
        exc += f"coverage_exceptions:\n  host|{sorted(gaps)[0]}: {{approved_by: reviewer, reason: bench, expires: '2999-01-01'}}\n"
        plan.append((docs, exc))
    return plan, sorted({n for docs, _ in plan for n in docs})


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sp", required=True, help="the Go sp binary")
    ap.add_argument("--size", default="10000:1000", help="findings:assets of the synthetic estate")
    ap.add_argument("--rounds", type=int, default=6)
    ap.add_argument("--work", help="keep everything here (default: a temporary directory, removed)")
    ap.add_argument("--tz", default="UTC", help="TZ of the runner and both implementations (LEDGER-D4 shows outside UTC)")
    a = ap.parse_args(argv)
    work = a.work or tempfile.mkdtemp(prefix="sp-shadow-bench-")
    os.makedirs(os.path.join(work, "feed"), exist_ok=True)
    data = os.path.join(work, "data")
    os.makedirs(data, exist_ok=True)
    with open(os.path.join(work, "copy.py"), "w") as f:
        f.write(COPY)
    nf, na = (int(x) for x in a.size.split(":"))
    plan, jobs = prepare(work, nf, na, a.rounds)
    inst = instance(work, jobs, os.path.abspath(a.sp))
    env = dict(os.environ, TZ=a.tz, PYTHONDONTWRITEBYTECODE="1")
    total, seen, failures = {"unexplained": 0, "explained": {}}, set(), []
    try:
        for r, (docs, exc) in enumerate(plan):
            with open(os.path.join(data, "exceptions.yaml"), "w") as f:
                f.write(exc)
            for job in sorted(docs):
                write_feed(work, job, *docs[job])
                rc, err = run_job(inst, data, job, env)
                if rc:
                    failures.append(f"round {r} {job}: rc={rc} {err.strip()[-200:]}")
            rc, err = run_job(inst, data, "remediation", env)
            if rc:
                failures.append(f"round {r} remediation: rc={rc} {err.strip()[-200:]}")
            summarize(r, reports(data, seen), total)
    finally:
        if not a.work:
            shutil.rmtree(work, ignore_errors=True)
    print(json.dumps({"total": total, "job_failures (python is the source of truth)": failures}, indent=1, sort_keys=True))
    return 1 if total["unexplained"] else 0


def summarize(r, reps, total):
    for p, rep in reps:
        why = rep.get("explained_by", {})
        for d in rep.get("differences", []):
            if not d.get("explained"):
                print(f"  UNEXPLAINED {rep['component']} {d}", file=sys.stderr)
        total["unexplained"] += rep.get("unexplained", 0)
        for k, v in why.items():
            total["explained"][k] = total["explained"].get(k, 0) + v
        print(f"round {r} {os.path.basename(os.path.dirname(p))} {rep['component']}: python_rc={rep['python_rc']} "
              f"go_rc={rep['go_rc']} unexplained={rep['unexplained']} explained={rep['explained']} {why}")


if __name__ == "__main__":
    sys.exit(main())
