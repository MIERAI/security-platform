#!/usr/bin/env python3
"""Scale benchmark: how the core stages behave as the number of assets and findings grows.

    python bench/scale.py                                   # smoke size (CI): 1k findings, 100 assets, 3 runs
    python bench/scale.py --sizes 1000:100,10000:1000,100000:10000 --runs 5 --parallel 3 --out results.json

For each size it generates SYNTHETIC findings documents (schema findings/v1; several collectors; coverage per
asset; nothing environment-specific), then replays --runs collector runs with churn (each run: --churn of the open
findings are fixed, the same number of new ones appear, the rest is unchanged; a few hosts are a coverage gap; a few
findings have a human-approved exception, some of them expired) and runs, after every run, the real stages as
separate processes:

    ledger       core/ledger.py   (merge + lifecycle + SLIs + ledger.prom + latest-auto.md + ocsf.jsonl)
    scorecard    scorecard/scorecard.py compute
    digest       core/digest.py
    remediation  core/remediation.py

Wall time and peak RSS are measured per process (os.wait4 rusage), so the numbers are those of the stage alone.
Each size runs in its own temporary directory; independent sizes may run in parallel (--parallel), each stage is
single-threaded. Output: a table on stdout and (--out) the raw measurements as JSON.
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STAGES = {
    "ledger": lambda run, data: [os.path.join(ROOT, "core", "ledger.py"), "--run", run, "--data", data],
    "scorecard": lambda run, data: [os.path.join(ROOT, "scorecard", "scorecard.py"), "compute", "--data", data],
    "digest": lambda run, data: [os.path.join(ROOT, "core", "digest.py"), "--data", data],
    "remediation": lambda run, data: [os.path.join(ROOT, "core", "remediation.py"), "--data", data],
}
# share of the findings / assets per collector (vulnerabilities dominate real inventories)
MIX = {"vuln-intel": 0.60, "host": 0.12, "k8s": 0.15, "exposure": 0.05, "secrets-files": 0.08}
SEVERITIES = ["critical", "high", "medium", "medium", "low", "low", "info"]
HOST_CHECKS = ["ssh.password_auth_enabled", "ssh.root_login", "host.firewall_off", "host.updates_pending", "host.auditd_off"]
K8S_CHECKS = ["k8s.pod.privileged", "k8s.pod.run_as_root", "k8s.pod.no_limits", "k8s.pod.host_path", "k8s.sa.automount"]
EXPO_CHECKS = ["alertmanager.unauth", "prometheus.unauth_read", "telnet.open", "tls.weak", "http.no_tls"]
SECRET_CHECKS = ["secret.ssh_key_no_passphrase", "secret.token_file_world_readable", "secret.old"]


def fid(*parts):
    return hashlib.sha1("|".join(parts).encode()).hexdigest()[:12]


class Universe:
    """A deterministic synthetic estate: hosts, images, clusters/workloads, endpoints, and a pool of candidate
    findings per collector large enough to draw churn from."""

    def __init__(self, n_findings, n_assets, seed=1):
        self.rng = random.Random(seed)
        self.n_hosts = max(2, int(n_assets * 0.4))
        self.n_images = max(2, int(n_assets * 0.4))
        self.n_workloads = max(2, n_assets - self.n_hosts - self.n_images)
        self.n_clusters = max(1, self.n_workloads // 200)
        self.target = {c: max(1, int(n_findings * s)) for c, s in MIX.items()}

    def host(self, i):
        return f"h{i:05d}"

    def candidate(self, col):
        """One random finding of collector `col` (id is stable for (collector, asset, check))."""
        r = self.rng
        if col == "vuln-intel":
            img = f"image:registry.example/app{r.randrange(self.n_images):05d}:1.{r.randrange(3)}"
            cve = f"CVE-2099-{r.randrange(200000):06d}"
            sev = r.choice(SEVERITIES)
            kev = r.random() < 0.01
            at = dict(cve=cve, base_severity=sev, kev=kev, epss=round(r.random(), 3), published_at="2099-01-01",
                      fixed="2.0" if r.random() < 0.6 else None, package=f"pkg{r.randrange(500)}", installed="1.0",
                      alertable=kev, exposed=r.random() < 0.1)
            return dict(layer="supply-chain", asset=img, check="vuln." + cve.lower(), severity=sev, kind="vulnerability",
                        attributes=at)
        if col == "host":
            return dict(layer="host", asset=f"host:{self.host(r.randrange(self.n_hosts))}", check=r.choice(HOST_CHECKS),
                        severity=r.choice(SEVERITIES), kind="compliance")
        if col == "k8s":
            i = r.randrange(self.n_workloads)
            return dict(layer="workload", asset=f"k8s-workload:c{i % self.n_clusters}/ns{i % 37}/Deployment/app{i}",
                        check=r.choice(K8S_CHECKS), severity=r.choice(SEVERITIES), kind="compliance")
        if col == "exposure":
            i = r.randrange(self.n_hosts)
            return dict(layer="network", asset=f"net-endpoint:{self.host(i)}@10.{i // 65536}.{i // 256 % 256}.{i % 256}:"
                        f"{r.choice([22, 23, 80, 443, 9090, 9093])}", check=r.choice(EXPO_CHECKS),
                        severity=r.choice(SEVERITIES), kind="detection")
        h = r.randrange(self.n_hosts)
        return dict(layer="data-secrets", asset=f"secret-file:{self.host(h)}:~/.ssh/key{r.randrange(20)}",
                    check=r.choice(SECRET_CHECKS), severity=r.choice(SEVERITIES), kind="compliance")

    def coverage(self, col):
        if col in ("host", "secrets-files"):
            return [f"host:{self.host(i)}" for i in range(self.n_hosts)]
        if col == "vuln-intel":
            return [f"image:registry.example/app{i:05d}:1.{t}" for i in range(self.n_images) for t in range(3)]
        if col == "k8s":
            return [f"k8s-cluster:c{i}" for i in range(self.n_clusters)]
        return [f"net-endpoint:{self.host(i)}@10.{i // 65536}.{i // 256 % 256}.{i % 256}" for i in range(self.n_hosts)]

    def draw(self, col, n, exclude):
        out = {}
        tries = 0
        while len(out) < n and tries < n * 20:
            tries += 1
            c = self.candidate(col)
            i = fid(col, c["asset"], c["check"])
            if i not in exclude and i not in out:
                out[i] = c
        return out


def iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def write_doc(run_dir, col, findings, coverage, gaps, ts):
    doc = {"schema_version": "1.0", "collector": {"name": col, "version": "0.1.0", "tools": {}},
           "run": {"started_at": iso(ts), "finished_at": iso(ts), "instance": "bench"},
           "coverage": [{"asset": a, "status": "ok"} for a in coverage if a not in gaps]
           + [{"asset": a, "status": "gap", "reason": "offline at scan time"} for a in coverage if a in gaps],
           "findings": [dict(id=i, title=f"synthetic {c['check']} on {c['asset'].split(':', 1)[0]}", evidence=f"raw/{col}/x.json#{i}",
                             remediation="apply the documented fix", needs_human=False, owner="platform", observed_at=iso(ts),
                             refs=[], **{k: v for k, v in c.items() if k != "attributes"},
                             attributes=c.get("attributes", {})) for i, c in findings.items()],
           "metrics": [{"name": "security_bench_metric", "value": 1, "labels": {"collector": col}}]}
    with open(os.path.join(run_dir, f"{col}.findings.json"), "w") as f:
        json.dump(doc, f)


def measure(argv, env):
    """-> (seconds, peak RSS MiB, rc) of one child process (rusage of that child only)."""
    t0 = time.perf_counter()
    p = subprocess.Popen([sys.executable] + argv, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env)
    _, status, ru = os.wait4(p.pid, 0)
    dt = time.perf_counter() - t0
    err = p.stderr.read().decode(errors="replace")
    p.stderr.close()
    p.returncode = os.waitstatus_to_exitcode(status)
    rss = ru.ru_maxrss / (1024 * 1024 if sys.platform == "darwin" else 1024)
    if p.returncode:
        raise RuntimeError(f"{argv[0]} rc={p.returncode}: {err[-500:]}")
    return round(dt, 3), round(rss, 1)


def bench(n_findings, n_assets, runs, churn, stages, keep=None, seed=1):
    U = Universe(n_findings, n_assets, seed)
    work = keep or tempfile.mkdtemp(prefix=f"sp-bench-{n_findings}-")
    data = os.path.join(work, "data")
    os.makedirs(data, exist_ok=True)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    current = {c: U.draw(c, U.target[c], set()) for c in MIX}
    cov = {c: U.coverage(c) for c in MIX}
    t0 = 1_900_000_000
    res = {"findings": n_findings, "assets": n_assets, "runs": []}
    try:
        for r in range(runs):
            if r:
                for c in MIX:     # churn: some fixed, as many new, the rest unchanged
                    ids = sorted(current[c])
                    k = int(len(ids) * churn)
                    gone = set(U.rng.sample(ids, k))
                    keep_ = {i: v for i, v in current[c].items() if i not in gone}
                    keep_.update(U.draw(c, k, set(current[c])))
                    current[c] = keep_
            gaps = {f"host:{U.host(i)}" for i in U.rng.sample(range(U.n_hosts), max(1, U.n_hosts // 100))}
            run_dir = os.path.join(data, "runs", f"r{r:02d}")
            os.makedirs(run_dir)
            for c in MIX:
                write_doc(run_dir, c, current[c], cov[c], gaps if c in ("host", "secrets-files") else set(), t0 + r * 86400)
            # exceptions: ~1% of the open findings, one in five already expired
            allids = sorted(i for c in MIX for i in current[c])
            ex = U.rng.sample(allids, max(1, len(allids) // 100))
            with open(os.path.join(data, "exceptions.yaml"), "w") as f:
                f.write("exceptions:\n")
                for j, i in enumerate(ex):
                    f.write(f"  '{i}': {{reason: bench, approved_by: reviewer, expires: '{'2001-01-01' if j % 5 == 0 else '2999-01-01'}'}}\n")
            row = {"run": r + 1, "open_in_run": len(allids)}
            for s in stages:
                row[s] = measure(STAGES[s](run_dir, data), env)
            lp = os.path.join(data, "ledger.json")
            if os.path.exists(lp):
                row["ledger_mib"] = round(os.path.getsize(lp) / 2**20, 1)
                L = json.load(open(lp))
                st = {}
                for e in L["entries"].values():
                    st[e["status"]] = st.get(e["status"], 0) + 1
                row["entries"], row["status"] = len(L["entries"]), st
                del L
            res["runs"].append(row)
            print(f"  [{n_findings}/{n_assets}] run {r + 1}: " + " ".join(f"{s}={row[s][0]}s/{row[s][1]}MiB" for s in stages),
                  file=sys.stderr, flush=True)
    finally:
        if not keep:
            shutil.rmtree(work, ignore_errors=True)
    return res


def table(results, stages):
    head = "| findings | assets | run | ledger entries | ledger.json MiB | " + " | ".join(f"{s} s / MiB" for s in stages) + " |"
    out = [head, "|" + "---|" * (head.count("|") - 1)]
    for res in results:
        for row in res["runs"]:
            out.append(f"| {res['findings']} | {res['assets']} | {row['run']} | {row.get('entries', '')} | "
                       f"{row.get('ledger_mib', '')} | " + " | ".join(f"{row[s][0]} / {row[s][1]}" for s in stages) + " |")
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sizes", default="1000:100", help="findings:assets[,findings:assets...]")
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--churn", type=float, default=0.05)
    ap.add_argument("--stages", default=",".join(STAGES))
    ap.add_argument("--parallel", type=int, default=1, help="sizes benchmarked at the same time (each in its own dir)")
    ap.add_argument("--out")
    a = ap.parse_args(argv)
    stages = [s for s in a.stages.split(",") if s]
    sizes = [tuple(int(x) for x in s.split(":")) for s in a.sizes.split(",")]
    with concurrent.futures.ProcessPoolExecutor(max_workers=max(1, a.parallel)) as ex:
        results = list(ex.map(bench, [f for f, _ in sizes], [n for _, n in sizes], [a.runs] * len(sizes),
                              [a.churn] * len(sizes), [stages] * len(sizes)))
    print(table(results, stages))
    if a.out:
        json.dump({"python": sys.version.split()[0], "platform": sys.platform, "results": results}, open(a.out, "w"), indent=1)


if __name__ == "__main__":
    main()
