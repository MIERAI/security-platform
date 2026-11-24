"""e2e assertions on the private data directory of the fictional company (runs inside the operator container)."""
import glob
import json
import os
import sys

data = os.path.expanduser(sys.argv[1])
L = json.load(open(os.path.join(data, "ledger.json")))["entries"]
open_ = [e for e in L.values() if e["status"] == "open"]
failures = []


def expect(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def has(check, asset_part):
    return any(e["check"] == check and asset_part in e["asset"] for e in open_)


expect(has("ssh.password_auth_enabled", "host:app-1"), "host: password login found on app-1 (ssh adapter)")
expect(not any(e["asset"] == "host:app-2" and e["check"].startswith("ssh.password") for e in open_),
       "host: hardened app-2 has no password-login finding")
expect(has("repo.default_branch_unprotected", "acme/webapp"), "codehost-gitea: unprotected default branch")
expect(has("repo.deploy_key_write", "acme/webapp/deploy-key"), "codehost-gitea: write deploy key")
expect(not any(e["check"] == "repo.default_branch_unprotected" and "acme/infra" in e["asset"] for e in open_),
       "codehost-gitea: protected repo not flagged")
expect(any(e["check"].startswith("k8s.pod.privileged") and "legacy" in e["asset"] for e in open_),
       "k8s: privileged pod in namespace legacy")

latest = {os.path.basename(p).split(".")[0]: json.load(open(p))
          for p in glob.glob(os.path.join(data, "latest", "*.findings.json"))}
for c in ("exposure", "host", "k8s", "codehost-gitea"):
    expect(c in latest, f"{c}: a valid findings document reached the ledger")
exp = latest.get("exposure", {})
cov = {x["asset"]: x["status"] for x in exp.get("coverage", [])}
expect(sum(1 for a, s in cov.items() if a.startswith("net-endpoint:") and s == "ok") >= 3,
       "exposure: the CIDR's live servers were scanned (static discovery, local vantage)")
expect(not any("10.250.99.5" in a for a in cov), "exposure: the unused CIDR address is not a coverage gap")
gaps = [x for d in latest.values() for x in d.get("coverage", []) if x["status"] == "gap"]
expect(not gaps, f"no coverage gaps ({[g['asset'] + ': ' + g.get('reason', '') for g in gaps]})")
items = os.path.join(data, "tracker", "items.json")
expect(os.path.exists(items), "remediation: tracker items written")
if os.path.exists(items):
    it = json.load(open(items))
    it = it.get("items", it) if isinstance(it, dict) else it
    vals = it.values() if isinstance(it, dict) else it
    expect(all(i.get("owner") for i in vals), "remediation: every item has an owner (default_owner)")
prom = open(os.path.join(data, "metrics", "security-platform.prom")).read()
expect("security_findings{" in prom and "security_sli{" in prom, "metrics: ledger metrics in the published text")
sc_p = os.path.join(data, "reports", "scorecard.json")
expect(os.path.exists(sc_p), "scorecard: computed on publish (reports/scorecard.json)")
if os.path.exists(sc_p):
    sc = json.load(open(sc_p))
    expect(len(sc.get("dimensions", {})) >= 10 and sc.get("pillars"), "scorecard: dimensions and pillars scored "
           f"(overall {sc.get('overall')}, weakest {sc.get('weakest')})")
    expect("security_score{" in prom or "security_score_overall" in prom, "metrics: scorecard metrics published")
sys.exit(1 if failures else 0)
