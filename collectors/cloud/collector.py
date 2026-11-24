#!/usr/bin/env python3
"""Collector `cloud`: cloud security posture (AWS accounts, GCP projects, Azure subscriptions), READ-ONLY.

Engine-agnostic: per account it
  1. authenticates with short-lived credentials only (adapters/cloud.py: OIDC federation; no stored keys),
  2. verifies its OWN permissions (read-only expected; a write-capable grant = finding
     cloud.platform_credential_over_privileged, and by default the account is not scanned: refuse-to-run),
  3. runs the configured check engines (Prowler by default; Steampipe, ScoutSuite) as external processes, and
  4. reads exports of the provider's own posture service (Security Hub ASFF, Security Command Center, Defender),
then maps every verdict onto a generic control (controls.py) and MERGES the same (resource, control) from several
engines/imports into ONE finding with several sources. Every failure is a coverage gap with its reason (expired
token, wrong audience, denied role, missing role, engine missing, a service the engine could not list) - never a
silent "no findings".

Instance config (docs/cloud.md, docs/instance-reference.md):
  cloud:
    refuse_over_privileged: true            # default; per account too
    accounts:
      - {provider: aws, account_id: "123456789012", role_arn: arn:aws:iam::123456789012:role/security-audit,
         audience: sts.amazonaws.com, identity_token: {type: file, path: /var/run/secrets/tokens/aws},
         regions: [eu-west-1], engines: [prowler, steampipe]}
      - {provider: gcp, project_id: my-project, workload_identity_provider: projects/N/locations/global/workloadIdentityPools/P/providers/X,
         service_account: auditor@my-project.iam.gserviceaccount.com, identity_token: {...}}
      - {provider: azure, subscription_id: ..., tenant_id: ..., client_id: ..., identity_token: {...}}
    engines:
      prowler:   {path: ~/.local/opt/security-platform/tools/prowler/bin/prowler, checks: [..]?, services: [..]?, timeout: 3h}
      steampipe: {path: .../steampipe, install_dir: .../steampipe-home, timeout: 10m}
      scoutsuite: {path: .../scout}
    imports:
      - {type: securityhub | scc | defender, file: <export.json>, max_age: 2d, accounts: [ids]?}
"""
import json
import os
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..", "..")
sys.path[:0] = [os.path.join(ROOT, "sdk"), ROOT, HERE]
import spsdk  # noqa: E402
from adapters import cloud  # noqa: E402
import controls  # noqa: E402
import engines  # noqa: E402

VERSION = open(os.path.join(HERE, "VERSION")).read().strip()
SEV_ORDER = ["info", "low", "medium", "high", "critical"]
GCP_SERVICE = {"cloudstorage": "storage", "cloudsql": "sqladmin", "gke": "container", "kms": "cloudkms",
               "cloudresourcemanager": "cloudresourcemanager", "dns": "dns", "compute": "compute", "iam": "iam"}
AZURE_SERVICE = {"vm": "compute", "aks": "containerservice", "sqlserver": "sql", "postgresql": "dbforpostgresql",
                 "mysql": "dbformysql", "monitor": "insights", "containerregistry": "containerregistry"}


def service_norm(provider, service):
    s = (service or "other").lower()
    if provider == "gcp":
        return GCP_SERVICE.get(s, s)
    if provider == "azure":
        return AZURE_SERVICE.get(s, s)
    return s


def asset_of(provider, account, r):
    """Canonical asset of a resource, identical whichever engine/import reported it:
       aws   cloud:aws/<account>/<service>/<region|global>/<ARN resource part>
       gcp   cloud:gcp/<project>/<api service>/<resource name>
       azure cloud:azure/<subscription>/<provider namespace>/<resource id below the subscription, lower case>"""
    uid = r.get("resource") or r.get("name") or "account"
    if uid.startswith("arn:"):
        p = uid.split(":", 5)
        if len(p) == 6:
            return f"cloud:aws/{p[4] or account}/{p[2]}/{p[3] or 'global'}/{p[5]}"
    if provider == "azure" and uid.lower().startswith("/subscriptions/"):
        parts = uid.strip("/").split("/")
        ns = next((parts[i + 1].split(".", 1)[-1].lower() for i, x in enumerate(parts[:-1]) if x.lower() == "providers"),
                  service_norm(provider, r.get("service")))
        return f"cloud:azure/{parts[1].lower()}/{ns}/{'/'.join(parts[2:]).lower()}"
    if provider == "aws":
        return f"cloud:aws/{account}/{service_norm(provider, r.get('service'))}/{r.get('region') or 'global'}/{uid}"
    name = (r.get("name") if provider == "gcp" else "") or uid.split("/")[-1]      # GCP: resource NAME (ids differ per API)
    return f"cloud:{provider}/{account}/{service_norm(provider, r.get('service'))}/{name}"


class Pool:
    """Findings of one run, merged: key (asset, control); a source whose own check maps to no control joins an existing
    finding on the same asset when they share a CIS benchmark reference. Never double counted."""

    def __init__(self):
        self.items = {}

    def add(self, provider, account, r):
        if r.get("status") != "FAIL" or r.get("coverage_only"):
            return None
        asset = asset_of(provider, account, r)
        check, pillar, layer, title, fix, cis = controls.classify(provider, r["check"], r.get("control"))
        key = (asset, check)
        if key not in self.items and r.get("refs"):
            key = next((k for k, v in self.items.items() if k[0] == asset and set(v["refs"]) & set(r["refs"])), key)
        f = self.items.get(key)
        if f is None:
            f = self.items[key] = dict(asset=asset, check=check, pillar=pillar, layer=layer, severity=r["severity"],
                                       title=title or r.get("title") or check, remediation=fix or r.get("remediation") or "",
                                       refs=[], sources=[], provider=provider, account=account, resource=r.get("resource", ""),
                                       cis_benchmark={k: [f"{controls.CIS_VERSIONS[k]}/{x}" for x in v] for k, v in cis.items()
                                                      if k == provider})
        if SEV_ORDER.index(r["severity"]) > SEV_ORDER.index(f["severity"]):
            f["severity"] = r["severity"]
        src = {"source": r["source"], "check": r["check"], "detail": str(r.get("detail", ""))[:200]}
        if src not in f["sources"]:
            f["sources"].append(src)
        f["refs"] = sorted(set(f["refs"]) | set(r.get("refs") or []))
        return f

    def emit(self, c):
        for f in sorted(self.items.values(), key=lambda x: (x["asset"], x["check"])):
            short = f["asset"].split("/", 3)[-1] if f["asset"].count("/") >= 3 else f["asset"]
            engines_ = sorted({s["source"] for s in f["sources"]})
            c.finding(f["layer"], f["asset"], f["check"], f"{f['title']}: {short}", f["severity"],
                      f"raw/{c.name}/{f['provider']}-{f['account']}.json#{f['asset']}", f["remediation"],
                      kind="compliance", refs=f["refs"] or None, pillar=f["pillar"], provider=f["provider"],
                      account=f["account"], sources=f["sources"], engines=engines_, source_count=len(engines_),
                      cis_benchmark=f["cis_benchmark"])


def scan_account(c, acct, ecfgs, default_refuse, pool, evidence, stats):
    try:
        prov = cloud.provider(acct)
    except cloud.CloudAuthError as e:
        ident = acct.get("account_id") or acct.get("project_id") or acct.get("subscription_id") or acct.get("name", "?")
        c.gap(f"cloud:{acct.get('provider', 'unknown')}/{ident}", str(e))
        stats["gap"] += 1
        return
    ev = evidence.setdefault((prov.kind, prov.account), {"engines": {}, "imports": []})
    with tempfile.TemporaryDirectory(prefix="sp-cloud-") as tmp:          # 0700; removed with everything in it
        try:
            ev["identity"] = prov.identity()
        except cloud.CloudAuthError as e:
            c.gap(prov.asset, f"authentication failed: {e}")
            stats["gap"] += 1
            return
        try:
            perm = prov.permissions()
        except cloud.CloudAuthError as e:
            if "does not exist" in str(e):
                c.gap(prov.asset, str(e))
                stats["gap"] += 1
                return
            perm = {"error": f"could not verify own permissions: {e}"}
        ev["self_check"] = perm
        if perm.get("write_capable"):
            c.finding("identity", prov.asset, "cloud.platform_credential_over_privileged",
                      f"the platform's credential for {prov.kind} {prov.account} can write: "
                      + ", ".join(perm["write_capable"])[:200], "high",
                      f"raw/{c.name}/{prov.kind}-{prov.account}.json#self_check", controls.CONTROLS[
                          "cloud.platform_credential_over_privileged"][3], needs_human=True, pillar="people",
                      provider=prov.kind, account=prov.account)
            if acct.get("refuse_over_privileged", default_refuse):
                c.gap(prov.asset, "refused to scan: the platform's credential is over-privileged (read-only expected)")
                stats["refused"] += 1
                return
        names = acct["engines"] if "engines" in acct else (list(ecfgs) or ["prowler"])
        if not names:          # authentication + self-verification only (posture comes from an import, if any)
            ev["engines"] = {}
            return
        env_add, args = prov.engine_env(tmp)
        env = cloud.clean_env()
        env.update(env_add)
        ok, runs = [], []
        for name in names:
            fn = engines.ENGINES.get(name)
            if not fn:
                c.gap(f"{prov.asset}/engine:{name}", f"unknown engine {name} ({', '.join(engines.ENGINES)})")
                continue
            run = fn(prov, env, args, ecfgs.get(name) or {}, tmp)
            ev["engines"][name] = {"ok": run.ok, "reason": run.reason, "version": run.version,
                                   "errors": {s: e[:3] for s, e in run.errors.items()}, "results": len(run.results)}
            stats["engines"][(name, "ok" if run.ok else "failed")] = stats["engines"].get((name, "ok" if run.ok else "failed"), 0) + 1
            if not run.ok:
                c.gap(f"{prov.asset}/engine:{name}", run.reason or f"{name} failed")
                continue
            ok.append(name)
            if run.version:
                c.tools[name] = run.version
            runs.append(run)
            for r in run.results:
                pool.add(prov.kind, r.get("account") or prov.account, r)
        # a service is a gap when an engine could not list it (errors, no verdict) and NO engine covered it cleanly
        # (verdicts without errors): its findings are then kept, never "fixed" by a blind run
        clean = {r["service"] for run in runs for r in run.results if r["service"] not in run.errors}
        for run in runs:
            for svc, errs in sorted(run.gap_services().items()):
                if svc not in clean:
                    c.gap(f"{prov.asset}/{service_norm(prov.kind, svc)}", f"{run.engine} could not list {svc}: {errs[0]}"[:300])
        if ok:
            c.ok(prov.asset)
            stats["scanned"] += 1
        else:
            c.gap(prov.asset, "no engine ran: " + "; ".join(f"{n}: {ev['engines'].get(n, {}).get('reason', '?')}" for n in names)[:250])
            stats["gap"] += 1


def run_imports(c, imports, pool, evidence, configured):
    for imp in imports:
        typ, path = imp.get("type"), os.path.expanduser(str(imp.get("file", "")))
        label = f"cloud:import/{typ}"
        fn = engines.IMPORTERS.get(typ)
        if not fn:
            c.gap(label, f"unknown import type {typ} ({', '.join(engines.IMPORTERS)})")
            continue
        try:
            age = time.time() - os.stat(path).st_mtime
            doc = json.load(open(path))
        except (OSError, ValueError) as e:
            c.gap(label, f"export unreadable: {type(e).__name__}")
            continue
        if age > engines.seconds(imp.get("max_age"), 2 * 86400):
            c.gap(label, f"export is {age / 86400:.1f} days old (max_age {imp.get('max_age', '2d')})")
            continue
        results = fn(doc)
        prov = {"securityhub": "aws", "scc": "gcp", "defender": "azure"}[typ]
        accounts = [str(a) for a in imp.get("accounts") or []] or sorted({r["account"] for r in results if r["account"]})
        for a in accounts:
            c.ok(f"cloud:{prov}/{a}")
            evidence.setdefault((prov, a), {"engines": {}, "imports": []})["imports"].append(
                {"type": typ, "age_hours": round(age / 3600, 1), "results": sum(1 for r in results if r["account"] == a)})
        c.tools.setdefault(f"import-{typ}", "export")
        for r in results:
            if r["account"] in accounts:
                pool.add(prov, r["account"], r)


def main():
    inst = spsdk.load_instance()
    cfg = inst.get("cloud") or {}
    c = spsdk.Collector("cloud", VERSION)
    pool, evidence = Pool(), {}
    stats = {"scanned": 0, "gap": 0, "refused": 0, "engines": {}}
    ecfgs = cfg.get("engines") or {}
    default_refuse = cfg.get("refuse_over_privileged", True)
    for acct in cfg.get("accounts") or []:
        scan_account(c, acct, ecfgs, default_refuse, pool, evidence, stats)
    run_imports(c, cfg.get("imports") or [], pool, evidence, cfg.get("accounts") or [])
    pool.emit(c)
    for (prov, acct), ev in sorted(evidence.items()):
        ev["findings"] = {f["asset"]: {"check": f["check"], "pillar": f["pillar"], "sources": f["sources"]}
                          for f in pool.items.values() if f["provider"] == prov and f["account"] == acct}
        c.raw(f"{prov}-{acct}.json", ev)
    for st in ("scanned", "gap", "refused"):
        c.metric("security_cloud_accounts", stats[st], "Cloud accounts/projects/subscriptions by scan state", state=st)
    for (name, res), n in sorted(stats["engines"].items()):
        c.metric("security_cloud_engine_runs", n, "Check-engine runs in this collector run", source=name, result=res)
    pillars = {}
    for f in pool.items.values():
        pillars[f["pillar"]] = pillars.get(f["pillar"], 0) + 1
    for p in ("network", "device", "people", "software"):
        c.metric("security_cloud_findings", pillars.get(p, 0), "Cloud findings (merged across engines) by pillar", pillar=p)
    c.write()


if __name__ == "__main__":
    main()
