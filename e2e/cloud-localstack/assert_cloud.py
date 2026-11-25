"""Assertions of e2e/cloud-localstack/run.sh (stdlib + the product's own modules).

  assert_cloud.py first     WORK              findings, pillars, de-duplication, coverage after the first scan
  assert_cloud.py second    WORK              lifecycle: the fixed resources' findings are fixed, the rest stay open
  assert_cloud.py failures  WORK PY ROOT      each failure scenario = a coverage gap with its reason
  assert_cloud.py scorecard WORK PY ROOT      cloud dimension applicable here, N/A without cloud, other scores unchanged
  assert_cloud.py secrets   WORK              no credential material on disk, temporary directories removed
  assert_cloud.py adc       WORK ROOT         GCP source adc: evidence names the service account + source only;
                                              discovery gcp lists the project's VM instances through the same login
"""
import glob
import json
import os
import re
import subprocess
import sys

failures = []
SUMMARY = []
IMPL, SP = os.environ.get("SP_CLOUD_E2E_IMPL", "python"), os.environ.get("SP_CLOUD_E2E_SP", "")
HERE = os.path.dirname(os.path.abspath(__file__))


def expect(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def ledger(work):
    return json.load(open(os.path.join(work, "data", "ledger.json")))["entries"]


def entry(L, check, asset_part):
    hits = [e for e in L.values() if e["check"] == check and asset_part in e["asset"]]
    return hits


def latest(work):
    return json.load(open(os.path.join(work, "data", "latest", "cloud.findings.json")))


def first(work):
    L = ledger(work)
    doc = latest(work)
    cov = {c["asset"]: (c["status"], c.get("reason", "")) for c in doc["coverage"]}
    A = "cloud:aws/000000000000"
    cases = [  # (what, check, asset part, pillar, sources expected at least)
        ("AWS security group open to 0.0.0.0/0 on 22", "cloud.firewall_admin_port_open", "/ec2/us-east-1/security-group/sg-",
         "network", {"prowler", "steampipe", "securityhub"}),
        ("AWS public S3 bucket", "cloud.storage_public", "/s3/global/acme-public-assets", "software",
         {"prowler", "steampipe", "scoutsuite", "securityhub"}),
        ("AWS unencrypted S3 bucket", "cloud.storage_unencrypted", "/s3/global/acme-unencrypted-logs", "software", {"prowler"}),
        ("AWS console user without MFA", "cloud.user_without_mfa", "/iam/global/user/legacy-deployer", "people",
         {"prowler", "steampipe", "scoutsuite"}),
        ("AWS user's access key created at setup", "cloud.aws.iam_user_no_setup_initial_access_key", "user/legacy-deployer",
         "people", {"prowler"}),
        ("AWS CloudTrail disabled (no multi-region trail)", "cloud.audit_log_disabled", "/cloudtrail/", "software", {"prowler"}),
        ("GCP firewall open to SSH (SCC import)", "cloud.firewall_admin_port_open", "cloud:gcp/acme-readonly/compute/", "network", {"scc"}),
        ("GCP public bucket (SCC import)", "cloud.storage_public", "cloud:gcp/acme-readonly/storage/", "software", {"scc"}),
        ("Azure management ports open (Defender import)", "cloud.firewall_admin_port_open", "virtualmachines/vm-legacy", "network", {"defender"}),
        ("Azure VM missing updates (Defender import)", "cloud.instance_unpatched", "virtualmachines/vm-legacy", "device", {"defender"}),
        ("GCP over-privileged platform identity", "cloud.platform_credential_over_privileged", "cloud:gcp/acme-overprivileged", "people", set()),
        ("Azure over-privileged platform identity", "cloud.platform_credential_over_privileged", "cloud:azure/44444444", "people", set()),
    ]
    for what, check, part, pillar, sources in cases:
        hits = [e for e in entry(L, check, part) if e["status"] == "open"]
        expect(len(hits) == 1, f"{what}: exactly one open finding ({len(hits)})")
        if hits:
            at = hits[0].get("attributes") or {}
            expect(at.get("pillar") == pillar, f"{what}: pillar {at.get('pillar')} (expected {pillar})")
            got = set(at.get("engines") or [])
            expect(sources <= got, f"{what}: sources {sorted(got)} include {sorted(sources)}")
            SUMMARY.append((what, check, pillar, ",".join(sorted(got)) or "self-check", hits[0]["severity"]))
    expect({(e.get("attributes") or {}).get("pillar") for e in L.values() if e["status"] == "open"}
           >= {"network", "device", "people", "software"}, "all four pillars have cloud findings")
    expect(cov.get(A, ("",))[0] == "ok", f"AWS account covered ({cov.get(A)})")
    expect(cov.get("cloud:gcp/acme-readonly", ("",))[0] == "ok", "GCP project covered by the SCC import (auth checked, no scan)")
    expect("refused" in cov.get("cloud:gcp/acme-overprivileged", ("", ""))[1], "GCP over-privileged project refused")
    expect("refused" in cov.get("cloud:azure/44444444-4444-4444-8444-444444444444", ("", ""))[1], "Azure over-privileged subscription refused")
    ct = cov.get(A + "/cloudtrail")
    expect(ct and ct[0] == "gap", f"LocalStack limit recorded honestly: cloudtrail is a coverage gap ({ct and ct[1][:90]})")
    raw = json.load(open(glob.glob(os.path.join(work, "runs", "1", "raw", "cloud", "aws-000000000000.json"))[0]))
    expect(raw["self_check"]["write_capable"] == [] and "arn:aws:iam::aws:policy/SecurityAudit" in raw["self_check"]["grants"],
           f"self-verification: the AWS role holds {raw['self_check']['grants']} and nothing write-capable")
    expect(all(raw["engines"][e]["ok"] for e in ("prowler", "steampipe", "scoutsuite")), "three engines ran against LocalStack")
    expect(A + "/ec2" not in cov, "ec2 not a gap: ScoutSuite could not list it on LocalStack but Steampipe covered it cleanly")
    print("     engine errors (LocalStack limits): " + "; ".join(f"{e}: {sorted(v['errors'])}" for e, v in raw["engines"].items()))
    print("\n| misconfiguration | control | pillar | sources | severity |\n|---|---|---|---|---|")
    for row in SUMMARY:
        print("| " + " | ".join(row) + " |")
    json.dump({"first": SUMMARY, "gaps": {a: r for a, (s, r) in cov.items() if s == "gap"}},
              open(os.path.join(work, "summary-first.json"), "w"), indent=1)


def second(work):
    L = ledger(work)
    for what, check, part in (("public bucket", "cloud.storage_public", "/s3/global/acme-public-assets"),
                              ("open SSH security group", "cloud.firewall_admin_port_open", "security-group/sg-"),
                              ("console user without MFA", "cloud.user_without_mfa", "user/legacy-deployer")):
        hits = entry(L, check, part)
        expect(len(hits) == 1 and hits[0]["status"] == "fixed", f"lifecycle: {what} -> fixed on the next covered run "
               f"({[h['status'] for h in hits]})")
    for what, check, part in (("unencrypted bucket", "cloud.storage_unencrypted", "acme-unencrypted-logs"),
                              ("CloudTrail disabled (cloudtrail gap: never closed by a blind run)", "cloud.audit_log_disabled", "/cloudtrail/")):
        hits = entry(L, check, part)
        expect(len(hits) == 1 and hits[0]["status"] == "open", f"lifecycle: {what} stays open")
    gcp = entry(L, "cloud.firewall_admin_port_open", "cloud:gcp/acme-readonly")
    expect(gcp and gcp[0]["status"] == "open", "lifecycle: GCP finding (unchanged export) stays open")


def run_collector(work, py, root, inst, run, impl=None):
    env = {"PATH": os.environ["PATH"], "HOME": os.path.join(work, "home"), "TMPDIR": os.path.join(work, "tmp"),
           "SP_INSTANCE": inst, "SP_RUN_DIR": run}
    argv = [SP, "cloud", "collect"] if (impl or IMPL) == "go" else [py, "collectors/cloud/collector.py"]
    subprocess.run(argv, cwd=root, env=env, check=True, capture_output=True)
    return json.load(open(os.path.join(run, "cloud.findings.json")))


def compare_with_python(work, py, root, name, run):
    """Go implementation: the same scenario with the Python implementation gives the same output."""
    if IMPL != "go":
        return
    pyrun = run + "-python"
    run_collector(work, py, root, os.path.join(work, "python", "failures", f"{name}.json"), pyrun, impl="python")
    r = subprocess.run([py, "-I", os.path.join(HERE, "compare_impls.py"), pyrun, run], capture_output=True, text=True)
    expect(r.returncode == 0, f"{name}: Go and Python outputs identical ({r.stdout.strip().splitlines()[-1]})")
    if r.returncode:
        print(r.stdout)


def failures_(work, py, root):
    rows = []
    for p in sorted(glob.glob(os.path.join(work, "failures", "*.json"))):
        inst = json.load(open(p))
        doc = run_collector(work, py, root, p, os.path.join(work, "runs", "fail-" + inst["name"]))
        gaps = [c for c in doc["coverage"] if c["status"] == "gap"]
        reason = gaps[0]["reason"] if gaps else ""
        expect(bool(gaps) and inst["expect"] in reason, f"{inst['name']}: coverage gap '{reason[:110]}'")
        if inst["name"].endswith("over-privileged"):
            expect([f["check"] for f in doc["findings"]] == ["cloud.platform_credential_over_privileged"],
                   f"{inst['name']}: finding cloud.platform_credential_over_privileged, no scan")
        else:
            expect(not doc["findings"], f"{inst['name']}: no findings (a gap is not 'secure')")
        compare_with_python(work, py, root, inst["name"], os.path.join(work, "runs", "fail-" + inst["name"]))
        rows.append((inst["name"], reason[:140]))
    json.dump(rows, open(os.path.join(work, "summary-failures.json"), "w"), indent=1)


def scorecard(work, py, root):
    sys.path.insert(0, os.path.join(root, "scorecard"))
    import scorecard as sc
    data = os.path.join(work, "data")
    inst = json.load(open(os.path.join(work, "instance.json")))
    r = sc.compute(data, inst)
    expect("cloud" in r["dimensions"], f"cloud dimension applicable with cloud accounts: score {r['dimensions'].get('cloud', {}).get('score')}")
    st = {c["id"]: c["status"] for c in r["controls"] if c["dimension"] == "cloud" or c["id"].startswith("self.cloud")}
    print("     " + ", ".join(f"{k}={v}" for k, v in sorted(st.items())))
    expect(st.get("self.cloud-credential-read-only") == "fail", "self dimension: over-privileged platform identity fails its control")
    r1 = sc.compute(data, {})
    expect("cloud" in r1["dimensions"], "no cloud config but cloud assets were covered (e.g. an import): applicable")
    empty = os.path.join(work, "data-without-cloud")
    os.makedirs(empty, exist_ok=True)
    r0 = sc.compute(empty, {})
    expect("cloud" not in r0["dimensions"] and "cloud" in r0["not_applicable"],
           f"an environment without cloud: cloud dimension N/A ({r0['not_applicable'].get('cloud', {}).get('reason')})")
    others = {k: v["score"] for k, v in r["dimensions"].items() if k != "cloud"}
    others0 = {k: v["score"] for k, v in r0["dimensions"].items()}
    expect(r0["overall"] == min(others0.values()), f"N/A dimension excluded from the overall score ({r0['overall']})")
    json.dump({"with_cloud": {"cloud": r["dimensions"]["cloud"]["score"], "controls": st},
               "without_cloud": {"not_applicable": r0["not_applicable"], "overall": r0["overall"]},
               "other_dimensions_with_cloud_config": others}, open(os.path.join(work, "summary-scorecard.json"), "w"), indent=1)


CRED = re.compile(r'"(?:SecretAccessKey|SessionToken|secret_access_key|session_token)"\s*:|\b(?:ASIA|LSIA)[A-Z0-9]{16}\b|'
                  r'ya29\.mock-|"access_token"\s*:|mock-refresh-|"refresh_token"\s*:')


def secrets(work):
    expect(os.path.isdir(os.path.join(work, "runs", "1")) and os.path.isdir(os.path.join(work, "data")), "scan output exists")
    left = glob.glob(os.path.join(work, "tmp", "sp-cloud-*"))
    expect(not left, f"per-run temporary directories removed ({left})")
    hits = []
    for top in ("data", "runs", "home", "tmp"):
        for rootd, _, files in os.walk(os.path.join(work, top)):
            for f in files:
                p = os.path.join(rootd, f)
                try:
                    if CRED.search(open(p, errors="replace").read()):
                        hits.append(os.path.relpath(p, work))
                except OSError:
                    pass
    expect(not hits, f"no credential material in data, runs, home or tmp ({hits[:5]})")
    expect(not os.path.exists(os.path.join(work, "home", ".aws")), "no ~/.aws written")
    print("     files in the scan's home: " + (", ".join(sorted(os.path.relpath(os.path.join(r, f), os.path.join(work, "home"))
                                                          for r, _, fs in os.walk(os.path.join(work, "home")) for f in fs)[:8]) or "none"))


def adc(work, root):
    raw = os.path.join(work, "runs", "1", "raw", "cloud", "gcp-adc-readonly.json")
    ev = json.load(open(raw))
    expect(ev.get("identity") == {"principal": "serviceAccount:audit@adc-readonly.iam.gserviceaccount.com",
                                  "account": "adc-readonly", "source": "adc"},
           f"GCP source adc: logged in as the audit service account, evidence = principal + source ({ev.get('identity')})")
    expect((ev.get("self_check") or {}).get("write_capable") == [], "GCP source adc: self-check ran and passed (read-only)")
    text = open(raw).read()
    expect("operator@example.com" not in text and "mock-refresh-" not in text, "GCP source adc: the operator's account and "
           "refresh token are not in the evidence")
    sys.path.insert(0, root)
    from adapters import discovery
    inst = json.load(open(os.path.join(work, "instance.json")))
    acct = next(a for a in inst["cloud"]["accounts"] if a.get("source") == "adc")
    m = acct["iamcredentials_url"].split("/gcp/")[0]
    base = dict({k: v for k, v in acct.items() if k not in ("provider", "engines")}, type="gcp",
                cloudasset_url=m + "/gcp/cloudasset/v1")
    over = dict(base, project_id="acme-overprivileged", service_account="auditor@acme-overprivileged.iam.gserviceaccount.com")
    got = discover(work, discovery, base)
    expect([(d["name"], d["address"], d["online"]) for d in got] == [("web-1", "192.0.2.10", True), ("batch-1", None, True)],
           f"discovery gcp (cloudasset, operator ADC, {IMPL}): running instances with their external address ({len(got)})")
    if IMPL == "go":
        py = discovery.discover(base)
        expect(json.dumps(got, sort_keys=True) == json.dumps(py, sort_keys=True), "discovery gcp: Go and Python list the same devices")
    try:
        discover(work, discovery, over)
        expect(False, "discovery gcp refuses an over-privileged identity")
    except Exception as e:  # noqa: BLE001
        expect("over-privileged" in str(e), f"discovery gcp refuses an over-privileged identity ({str(e)[:80]})")


def discover(work, discovery, cfg):
    """discovery gcp with the implementation under test (Go: `sp cloud discover CONFIG.json`, JSON on stdout)."""
    if IMPL != "go":
        return discovery.discover(cfg)
    p = os.path.join(work, "discover.json")
    json.dump(cfg, open(p, "w"))
    r = subprocess.run([SP, "cloud", "discover", p], capture_output=True, text=True,
                       env={"PATH": os.environ["PATH"], "HOME": os.path.join(work, "home")})
    os.remove(p)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip())
    return json.loads(r.stdout)


if __name__ == "__main__":
    cmd, work = sys.argv[1], sys.argv[2]
    {"first": lambda: first(work), "second": lambda: second(work), "secrets": lambda: secrets(work),
     "failures": lambda: failures_(work, sys.argv[3], sys.argv[4]),
     "scorecard": lambda: scorecard(work, sys.argv[3], sys.argv[4]), "adc": lambda: adc(work, sys.argv[3])}[cmd]()
    sys.exit(1 if failures else 0)
