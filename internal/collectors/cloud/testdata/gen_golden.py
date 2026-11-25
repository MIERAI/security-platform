#!/usr/bin/env python3
"""The Python implementation's answers on the cloud fixtures (tests/fixtures/cloud), for the Go implementation's
parity tests (golden.json next to this file): every parser's verdicts, the merged findings of the de-duplication
scenarios, and the control tables. tests/test_cloud.py checks that golden.json is what the Python implementation
answers today, so the two implementations cannot drift apart unnoticed.

usage: gen_golden.py            write golden.json
       gen_golden.py --check    exit 1 when golden.json is not current
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", "..", "..", ".."))
sys.path[:0] = [os.path.join(ROOT, "sdk"), ROOT, os.path.join(ROOT, "collectors", "cloud")]
import collector  # noqa: E402
import controls  # noqa: E402
import engines  # noqa: E402
import steampipe_queries  # noqa: E402

FX = os.path.join(ROOT, "tests", "fixtures", "cloud")
LOG = "\n".join([json.dumps({"level": "ERROR", "module": "inspector2_service", "message": "AccessDenied  when\ncalling"}),
                 json.dumps({"level": "WARNING", "module": "s3_service", "message": "slow"}),
                 "not json", json.dumps({"level": "CRITICAL", "module": "ec2_service", "message": "x" * 300}),
                 json.dumps({"level": "ERROR", "module": "lib", "message": "not a service"})])


def fx(name):
    return json.load(open(os.path.join(FX, name)))


def result(r):
    """A verdict with every field present (the Go Result has no optional fields)."""
    return {"source": r["source"], "provider": r["provider"], "account": r["account"], "service": r["service"],
            "region": r["region"], "resource": r["resource"], "name": r.get("name", ""), "check": r["check"],
            "control": r.get("control") or "", "status": r["status"], "severity": r["severity"], "title": r["title"] or "",
            "detail": str(r.get("detail") or ""), "refs": r["refs"], "remediation": r.get("remediation") or "",
            "coverage_only": bool(r.get("coverage_only"))}


def pool(provider, default_account, results):
    p = collector.Pool()
    for r in results:
        p.add(provider, r.get("account") or default_account, r)
    return [dict(f) for f in p.items.values()]


def golden():
    aws = (engines.parse_prowler_ocsf(fx("prowler-aws.ocsf.json"), "aws")
           + engines.parse_scoutsuite(fx("scoutsuite-aws.json"), "aws", "000000000000")
           + engines.securityhub(fx("securityhub-asff.json")))
    return {
        "parsers": {
            "prowler-aws": [result(r) for r in engines.parse_prowler_ocsf(fx("prowler-aws.ocsf.json"), "aws")],
            "prowler-gcp": [result(r) for r in engines.parse_prowler_ocsf(fx("prowler-gcp.ocsf.json"))],
            "prowler-azure": [result(r) for r in engines.parse_prowler_ocsf(fx("prowler-azure.ocsf.json"))],
            "scoutsuite-aws": [result(r) for r in engines.parse_scoutsuite(fx("scoutsuite-aws.json"), "aws", "000000000000")],
            "securityhub": [result(r) for r in engines.securityhub(fx("securityhub-asff.json"))],
            "scc": [result(r) for r in engines.scc(fx("scc-findings.json"))],
            "defender": [result(r) for r in engines.defender(fx("defender-assessments.json"))],
        },
        "scoutsuite_blind": engines.scoutsuite_blind_services(fx("scoutsuite-aws.json")),
        "prowler_log": {"text": LOG, "errors": engines.prowler_errors(LOG)},
        "pools": {
            "aws": pool("aws", "000000000000", aws),
            "gcp": pool("gcp", "", engines.parse_prowler_ocsf(fx("prowler-gcp.ocsf.json")) + engines.scc(fx("scc-findings.json"))),
            "azure": pool("azure", "", engines.parse_prowler_ocsf(fx("prowler-azure.ocsf.json"))
                          + engines.defender(fx("defender-assessments.json"))),
        },
        "controls": {k: list(v[:4]) + [v[4]] for k, v in controls.CONTROLS.items()},
        "maps": {"prowler": controls.PROWLER, "scoutsuite": controls.SCOUTSUITE, "securityhub": controls.SECURITYHUB,
                 "scc": controls.SCC, "defender": controls.DEFENDER},
        "pillar_by_prefix": [list(x) for x in controls.PILLAR_BY_PREFIX],
        "cis_versions": controls.CIS_VERSIONS,
        "steampipe": steampipe_queries.QUERIES,
        "version": collector.VERSION,
    }


def render():
    return json.dumps(golden(), indent=1, sort_keys=True) + "\n"


if __name__ == "__main__":
    path = os.path.join(HERE, "golden.json")
    if sys.argv[1:] == ["--check"]:
        current = open(path).read() if os.path.exists(path) else ""
        sys.exit(0 if current == render() else "golden.json is not current: run gen_golden.py")
    with open(path, "w") as f:
        f.write(render())
    print(f"wrote {path}")
