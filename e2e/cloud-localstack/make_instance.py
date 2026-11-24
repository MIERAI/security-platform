"""Write the e2e instance configs: the main one (scanned twice into one ledger) and one per failure scenario.
usage: make_instance.py WORK TOOLS HERE LS_PORT OIDC_PORT MOCK_PORT"""
import json
import os
import shutil
import sys

WORK, TOOLS, HERE, LS, OIDC, MOCK = sys.argv[1:]
ROOT = os.path.dirname(os.path.dirname(HERE))
ISS = f"http://127.0.0.1:{OIDC}"
M = f"http://127.0.0.1:{MOCK}"
WIP = "projects/100000000001/locations/global/workloadIdentityPools/security-platform/providers/local-oidc"
GAUD = "https://iam.googleapis.com/" + WIP


def token(aud, issuer="workload"):
    return {"type": "command", "argv": [os.path.join(HERE, "token.sh"), ISS, issuer, aud]}


def aws(role="security-platform-audit", aud="sts.amazonaws.com", issuer="workload", engines=("prowler", "steampipe", "scoutsuite")):
    return {"provider": "aws", "account_id": "000000000000", "role_arn": f"arn:aws:iam::000000000000:role/{role}",
            "audience": "sts.amazonaws.com", "identity_token": token(aud, issuer), "endpoint_url": f"http://127.0.0.1:{LS}",
            "regions": ["us-east-1"], "engines": list(engines)}


def gcp(project, sa=None, aud=GAUD, precheck=True):
    d = {"provider": "gcp", "project_id": project, "workload_identity_provider": WIP,
         "service_account": sa or f"auditor@{project}.iam.gserviceaccount.com", "identity_token": token(aud),
         "sts_url": M + "/gcp/sts/v1/token", "iamcredentials_url": M + "/gcp/iamcredentials/v1",
         "resourcemanager_url": M + "/gcp/crm/v1", "engines": []}
    if precheck:
        d["audience"] = GAUD
    return d


def azure(sub, client="11111111-1111-4111-8111-111111111111", aud="api://AzureADTokenExchange"):
    return {"provider": "azure", "subscription_id": sub, "tenant_id": "00000000-0000-4000-8000-00000000aaaa",
            "client_id": client, "identity_token": token(aud), "authority_host": M + "/azure/login",
            "arm_url": M + "/azure/arm", "engines": []}


ENGINES = {
    "prowler": {"path": os.path.join(TOOLS, "tools", "prowler", "current", "bin", "prowler"), "timeout": "20m",
                "checks": ["ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22",
                           "ec2_securitygroup_allow_ingress_from_internet_to_all_ports", "s3_bucket_public_access",
                           "s3_bucket_default_encryption", "iam_user_mfa_enabled_console_access",
                           "iam_user_no_setup_initial_access_key", "iam_rotate_access_key_90_days", "iam_root_mfa_enabled",
                           "cloudtrail_multi_region_enabled", "ec2_ebs_public_snapshot", "ec2_ebs_volume_encryption"]},
    "steampipe": {"path": os.path.join(TOOLS, "tools", "steampipe", "current", "bin", "steampipe"),
                  "install_dir": os.path.join(TOOLS, "tools", "steampipe", "current", "home"), "plugin": "aws@1.34.1",
                  "timeout": "5m"},
    "scoutsuite": {"path": os.path.join(TOOLS, "tools", "scoutsuite", "current", "bin", "scout"), "services": ["s3", "ec2", "iam"],
                   "timeout": "10m"}}
for name in ("scc-findings.json", "defender-assessments.json"):      # exports of the native services (fixtures)
    shutil.copy(os.path.join(ROOT, "tests", "fixtures", "cloud", name), os.path.join(WORK, name))
main = {"name": "acme-cloud", "cloud": {
    "accounts": [aws(), gcp("acme-readonly"), gcp("acme-overprivileged"),
                 azure("33333333-3333-4333-8333-333333333333"), azure("44444444-4444-4444-8444-444444444444")],
    "engines": ENGINES,
    "imports": [{"type": "securityhub", "file": os.path.join(WORK, "securityhub.json"), "accounts": ["000000000000"]},
                {"type": "scc", "file": os.path.join(WORK, "scc-findings.json"), "accounts": ["acme-readonly"]},
                {"type": "defender", "file": os.path.join(WORK, "defender-assessments.json"),
                 "accounts": ["33333333-3333-4333-8333-333333333333"]}]}}
json.dump(main, open(os.path.join(WORK, "instance.json"), "w"), indent=1)

FAILURES = {   # name: (account config, expected coverage reason substring)
    "aws-expired-token": (aws(issuer="shortlived", engines=[]), "identity token expired"),
    "aws-wrong-audience": (aws(aud="some-other-audience", engines=[]), "audience mismatch"),
    "aws-missing-role": (aws(role="does-not-exist", engines=[]), "does not exist"),
    "aws-over-privileged": (aws(role="security-platform-overprivileged", engines=["prowler"]), "refused"),
    "gcp-wrong-audience": (gcp("acme-readonly", aud="some-other-audience", precheck=False), "does not match the expected audience"),
    "gcp-denied-impersonation": (gcp("acme-readonly", sa="someone-else@acme-readonly.iam.gserviceaccount.com"), "PERMISSION_DENIED"),
    "gcp-missing-service-account": (gcp("acme-readonly", sa="nobody@acme-readonly.iam.gserviceaccount.com"), "does not exist"),
    "azure-wrong-audience": (azure("33333333-3333-4333-8333-333333333333", aud="some-other-audience"), "AADSTS700212"),
    "azure-unknown-app": (azure("33333333-3333-4333-8333-333333333333", client="99999999-9999-4999-8999-999999999999"), "AADSTS700016"),
}
os.makedirs(os.path.join(WORK, "failures"), exist_ok=True)
for name, (acct, want) in FAILURES.items():
    json.dump({"name": name, "expect": want, "cloud": {"accounts": [acct], "engines": ENGINES}},
              open(os.path.join(WORK, "failures", f"{name}.json"), "w"), indent=1)
print(f"ok   instance: 5 accounts (1 AWS scanned by Prowler + Steampipe + ScoutSuite, 2 GCP, 2 Azure), 3 native imports; "
      f"{len(FAILURES)} failure scenarios")
