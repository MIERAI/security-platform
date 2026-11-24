"""Seed / fix the fictional company's LocalStack account (test SETUP, run as the account's admin with LocalStack's
dummy credentials - never by the platform), and write the Security Hub export the e2e imports.

  seed.py seed               the platform's roles + deliberate misconfigurations     (Prowler's env: boto3)
  seed.py fix                fix three of them                                         (Prowler's env: boto3)
  seed.py asff FILE failed|passed   an ASFF export for the seeded resources           (any python)
"""
import json
import os
import sys

WORK = os.environ["SP_E2E_WORK"]
STATE = os.path.join(WORK, "seed.json")
ACCOUNT = "000000000000"                       # LocalStack's default account id


def clients():
    import boto3
    kw = dict(endpoint_url=os.environ["SP_E2E_LS"], region_name="us-east-1", aws_access_key_id="test",
              aws_secret_access_key="test")      # LocalStack's documented dummy credentials (test setup only)
    return boto3.client("iam", **kw), boto3.client("s3", **kw), boto3.client("ec2", **kw)


def seed():
    iam, s3, ec2 = clients()
    issuer = os.environ["SP_E2E_OIDC"].split("://", 1)[1] + "/workload"
    oidc = iam.create_open_id_connect_provider(Url=f"http://{issuer}", ClientIDList=["sts.amazonaws.com"],
                                               ThumbprintList=["0" * 40])["OpenIDConnectProviderArn"]
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Federated": oidc},
             "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"StringEquals": {
                 f"{issuer}:aud": "sts.amazonaws.com", f"{issuer}:sub": "system:serviceaccount:security:scanner"}}}]}
    for role, policies in (("security-platform-audit", ["SecurityAudit", "job-function/ViewOnlyAccess"]),
                           ("security-platform-overprivileged", ["SecurityAudit", "AdministratorAccess"])):
        iam.create_role(RoleName=role, AssumeRolePolicyDocument=json.dumps(trust), MaxSessionDuration=3600)
        for p in policies:
            iam.attach_role_policy(RoleName=role, PolicyArn=f"arn:aws:iam::aws:policy/{p}")
    # misconfigurations
    s3.create_bucket(Bucket="acme-public-assets")
    s3.put_public_access_block(Bucket="acme-public-assets", PublicAccessBlockConfiguration=dict(
        BlockPublicAcls=False, IgnorePublicAcls=False, BlockPublicPolicy=False, RestrictPublicBuckets=False))
    s3.put_bucket_policy(Bucket="acme-public-assets", Policy=json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::acme-public-assets/*"}]}))
    s3.create_bucket(Bucket="acme-unencrypted-logs")
    s3.delete_bucket_encryption(Bucket="acme-unencrypted-logs")
    vpc = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    sg = ec2.create_security_group(GroupName="legacy-ssh", Description="legacy admin access", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    iam.create_user(UserName="legacy-deployer")
    iam.create_access_key(UserName="legacy-deployer")          # the key itself is discarded: nobody needs it
    iam.create_login_profile(UserName="legacy-deployer", Password="Seeded-" + os.urandom(8).hex() + "!")
    # CloudTrail: deliberately none (LocalStack community does not emulate the CloudTrail API at all)
    json.dump({"sg": sg, "vpc": vpc}, open(STATE, "w"))
    print(f"ok   seeded: public bucket, unencrypted bucket, {sg} open to 0.0.0.0/0:22, console user with access key "
          "and no MFA, no CloudTrail; roles security-platform-audit (SecurityAudit+ViewOnlyAccess) and "
          "security-platform-overprivileged (+AdministratorAccess)")


def fix():
    iam, s3, ec2 = clients()
    st = json.load(open(STATE))
    s3.delete_bucket_policy(Bucket="acme-public-assets")
    s3.put_public_access_block(Bucket="acme-public-assets", PublicAccessBlockConfiguration=dict(
        BlockPublicAcls=True, IgnorePublicAcls=True, BlockPublicPolicy=True, RestrictPublicBuckets=True))
    ec2.revoke_security_group_ingress(GroupId=st["sg"], IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    iam.delete_login_profile(UserName="legacy-deployer")        # no console password -> the MFA check passes
    print("ok   fixed: bucket private (policy removed, block public access on), SSH rule revoked, console login removed")


def asff(path, status):
    st = json.load(open(STATE))
    comp = "FAILED" if status == "failed" else "PASSED"
    f = lambda cid, title, rtype, rid, cis=None: {  # noqa: E731
        "SchemaVersion": "2018-10-08", "Id": f"arn:aws:securityhub:us-east-1:{ACCOUNT}:security-control/{cid}/finding/e2e",
        "GeneratorId": f"security-control/{cid}", "AwsAccountId": ACCOUNT, "Region": "us-east-1", "Title": title,
        "Severity": {"Label": "HIGH"}, "Compliance": dict({"Status": comp, "SecurityControlId": cid},
                                                          **({"RelatedRequirements": cis} if cis else {})),
        "Resources": [{"Type": rtype, "Id": rid, "Region": "us-east-1"}], "Workflow": {"Status": "NEW"}, "RecordState": "ACTIVE"}
    doc = {"Findings": [
        f("EC2.13", "Security groups should not allow ingress from 0.0.0.0/0 or ::/0 to port 22", "AwsEc2SecurityGroup",
          f"arn:aws:ec2:us-east-1:{ACCOUNT}:security-group/{st['sg']}", ["CIS AWS Foundations Benchmark v1.2.0/4.1"]),
        f("S3.2", "S3 general purpose buckets should block public read access", "AwsS3Bucket", "arn:aws:s3:::acme-public-assets")]}
    json.dump(doc, open(path, "w"), indent=1)


if __name__ == "__main__":
    {"seed": lambda: seed(), "fix": lambda: fix(), "asff": lambda: asff(sys.argv[2], sys.argv[3])}[sys.argv[1]]()
