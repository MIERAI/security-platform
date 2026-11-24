"""The Steampipe engine's query pack (this product's own SQL over the Steampipe AWS plugin's tables; no Steampipe mod
is used or copied). Each query returns the FAILING resources only, with the columns
    arn (canonical resource id), region, account_id, detail
and names the generic control it checks (controls.CONTROLS) and the cloud service it reads: a query that errors makes
that service a coverage gap, a query that succeeds covers it (0 rows = all its resources pass). `{region}` is the
account's home region.
"""

AWS = [
    {"id": "s3_bucket_public", "control": "cloud.storage_public", "service": "s3", "severity": "critical", "sql": """
select arn, region, account_id, 'bucket policy or ACL grants access to everyone' as detail
from aws_s3_bucket
where not (coalesce(block_public_policy, false) and coalesce(restrict_public_buckets, false))
  and (exists (select 1 from jsonb_array_elements(coalesce(policy_std -> 'Statement', '[]'::jsonb)) s
               where s ->> 'Effect' = 'Allow' and (s -> 'Principal' -> 'AWS') ? '*')
       or exists (select 1 from jsonb_array_elements(coalesce(acl -> 'Grants', '[]'::jsonb)) g
                  where g -> 'Grantee' ->> 'URI' like '%/global/AllUsers'))"""},
    {"id": "s3_bucket_unencrypted", "control": "cloud.storage_unencrypted", "service": "s3", "severity": "medium", "sql": """
select arn, region, account_id, 'no default encryption configuration' as detail
from aws_s3_bucket where server_side_encryption_configuration is null
   or jsonb_array_length(coalesce(server_side_encryption_configuration -> 'Rules', '[]'::jsonb)) = 0"""},
    {"id": "sg_admin_port_open", "control": "cloud.firewall_admin_port_open", "service": "ec2", "severity": "high", "sql": """
select distinct 'arn:aws:ec2:' || region || ':' || account_id || ':security-group/' || group_id as arn, region, account_id,
       'ingress ' || ip_protocol || ' ' || coalesce(from_port::text, '*') || '-' || coalesce(to_port::text, '*') || ' from '
       || coalesce(cidr_ipv4::text, cidr_ipv6::text) as detail
from aws_vpc_security_group_rule
where not is_egress and (cidr_ipv4 = '0.0.0.0/0' or cidr_ipv6 = '::/0')
  and (ip_protocol = '-1' or (ip_protocol = 'tcp' and ((from_port <= 22 and to_port >= 22) or (from_port <= 3389 and to_port >= 3389))))"""},
    {"id": "iam_user_console_without_mfa", "control": "cloud.user_without_mfa", "service": "iam", "severity": "high", "sql": """
select arn, 'global' as region, account_id, 'console password without MFA' as detail
from aws_iam_user where login_profile is not null and not mfa_enabled"""},
    {"id": "iam_access_key_older_than_90_days", "control": "cloud.access_key_old", "service": "iam", "severity": "medium", "sql": """
select 'arn:aws:iam::' || account_id || ':user/' || user_name as arn, 'global' as region, account_id,
       'active access key created ' || create_date::date as detail
from aws_iam_access_key where status = 'Active' and create_date < now() - interval '90 days'"""},
    {"id": "iam_root_without_mfa", "control": "cloud.root_mfa_disabled", "service": "iam", "severity": "critical", "sql": """
select 'arn:aws:iam::' || account_id || ':root' as arn, 'global' as region, account_id, 'root account MFA disabled' as detail
from aws_iam_account_summary where not account_mfa_enabled"""},
    {"id": "iam_root_access_keys", "control": "cloud.root_access_key", "service": "iam", "severity": "critical", "sql": """
select 'arn:aws:iam::' || account_id || ':root' as arn, 'global' as region, account_id, 'root access keys present' as detail
from aws_iam_account_summary where account_access_keys_present > 0"""},
    {"id": "cloudtrail_no_multi_region_trail", "control": "cloud.audit_log_disabled", "service": "cloudtrail", "severity": "high", "sql": """
select 'arn:aws:cloudtrail:{region}:' || account_id || ':trail' as arn, '{region}' as region, account_id,
       'no logging multi-region trail' as detail
from aws_account
where not exists (select 1 from aws_cloudtrail_trail t where t.is_multi_region_trail and t.is_logging)"""},
    {"id": "ebs_volume_unencrypted", "control": "cloud.volume_unencrypted", "service": "ec2", "severity": "medium", "sql": """
select arn, region, account_id, 'volume not encrypted' as detail from aws_ebs_volume where not encrypted"""},
    {"id": "ebs_snapshot_public", "control": "cloud.snapshot_public", "service": "ec2", "severity": "critical", "sql": """
select arn, region, account_id, 'snapshot shared with all accounts' as detail
from aws_ebs_snapshot where create_volume_permissions @> '[{"Group": "all"}]'"""},
]

QUERIES = {"aws": AWS}
