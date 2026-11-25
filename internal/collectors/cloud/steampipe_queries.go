package cloud

// steampipeQuery is one query of the Steampipe engine's pack: this product's own SQL over the Steampipe AWS plugin's
// tables (no Steampipe mod is used or copied). It returns the FAILING resources only, with the columns arn, region,
// account_id, detail; `{region}` is the account's home region. collectors/cloud/steampipe_queries.py is the same pack
// (TestSteampipeQueriesMatchPython keeps them equal).
type steampipeQuery struct {
	ID, Control, Service, Severity, SQL string
}

// steampipeQueries is the pack per provider.
func steampipeQueries() map[string][]steampipeQuery {
	return map[string][]steampipeQuery{
		"aws": {
			{ID: "s3_bucket_public", Control: "cloud.storage_public", Service: "s3", Severity: "critical", SQL: `
select arn, region, account_id, 'bucket policy or ACL grants access to everyone' as detail
from aws_s3_bucket
where not (coalesce(block_public_policy, false) and coalesce(restrict_public_buckets, false))
  and (exists (select 1 from jsonb_array_elements(coalesce(policy_std -> 'Statement', '[]'::jsonb)) s
               where s ->> 'Effect' = 'Allow' and (s -> 'Principal' -> 'AWS') ? '*')
       or exists (select 1 from jsonb_array_elements(coalesce(acl -> 'Grants', '[]'::jsonb)) g
                  where g -> 'Grantee' ->> 'URI' like '%/global/AllUsers'))`},
			{ID: "s3_bucket_unencrypted", Control: "cloud.storage_unencrypted", Service: "s3", Severity: "medium", SQL: `
select arn, region, account_id, 'no default encryption configuration' as detail
from aws_s3_bucket where server_side_encryption_configuration is null
   or jsonb_array_length(coalesce(server_side_encryption_configuration -> 'Rules', '[]'::jsonb)) = 0`},
			{ID: "sg_admin_port_open", Control: "cloud.firewall_admin_port_open", Service: "ec2", Severity: "high", SQL: `
select distinct 'arn:aws:ec2:' || region || ':' || account_id || ':security-group/' || group_id as arn, region, account_id,
       'ingress ' || ip_protocol || ' ' || coalesce(from_port::text, '*') || '-' || coalesce(to_port::text, '*') || ' from '
       || coalesce(cidr_ipv4::text, cidr_ipv6::text) as detail
from aws_vpc_security_group_rule
where not is_egress and (cidr_ipv4 = '0.0.0.0/0' or cidr_ipv6 = '::/0')
  and (ip_protocol = '-1' or (ip_protocol = 'tcp' and ((from_port <= 22 and to_port >= 22) or (from_port <= 3389 and to_port >= 3389))))`},
			{ID: "iam_user_console_without_mfa", Control: "cloud.user_without_mfa", Service: "iam", Severity: "high", SQL: `
select arn, 'global' as region, account_id, 'console password without MFA' as detail
from aws_iam_user where login_profile is not null and not mfa_enabled`},
			{ID: "iam_access_key_older_than_90_days", Control: "cloud.access_key_old", Service: "iam", Severity: "medium", SQL: `
select 'arn:aws:iam::' || account_id || ':user/' || user_name as arn, 'global' as region, account_id,
       'active access key created ' || create_date::date as detail
from aws_iam_access_key where status = 'Active' and create_date < now() - interval '90 days'`},
			{ID: "iam_root_without_mfa", Control: "cloud.root_mfa_disabled", Service: "iam", Severity: "critical", SQL: `
select 'arn:aws:iam::' || account_id || ':root' as arn, 'global' as region, account_id, 'root account MFA disabled' as detail
from aws_iam_account_summary where not account_mfa_enabled`},
			{ID: "iam_root_access_keys", Control: "cloud.root_access_key", Service: "iam", Severity: "critical", SQL: `
select 'arn:aws:iam::' || account_id || ':root' as arn, 'global' as region, account_id, 'root access keys present' as detail
from aws_iam_account_summary where account_access_keys_present > 0`},
			{ID: "cloudtrail_no_multi_region_trail", Control: "cloud.audit_log_disabled", Service: "cloudtrail", Severity: "high", SQL: `
select 'arn:aws:cloudtrail:{region}:' || account_id || ':trail' as arn, '{region}' as region, account_id,
       'no logging multi-region trail' as detail
from aws_account
where not exists (select 1 from aws_cloudtrail_trail t where t.is_multi_region_trail and t.is_logging)`},
			{ID: "ebs_volume_unencrypted", Control: "cloud.volume_unencrypted", Service: "ec2", Severity: "medium", SQL: `
select arn, region, account_id, 'volume not encrypted' as detail from aws_ebs_volume where not encrypted`},
			{ID: "ebs_snapshot_public", Control: "cloud.snapshot_public", Service: "ec2", Severity: "critical", SQL: `
select arn, region, account_id, 'snapshot shared with all accounts' as detail
from aws_ebs_snapshot where create_volume_permissions @> '[{"Group": "all"}]'`},
		},
	}
}
