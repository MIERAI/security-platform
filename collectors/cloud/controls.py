"""Generic cloud controls and how every engine's / native service's own check ids map onto them (data only).

A control is the PROBLEM, not the tool: `cloud.firewall_admin_port_open` is the same finding whether Prowler,
Steampipe, ScoutSuite, Security Hub, Security Command Center or Defender for Cloud saw it, so the same resource with
the same control from several sources is ONE finding (collector.py merges them) and SLIs/dashboards/scorecard work for
every engine. Each control has its pillar (network | device | people | software), its ledger layer, and the CIS
Foundations Benchmark sections it corresponds to per provider (benchmark versions in CIS_VERSIONS; the per-finding
references reported by an engine are kept as they come, see `refs`).

An engine check that maps to no control is still reported (`cloud.<provider>.<engine check id>`), classified into a
pillar by PILLAR_BY_PREFIX: nothing an engine found is dropped.
"""

CIS_VERSIONS = {"aws": "3.0", "gcp": "2.0", "azure": "2.0"}

# id: (pillar, layer, title, remediation, {provider: [CIS benchmark sections]})
CONTROLS = {
    # ---- network --------------------------------------------------------------------------------------------
    "cloud.firewall_admin_port_open": ("network", "network", "firewall rule allows SSH/RDP (admin ports) from the internet",
        "restrict the rule's source to known addresses or use a bastion/SSM/IAP instead of opening admin ports",
        {"aws": ["5.1", "5.2", "5.3"], "gcp": ["3.6", "3.7"], "azure": ["6.1", "6.2"]}),
    "cloud.firewall_open_to_internet": ("network", "network", "firewall rule allows all ports from the internet",
        "allow only the ports the service needs, from the sources that need them", {"aws": ["5.2"], "gcp": ["3.6"], "azure": ["6.1"]}),
    "cloud.public_endpoint": ("network", "network", "resource has a public endpoint/address",
        "remove the public address or put the resource behind a load balancer / private endpoint", {}),
    # ---- device / resource ------------------------------------------------------------------------------------
    "cloud.volume_unencrypted": ("device", "host", "block volume or snapshot is not encrypted",
        "enable encryption by default for new volumes; migrate data to encrypted volumes",
        {"aws": ["2.2.1"], "gcp": ["4.7"], "azure": ["7.2"]}),
    "cloud.instance_unpatched": ("device", "host", "instance is missing patches or is not under patch management",
        "bring the instance under the provider's patch management and apply missing updates", {}),
    "cloud.instance_metadata_v1": ("device", "host", "instance metadata service allows unauthenticated v1 requests",
        "require IMDSv2 (http tokens required)", {"aws": ["5.6"]}),
    # ---- people / identity ---------------------------------------------------------------------------------------
    "cloud.user_without_mfa": ("people", "identity", "user with console/password access has no MFA",
        "enable MFA (phishing-resistant where possible) for every human user; enforce it by policy",
        {"aws": ["1.10"], "gcp": ["1.2"], "azure": ["1.1.1", "1.1.2"]}),
    "cloud.root_mfa_disabled": ("people", "identity", "root / break-glass account has no MFA",
        "enable hardware or passkey MFA on the root account", {"aws": ["1.5", "1.6"]}),
    "cloud.root_access_key": ("people", "identity", "root account has access keys", "delete root access keys", {"aws": ["1.4"]}),
    "cloud.root_used": ("people", "identity", "root account was used recently",
        "use named, least-privilege identities; keep root for break-glass", {"aws": ["1.7"]}),
    "cloud.access_key_old": ("people", "identity", "long-lived access key / service-account key not rotated in 90 days",
        "replace long-lived keys with federation/roles; otherwise rotate every 90 days",
        {"aws": ["1.14"], "gcp": ["1.7"]}),
    "cloud.credential_unused": ("people", "identity", "credential unused for 45+ days", "disable and delete unused credentials",
        {"aws": ["1.12"]}),
    "cloud.service_account_key_user_managed": ("people", "identity", "service account has user-managed (long-lived) keys",
        "use workload identity federation / attached service accounts instead of keys", {"gcp": ["1.4"]}),
    "cloud.admin_privileges_broad": ("people", "identity", "identity has administrative privileges it should not need",
        "grant least privilege; no admin roles on workload identities", {"aws": ["1.16"], "gcp": ["1.5"], "azure": ["1.23"]}),
    "cloud.password_policy_weak": ("people", "identity", "account password policy is weaker than the benchmark",
        "set a password policy (length >= 14, reuse prevention) or move humans to SSO", {"aws": ["1.8", "1.9"]}),
    "cloud.platform_credential_over_privileged": ("people", "identity",
        "the security platform's own cloud credential can write (expected read-only)",
        "detach every policy/role except the read-only audit ones (docs/cloud.md: permissions)", {}),
    # ---- software / data ------------------------------------------------------------------------------------------
    "cloud.storage_public": ("software", "data-secrets", "storage bucket/container is publicly accessible",
        "block public access at account and bucket level; share through signed URLs or a CDN with origin access",
        {"aws": ["2.1.4"], "gcp": ["5.1"], "azure": ["3.7"]}),
    "cloud.storage_unencrypted": ("software", "data-secrets", "storage has no default encryption configured",
        "enable default encryption (provider-managed or customer-managed keys)", {"azure": ["3.2"]}),
    "cloud.storage_insecure_transport": ("software", "data-secrets", "storage accepts unencrypted (HTTP) requests",
        "deny requests without TLS (aws:SecureTransport / secure transfer required)", {"aws": ["2.1.1"], "azure": ["3.1"]}),
    "cloud.snapshot_public": ("software", "data-secrets", "snapshot or machine image is shared publicly",
        "remove public sharing; block public sharing at account level", {}),
    "cloud.audit_log_disabled": ("software", "detection", "control-plane audit logging is not enabled everywhere",
        "enable a multi-region/organisation audit trail (CloudTrail, Cloud Audit Logs, Activity Log export)",
        {"aws": ["3.1"], "gcp": ["2.1"], "azure": ["5.1.1"]}),
}

PROWLER = {
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22": "cloud.firewall_admin_port_open",
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389": "cloud.firewall_admin_port_open",
    "ec2_securitygroup_allow_ingress_from_internet_to_all_ports": "cloud.firewall_open_to_internet",
    "ec2_networkacl_allow_ingress_tcp_port_22": "cloud.firewall_admin_port_open",
    "ec2_networkacl_allow_ingress_tcp_port_3389": "cloud.firewall_admin_port_open",
    "ec2_networkacl_allow_ingress_any_port": "cloud.firewall_open_to_internet",
    "ec2_instance_public_ip": "cloud.public_endpoint",
    "rds_instance_no_public_access": "cloud.public_endpoint",
    "compute_firewall_ssh_access_from_the_internet_allowed": "cloud.firewall_admin_port_open",
    "compute_firewall_rdp_access_from_the_internet_allowed": "cloud.firewall_admin_port_open",
    "compute_instance_public_ip": "cloud.public_endpoint",
    "network_ssh_internet_access_restricted": "cloud.firewall_admin_port_open",
    "network_rdp_internet_access_restricted": "cloud.firewall_admin_port_open",
    "ec2_ebs_volume_encryption": "cloud.volume_unencrypted",
    "ec2_ebs_default_encryption": "cloud.volume_unencrypted",
    "ec2_ebs_snapshots_encrypted": "cloud.volume_unencrypted",
    "ssm_managed_compliant_patching": "cloud.instance_unpatched",
    "defender_ensure_system_updates_are_applied": "cloud.instance_unpatched",
    "ec2_instance_imdsv2_enabled": "cloud.instance_metadata_v1",
    "iam_user_mfa_enabled_console_access": "cloud.user_without_mfa",
    "entra_non_privileged_user_has_mfa": "cloud.user_without_mfa",
    "entra_privileged_user_has_mfa": "cloud.user_without_mfa",
    "iam_root_mfa_enabled": "cloud.root_mfa_disabled",
    "iam_root_hardware_mfa_enabled": "cloud.root_mfa_disabled",
    "iam_no_root_access_key": "cloud.root_access_key",
    "iam_avoid_root_usage": "cloud.root_used",
    "iam_rotate_access_key_90_days": "cloud.access_key_old",
    "iam_sa_user_managed_key_rotate_90_days": "cloud.access_key_old",
    "iam_user_accesskey_unused": "cloud.credential_unused",
    "iam_user_console_access_unused": "cloud.credential_unused",
    "iam_sa_user_managed_key_unused": "cloud.credential_unused",
    "iam_sa_no_user_managed_keys": "cloud.service_account_key_user_managed",
    "iam_sa_no_administrative_privileges": "cloud.admin_privileges_broad",
    "iam_password_policy_minimum_length_14": "cloud.password_policy_weak",
    "iam_password_policy_reuse_24": "cloud.password_policy_weak",
    "s3_bucket_public_access": "cloud.storage_public",
    "s3_bucket_policy_public_write_access": "cloud.storage_public",
    "s3_bucket_public_list_acl": "cloud.storage_public",
    "s3_bucket_public_write_acl": "cloud.storage_public",
    "cloudstorage_bucket_public_access": "cloud.storage_public",
    "storage_blob_public_access_level_is_disabled": "cloud.storage_public",
    "s3_bucket_default_encryption": "cloud.storage_unencrypted",
    "s3_bucket_secure_transport_policy": "cloud.storage_insecure_transport",
    "storage_secure_transfer_required_is_enabled": "cloud.storage_insecure_transport",
    "ec2_ebs_public_snapshot": "cloud.snapshot_public",
    "rds_snapshots_public_access": "cloud.snapshot_public",
    "cloudtrail_multi_region_enabled": "cloud.audit_log_disabled",
    "cloudtrail_multi_region_enabled_logging_management_events": "cloud.audit_log_disabled",
    "iam_audit_logs_enabled": "cloud.audit_log_disabled",
    "logging_sink_created": "cloud.audit_log_disabled",
    "monitor_diagnostic_settings_exists": "cloud.audit_log_disabled",
}

# Steampipe: the query pack in steampipe_queries.py names its control directly. ScoutSuite rule ids:
SCOUTSUITE = {
    "ec2-security-group-opens-SSH-port-to-all": "cloud.firewall_admin_port_open",
    "ec2-security-group-opens-RDP-port-to-all": "cloud.firewall_admin_port_open",
    "ec2-security-group-opens-all-ports-to-all": "cloud.firewall_open_to_internet",
    "ec2-ebs-volume-not-encrypted": "cloud.volume_unencrypted",
    "ec2-ebs-snapshot-not-encrypted": "cloud.volume_unencrypted",
    "ec2-ebs-snapshot-public": "cloud.snapshot_public",
    "iam-user-without-mfa": "cloud.user_without_mfa",
    "iam-root-account-no-mfa": "cloud.root_mfa_disabled",
    "iam-root-account-with-active-keys": "cloud.root_access_key",
    "iam-root-account-used-recently": "cloud.root_used",
    "iam-user-no-Active-key-rotation": "cloud.access_key_old",
    "iam-user-unused-access-key-initial-setup": "cloud.credential_unused",
    "iam-password-policy-minimum-length": "cloud.password_policy_weak",
    "iam-password-policy-reuse-enabled": "cloud.password_policy_weak",
    "s3-bucket-world-Policy-Star": "cloud.storage_public",
    "s3-bucket-world-Get-policy": "cloud.storage_public",
    "s3-bucket-world-Put-policy": "cloud.storage_public",
    "s3-bucket-world-List-policy": "cloud.storage_public",
    "s3-bucket-AllUsers-read": "cloud.storage_public",
    "s3-bucket-AllUsers-write": "cloud.storage_public",
    "s3-bucket-no-default-encryption": "cloud.storage_unencrypted",
    "s3-bucket-allowing-cleartext": "cloud.storage_insecure_transport",
    "cloudtrail-not-configured": "cloud.audit_log_disabled",
    "computeengine-firewall-rule-allows-port-range": "cloud.firewall_open_to_internet",
    "cloudstorage-bucket-allUsers": "cloud.storage_public",
    "network-security-group-ssh-port-open-to-all": "cloud.firewall_admin_port_open",
    "storageaccount-public-blob-container": "cloud.storage_public",
}

# AWS Security Hub (ASFF Compliance.SecurityControlId, consolidated control ids)
SECURITYHUB = {
    "EC2.13": "cloud.firewall_admin_port_open", "EC2.14": "cloud.firewall_admin_port_open",
    "EC2.21": "cloud.firewall_admin_port_open", "EC2.19": "cloud.firewall_open_to_internet",
    "EC2.9": "cloud.public_endpoint", "RDS.2": "cloud.public_endpoint",
    "EC2.3": "cloud.volume_unencrypted", "EC2.7": "cloud.volume_unencrypted",
    "SSM.2": "cloud.instance_unpatched", "EC2.8": "cloud.instance_metadata_v1",
    "IAM.5": "cloud.user_without_mfa", "IAM.19": "cloud.user_without_mfa",
    "IAM.9": "cloud.root_mfa_disabled", "IAM.6": "cloud.root_mfa_disabled", "IAM.4": "cloud.root_access_key",
    "IAM.3": "cloud.access_key_old", "IAM.8": "cloud.credential_unused", "IAM.22": "cloud.credential_unused",
    "IAM.7": "cloud.password_policy_weak", "IAM.15": "cloud.password_policy_weak", "IAM.16": "cloud.password_policy_weak",
    "S3.2": "cloud.storage_public", "S3.3": "cloud.storage_public",
    "S3.4": "cloud.storage_unencrypted", "S3.5": "cloud.storage_insecure_transport",
    "EC2.1": "cloud.snapshot_public", "RDS.1": "cloud.snapshot_public",
    "CloudTrail.1": "cloud.audit_log_disabled", "CloudTrail.3": "cloud.audit_log_disabled",
}

# GCP Security Command Center (Security Health Analytics finding categories)
SCC = {
    "OPEN_SSH_PORT": "cloud.firewall_admin_port_open", "OPEN_RDP_PORT": "cloud.firewall_admin_port_open",
    "OPEN_FIREWALL": "cloud.firewall_open_to_internet", "PUBLIC_IP_ADDRESS": "cloud.public_endpoint",
    "PUBLIC_SQL_INSTANCE": "cloud.public_endpoint", "OS_VULNERABILITY": "cloud.instance_unpatched",
    "MFA_NOT_ENFORCED": "cloud.user_without_mfa", "SERVICE_ACCOUNT_KEY_NOT_ROTATED": "cloud.access_key_old",
    "USER_MANAGED_SERVICE_ACCOUNT_KEY": "cloud.service_account_key_user_managed",
    "ADMIN_SERVICE_ACCOUNT": "cloud.admin_privileges_broad", "PUBLIC_BUCKET_ACL": "cloud.storage_public",
    "AUDIT_LOGGING_DISABLED": "cloud.audit_log_disabled", "PUBLIC_DATASET": "cloud.storage_public",
}

# Microsoft Defender for Cloud assessments (displayName, lower case: the assessment keys are GUIDs)
DEFENDER = {
    "management ports should be closed on your virtual machines": "cloud.firewall_admin_port_open",
    "internet-facing virtual machines should be protected with network security groups": "cloud.public_endpoint",
    "system updates should be installed on your machines": "cloud.instance_unpatched",
    "machines should be configured to periodically check for missing system updates": "cloud.instance_unpatched",
    "accounts with owner permissions on azure resources should be mfa enabled": "cloud.user_without_mfa",
    "accounts with write permissions on azure resources should be mfa enabled": "cloud.user_without_mfa",
    "storage account public access should be disallowed": "cloud.storage_public",
    "secure transfer to storage accounts should be enabled": "cloud.storage_insecure_transport",
    "virtual machines should encrypt temp disks, caches, and data flows between compute and storage resources": "cloud.volume_unencrypted",
}

# Pillar of an UNMAPPED engine check by its id prefix (first match), then by service.
PILLAR_BY_PREFIX = [
    ("ec2_securitygroup", "network"), ("ec2_networkacl", "network"), ("ec2_elastic_ip", "network"), ("vpc", "network"),
    ("elb", "network"), ("cloudfront", "network"), ("apigateway", "network"), ("route53", "network"),
    ("compute_firewall", "network"), ("compute_network", "network"), ("network", "network"), ("dns", "network"),
    ("ec2_instance", "device"), ("ec2_ebs", "device"), ("ec2_ami", "software"), ("ssm", "device"), ("autoscaling", "device"),
    ("compute_instance", "device"), ("vm", "device"), ("gke", "device"), ("eks", "device"), ("aks", "device"),
    ("iam", "people"), ("organizations", "people"), ("sso", "people"), ("accessanalyzer", "people"), ("entra", "people"),
    ("account", "people"),
]
PILLAR_LAYER = {"network": "network", "device": "host", "people": "identity", "software": "data-secrets"}


def control_for(source, check):
    table = {"prowler": PROWLER, "scoutsuite": SCOUTSUITE, "securityhub": SECURITYHUB, "scc": SCC,
             "defender": DEFENDER}.get(source, {})
    return table.get(check if source != "defender" else check.lower())


def classify(provider, check_id, control=None):
    """-> (check name, pillar, layer, title, remediation, cis sections {provider: [..]})."""
    if control:
        pillar, layer, title, fix, cis = CONTROLS[control]
        return control, pillar, layer, title, fix, cis
    pillar = next((p for pre, p in PILLAR_BY_PREFIX if check_id.startswith(pre)), "software")
    name = "cloud." + provider + "." + "".join(ch if ch.isalnum() or ch in "_.-" else "_" for ch in check_id.lower())
    return name, pillar, PILLAR_LAYER[pillar], None, None, {}
