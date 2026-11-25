package cloud

// The engines' and native services' own check ids -> generic controls (collectors/cloud/controls.py: the same
// data; TestControlTablesMatchPython keeps them equal).

// prowlerControls: Prowler check ids.
func prowlerControls() map[string]string {
	m := prowlerNetworkDeviceControls()
	for k, v := range prowlerIdentityDataControls() {
		m[k] = v
	}
	return m
}

func prowlerNetworkDeviceControls() map[string]string {
	return map[string]string{
		"ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22":   "cloud.firewall_admin_port_open",
		"ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389": "cloud.firewall_admin_port_open",
		"ec2_securitygroup_allow_ingress_from_internet_to_all_ports":     "cloud.firewall_open_to_internet",
		"ec2_networkacl_allow_ingress_tcp_port_22":                       "cloud.firewall_admin_port_open",
		"ec2_networkacl_allow_ingress_tcp_port_3389":                     "cloud.firewall_admin_port_open",
		"ec2_networkacl_allow_ingress_any_port":                          "cloud.firewall_open_to_internet",
		"ec2_instance_public_ip":                                         "cloud.public_endpoint",
		"rds_instance_no_public_access":                                  "cloud.public_endpoint",
		"compute_firewall_ssh_access_from_the_internet_allowed":          "cloud.firewall_admin_port_open",
		"compute_firewall_rdp_access_from_the_internet_allowed":          "cloud.firewall_admin_port_open",
		"compute_instance_public_ip":                                     "cloud.public_endpoint",
		"network_ssh_internet_access_restricted":                         "cloud.firewall_admin_port_open",
		"network_rdp_internet_access_restricted":                         "cloud.firewall_admin_port_open",
		"ec2_ebs_volume_encryption":                                      "cloud.volume_unencrypted",
		"ec2_ebs_default_encryption":                                     "cloud.volume_unencrypted",
		"ec2_ebs_snapshots_encrypted":                                    "cloud.volume_unencrypted",
		"ssm_managed_compliant_patching":                                 "cloud.instance_unpatched",
		"defender_ensure_system_updates_are_applied":                     "cloud.instance_unpatched",
		"ec2_instance_imdsv2_enabled":                                    "cloud.instance_metadata_v1",
		"iam_user_mfa_enabled_console_access":                            "cloud.user_without_mfa",
		"entra_non_privileged_user_has_mfa":                              "cloud.user_without_mfa",
		"entra_privileged_user_has_mfa":                                  "cloud.user_without_mfa",
		"iam_root_mfa_enabled":                                           "cloud.root_mfa_disabled",
		"iam_root_hardware_mfa_enabled":                                  "cloud.root_mfa_disabled",
		"iam_no_root_access_key":                                         "cloud.root_access_key",
	}
}

func prowlerIdentityDataControls() map[string]string {
	return map[string]string{
		"iam_avoid_root_usage":                                      "cloud.root_used",
		"iam_rotate_access_key_90_days":                             "cloud.access_key_old",
		"iam_sa_user_managed_key_rotate_90_days":                    "cloud.access_key_old",
		"iam_user_accesskey_unused":                                 "cloud.credential_unused",
		"iam_user_console_access_unused":                            "cloud.credential_unused",
		"iam_sa_user_managed_key_unused":                            "cloud.credential_unused",
		"iam_sa_no_user_managed_keys":                               "cloud.service_account_key_user_managed",
		"iam_sa_no_administrative_privileges":                       "cloud.admin_privileges_broad",
		"iam_password_policy_minimum_length_14":                     "cloud.password_policy_weak",
		"iam_password_policy_reuse_24":                              "cloud.password_policy_weak",
		"s3_bucket_public_access":                                   "cloud.storage_public",
		"s3_bucket_policy_public_write_access":                      "cloud.storage_public",
		"s3_bucket_public_list_acl":                                 "cloud.storage_public",
		"s3_bucket_public_write_acl":                                "cloud.storage_public",
		"cloudstorage_bucket_public_access":                         "cloud.storage_public",
		"storage_blob_public_access_level_is_disabled":              "cloud.storage_public",
		"s3_bucket_default_encryption":                              "cloud.storage_unencrypted",
		"s3_bucket_secure_transport_policy":                         "cloud.storage_insecure_transport",
		"storage_secure_transfer_required_is_enabled":               "cloud.storage_insecure_transport",
		"ec2_ebs_public_snapshot":                                   "cloud.snapshot_public",
		"rds_snapshots_public_access":                               "cloud.snapshot_public",
		"cloudtrail_multi_region_enabled":                           "cloud.audit_log_disabled",
		"cloudtrail_multi_region_enabled_logging_management_events": "cloud.audit_log_disabled",
		"iam_audit_logs_enabled":                                    "cloud.audit_log_disabled",
		"logging_sink_created":                                      "cloud.audit_log_disabled",
		"monitor_diagnostic_settings_exists":                        "cloud.audit_log_disabled",
	}
}

// scoutControls: ScoutSuite rule ids (Steampipe queries name their control directly).
func scoutControls() map[string]string {
	return map[string]string{
		"ec2-security-group-opens-SSH-port-to-all":      "cloud.firewall_admin_port_open",
		"ec2-security-group-opens-RDP-port-to-all":      "cloud.firewall_admin_port_open",
		"ec2-security-group-opens-all-ports-to-all":     "cloud.firewall_open_to_internet",
		"ec2-ebs-volume-not-encrypted":                  "cloud.volume_unencrypted",
		"ec2-ebs-snapshot-not-encrypted":                "cloud.volume_unencrypted",
		"ec2-ebs-snapshot-public":                       "cloud.snapshot_public",
		"iam-user-without-mfa":                          "cloud.user_without_mfa",
		"iam-root-account-no-mfa":                       "cloud.root_mfa_disabled",
		"iam-root-account-with-active-keys":             "cloud.root_access_key",
		"iam-root-account-used-recently":                "cloud.root_used",
		"iam-user-no-Active-key-rotation":               "cloud.access_key_old",
		"iam-user-unused-access-key-initial-setup":      "cloud.credential_unused",
		"iam-password-policy-minimum-length":            "cloud.password_policy_weak",
		"iam-password-policy-reuse-enabled":             "cloud.password_policy_weak",
		"s3-bucket-world-Policy-Star":                   "cloud.storage_public",
		"s3-bucket-world-Get-policy":                    "cloud.storage_public",
		"s3-bucket-world-Put-policy":                    "cloud.storage_public",
		"s3-bucket-world-List-policy":                   "cloud.storage_public",
		"s3-bucket-AllUsers-read":                       "cloud.storage_public",
		"s3-bucket-AllUsers-write":                      "cloud.storage_public",
		"s3-bucket-no-default-encryption":               "cloud.storage_unencrypted",
		"s3-bucket-allowing-cleartext":                  "cloud.storage_insecure_transport",
		"cloudtrail-not-configured":                     "cloud.audit_log_disabled",
		"computeengine-firewall-rule-allows-port-range": "cloud.firewall_open_to_internet",
		"cloudstorage-bucket-allUsers":                  "cloud.storage_public",
		"network-security-group-ssh-port-open-to-all":   "cloud.firewall_admin_port_open",
		"storageaccount-public-blob-container":          "cloud.storage_public",
	}
}

// securityHubControls: AWS Security Hub consolidated control ids (ASFF Compliance.SecurityControlId).
func securityHubControls() map[string]string {
	return map[string]string{
		"EC2.13":       "cloud.firewall_admin_port_open",
		"EC2.14":       "cloud.firewall_admin_port_open",
		"EC2.21":       "cloud.firewall_admin_port_open",
		"EC2.19":       "cloud.firewall_open_to_internet",
		"EC2.9":        "cloud.public_endpoint",
		"RDS.2":        "cloud.public_endpoint",
		"EC2.3":        "cloud.volume_unencrypted",
		"EC2.7":        "cloud.volume_unencrypted",
		"SSM.2":        "cloud.instance_unpatched",
		"EC2.8":        "cloud.instance_metadata_v1",
		"IAM.5":        "cloud.user_without_mfa",
		"IAM.19":       "cloud.user_without_mfa",
		"IAM.9":        "cloud.root_mfa_disabled",
		"IAM.6":        "cloud.root_mfa_disabled",
		"IAM.4":        "cloud.root_access_key",
		"IAM.3":        "cloud.access_key_old",
		"IAM.8":        "cloud.credential_unused",
		"IAM.22":       "cloud.credential_unused",
		"IAM.7":        "cloud.password_policy_weak",
		"IAM.15":       "cloud.password_policy_weak",
		"IAM.16":       "cloud.password_policy_weak",
		"S3.2":         "cloud.storage_public",
		"S3.3":         "cloud.storage_public",
		"S3.4":         "cloud.storage_unencrypted",
		"S3.5":         "cloud.storage_insecure_transport",
		"EC2.1":        "cloud.snapshot_public",
		"RDS.1":        "cloud.snapshot_public",
		"CloudTrail.1": "cloud.audit_log_disabled",
		"CloudTrail.3": "cloud.audit_log_disabled",
	}
}

// sccControls: GCP Security Command Center (Security Health Analytics) finding categories.
func sccControls() map[string]string {
	return map[string]string{
		"OPEN_SSH_PORT":                    "cloud.firewall_admin_port_open",
		"OPEN_RDP_PORT":                    "cloud.firewall_admin_port_open",
		"OPEN_FIREWALL":                    "cloud.firewall_open_to_internet",
		"PUBLIC_IP_ADDRESS":                "cloud.public_endpoint",
		"PUBLIC_SQL_INSTANCE":              "cloud.public_endpoint",
		"OS_VULNERABILITY":                 "cloud.instance_unpatched",
		"MFA_NOT_ENFORCED":                 "cloud.user_without_mfa",
		"SERVICE_ACCOUNT_KEY_NOT_ROTATED":  "cloud.access_key_old",
		"USER_MANAGED_SERVICE_ACCOUNT_KEY": "cloud.service_account_key_user_managed",
		"ADMIN_SERVICE_ACCOUNT":            "cloud.admin_privileges_broad",
		"PUBLIC_BUCKET_ACL":                "cloud.storage_public",
		"AUDIT_LOGGING_DISABLED":           "cloud.audit_log_disabled",
		"PUBLIC_DATASET":                   "cloud.storage_public",
	}
}

// defenderControls: Microsoft Defender for Cloud assessment display names, lower case.
func defenderControls() map[string]string {
	return map[string]string{
		"management ports should be closed on your virtual machines":                                               "cloud.firewall_admin_port_open",
		"internet-facing virtual machines should be protected with network security groups":                        "cloud.public_endpoint",
		"system updates should be installed on your machines":                                                      "cloud.instance_unpatched",
		"machines should be configured to periodically check for missing system updates":                           "cloud.instance_unpatched",
		"accounts with owner permissions on azure resources should be mfa enabled":                                 "cloud.user_without_mfa",
		"accounts with write permissions on azure resources should be mfa enabled":                                 "cloud.user_without_mfa",
		"storage account public access should be disallowed":                                                       "cloud.storage_public",
		"secure transfer to storage accounts should be enabled":                                                    "cloud.storage_insecure_transport",
		"virtual machines should encrypt temp disks, caches, and data flows between compute and storage resources": "cloud.volume_unencrypted",
	}
}
