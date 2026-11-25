package cloud

import (
	"strings"
	"unicode"
)

// Control is a generic cloud control: the PROBLEM, not the tool. The same resource with the same control from
// several engines/imports is ONE finding. Data only (collectors/cloud/controls.py is the same table).
type Control struct {
	Pillar, Layer, Title, Remediation string
	CIS                               map[string][]string // provider -> CIS Foundations Benchmark sections
}

// CISVersions are the CIS Foundations Benchmark versions the sections refer to.
func CISVersions() map[string]string {
	return map[string]string{"aws": "3.0", "gcp": "2.0", "azure": "2.0"}
}

// sections maps a provider onto CIS Foundations Benchmark sections.
type sections = map[string][]string

// Controls is the control table.
func Controls() map[string]Control {
	return map[string]Control{
		"cloud.firewall_admin_port_open": {"network", "network", "firewall rule allows SSH/RDP (admin ports) from the internet",
			"restrict the rule's source to known addresses or use a bastion/SSM/IAP instead of opening admin ports",
			sections{"aws": {"5.1", "5.2", "5.3"}, "gcp": {"3.6", "3.7"}, "azure": {"6.1", "6.2"}}},
		"cloud.firewall_open_to_internet": {"network", "network", "firewall rule allows all ports from the internet",
			"allow only the ports the service needs, from the sources that need them", sections{"aws": {"5.2"}, "gcp": {"3.6"}, "azure": {"6.1"}}},
		"cloud.public_endpoint": {"network", "network", "resource has a public endpoint/address",
			"remove the public address or put the resource behind a load balancer / private endpoint", nil},
		"cloud.volume_unencrypted": {"device", "host", "block volume or snapshot is not encrypted",
			"enable encryption by default for new volumes; migrate data to encrypted volumes",
			sections{"aws": {"2.2.1"}, "gcp": {"4.7"}, "azure": {"7.2"}}},
		"cloud.instance_unpatched": {"device", "host", "instance is missing patches or is not under patch management",
			"bring the instance under the provider's patch management and apply missing updates", nil},
		"cloud.instance_metadata_v1": {"device", "host", "instance metadata service allows unauthenticated v1 requests",
			"require IMDSv2 (http tokens required)", sections{"aws": {"5.6"}}},
		"cloud.user_without_mfa": {"people", "identity", "user with console/password access has no MFA",
			"enable MFA (phishing-resistant where possible) for every human user; enforce it by policy",
			sections{"aws": {"1.10"}, "gcp": {"1.2"}, "azure": {"1.1.1", "1.1.2"}}},
		"cloud.root_mfa_disabled": {"people", "identity", "root / break-glass account has no MFA",
			"enable hardware or passkey MFA on the root account", sections{"aws": {"1.5", "1.6"}}},
		"cloud.root_access_key": {"people", "identity", "root account has access keys", "delete root access keys", sections{"aws": {"1.4"}}},
		"cloud.root_used": {"people", "identity", "root account was used recently",
			"use named, least-privilege identities; keep root for break-glass", sections{"aws": {"1.7"}}},
		"cloud.access_key_old": {"people", "identity", "long-lived access key / service-account key not rotated in 90 days",
			"replace long-lived keys with federation/roles; otherwise rotate every 90 days", sections{"aws": {"1.14"}, "gcp": {"1.7"}}},
		"cloud.credential_unused": {"people", "identity", "credential unused for 45+ days", "disable and delete unused credentials",
			sections{"aws": {"1.12"}}},
		"cloud.service_account_key_user_managed": {"people", "identity", "service account has user-managed (long-lived) keys",
			"use workload identity federation / attached service accounts instead of keys", sections{"gcp": {"1.4"}}},
		"cloud.admin_privileges_broad": {"people", "identity", "identity has administrative privileges it should not need",
			"grant least privilege; no admin roles on workload identities", sections{"aws": {"1.16"}, "gcp": {"1.5"}, "azure": {"1.23"}}},
		"cloud.password_policy_weak": {"people", "identity", "account password policy is weaker than the benchmark",
			"set a password policy (length >= 14, reuse prevention) or move humans to SSO", sections{"aws": {"1.8", "1.9"}}},
		"cloud.platform_credential_over_privileged": {"people", "identity",
			"the security platform's own cloud credential can write (expected read-only)",
			"detach every policy/role except the read-only audit ones (docs/cloud.md: permissions)", nil},
		"cloud.storage_public": {"software", "data-secrets", "storage bucket/container is publicly accessible",
			"block public access at account and bucket level; share through signed URLs or a CDN with origin access",
			sections{"aws": {"2.1.4"}, "gcp": {"5.1"}, "azure": {"3.7"}}},
		"cloud.storage_unencrypted": {"software", "data-secrets", "storage has no default encryption configured",
			"enable default encryption (provider-managed or customer-managed keys)", sections{"azure": {"3.2"}}},
		"cloud.storage_insecure_transport": {"software", "data-secrets", "storage accepts unencrypted (HTTP) requests",
			"deny requests without TLS (aws:SecureTransport / secure transfer required)", sections{"aws": {"2.1.1"}, "azure": {"3.1"}}},
		"cloud.snapshot_public": {"software", "data-secrets", "snapshot or machine image is shared publicly",
			"remove public sharing; block public sharing at account level", nil},
		"cloud.audit_log_disabled": {"software", "detection", "control-plane audit logging is not enabled everywhere",
			"enable a multi-region/organisation audit trail (CloudTrail, Cloud Audit Logs, Activity Log export)",
			sections{"aws": {"3.1"}, "gcp": {"2.1"}, "azure": {"5.1.1"}}},
	}
}

// controlTable maps one source's own check ids onto controls.
func controlTable(source string) map[string]string {
	switch source {
	case "prowler":
		return prowlerControls()
	case "scoutsuite":
		return scoutControls()
	case "securityhub":
		return securityHubControls()
	case "scc":
		return sccControls()
	case "defender":
		return defenderControls()
	default:
		return map[string]string{}
	}
}

// ControlFor is the generic control of a source's check ("" when none).
func ControlFor(source, check string) string {
	if source == "defender" {
		check = strings.ToLower(check)
	}
	return controlTable(source)[check]
}

// Classification is where a verdict lands: its check name, pillar, ledger layer, title, remediation and CIS sections.
type Classification struct {
	Check, Pillar, Layer, Title, Remediation string
	CIS                                      map[string][]string
}

// Classify maps a check onto its control, or classifies an unmapped check (`cloud.<provider>.<check id>`) into a
// pillar by its id prefix: nothing an engine found is dropped.
func Classify(provider, checkID, control string) Classification {
	if control != "" {
		c := Controls()[control]
		return Classification{Check: control, Pillar: c.Pillar, Layer: c.Layer, Title: c.Title, Remediation: c.Remediation, CIS: c.CIS}
	}
	pillar := "software"
	for _, pp := range pillarByPrefix() {
		if strings.HasPrefix(checkID, pp[0]) {
			pillar = pp[1]
			break
		}
	}
	var name strings.Builder
	for _, r := range strings.ToLower(checkID) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("_.-", r) {
			name.WriteRune(r)
		} else {
			name.WriteRune('_')
		}
	}
	return Classification{Check: "cloud." + provider + "." + name.String(), Pillar: pillar, Layer: pillarLayer()[pillar],
		CIS: map[string][]string{}}
}

func pillarLayer() map[string]string {
	return map[string]string{"network": "network", "device": "host", "people": "identity", "software": "data-secrets"}
}

// pillarByPrefix: the pillar of an UNMAPPED engine check by its id prefix (first match).
func pillarByPrefix() [][2]string {
	return [][2]string{
		{"ec2_securitygroup", "network"}, {"ec2_networkacl", "network"}, {"ec2_elastic_ip", "network"}, {"vpc", "network"},
		{"elb", "network"}, {"cloudfront", "network"}, {"apigateway", "network"}, {"route53", "network"},
		{"compute_firewall", "network"}, {"compute_network", "network"}, {"network", "network"}, {"dns", "network"},
		{"ec2_instance", "device"}, {"ec2_ebs", "device"}, {"ec2_ami", "software"}, {"ssm", "device"}, {"autoscaling", "device"},
		{"compute_instance", "device"}, {"vm", "device"}, {"gke", "device"}, {"eks", "device"}, {"aks", "device"},
		{"iam", "people"}, {"organizations", "people"}, {"sso", "people"}, {"accessanalyzer", "people"}, {"entra", "people"},
		{"account", "people"},
	}
}
