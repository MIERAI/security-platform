package identity

import (
	"strconv"
	"strings"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

const day = 86400.0

// limits are the instance's ages, in seconds.
type limits struct {
	maxAge, sshAge, soon, dormant float64
	expected                      map[string]map[string]bool // provider type -> expected collaborators
}

func newLimits(cfg *pyvalue.Map) limits {
	l := limits{maxAge: rundoc.Float(cfg.GetOr("max_token_age_days", int64(90)), 90) * day,
		sshAge:   rundoc.Float(cfg.GetOr("max_ssh_key_age_days", int64(365)), 365) * day,
		soon:     rundoc.Float(cfg.GetOr("expiring_days", int64(14)), 14) * day,
		dormant:  rundoc.Float(cfg.GetOr("dormant_device_days", int64(60)), 60) * day,
		expected: map[string]map[string]bool{}}
	for _, p := range rundoc.List(cfg.Value("providers")) {
		pm := rundoc.Map(p)
		set := map[string]bool{}
		for _, c := range rundoc.Strings(pm.Value("expected_collaborators")) {
			set[c] = true
		}
		l.expected[rundoc.Str(pm.Value("type"))] = set
	}
	return l
}

// checker applies the provider-independent checks (collectors/identity/collector.py: checks).
type checker struct {
	doc *rundoc.Document
	lim limits
	now float64
	ev  string
}

// add records a finding of the identity layer with the inventory as its evidence.
func (c *checker) add(f rundoc.Finding) {
	f.Layer, f.Evidence = "identity", c.ev
	c.doc.AddFinding(&f)
}

func (c *checker) run(s *snapshot) {
	for _, a := range s.accounts {
		c.account(a)
	}
	for _, o := range s.orgs {
		if isFalse(get(o, "mfa_required")) {
			c.add(rundoc.Finding{Asset: "org:" + pyStr(get(o, "provider")) + "/" + pyStr(get(o, "id")), Check: "identity.org_mfa_not_required", Title: "organisation " + pyStr(get(o, "id")) + " does not require 2FA of its members", Severity: "medium", Remediation: "require 2FA for everyone in the organisation settings (members without 2FA are removed: check first)", NeedsHuman: true})
		}
	}
	for _, g := range s.grants {
		c.grant(g)
	}
	for _, p := range s.policies {
		c.policy(p)
	}
	for _, cr := range s.credentials {
		c.credential(cr)
	}
}

func (c *checker) account(a *pyjson.Object) {
	if !isFalse(get(a, "mfa")) {
		return
	}
	sev := "high"
	if truthy(get(a, "admin")) {
		sev = "critical"
	}
	prov, id := pyStr(get(a, "provider")), pyStr(get(a, "id"))
	c.add(rundoc.Finding{Asset: "identity:" + prov + "/" + id, Check: "identity.mfa_disabled", Title: prov + " account " + id + " has no two-factor authentication", Severity: sev, Remediation: "enable 2FA (prefer a passkey or security key)", NeedsHuman: true})
}

func (c *checker) grant(g *pyjson.Object) {
	switch pyStr(get(g, "kind")) {
	case "collaborator":
		principal, perm := pyStr(get(g, "principal")), pyStr(get(g, "permission"))
		if c.lim.expected[pyStr(get(g, "provider"))][principal] {
			return
		}
		sev := "medium"
		if perm == "admin" || perm == "maintain" || perm == "push" {
			sev = "high"
		}
		res := pyStr(get(g, "resource"))
		_, short, _ := strings.Cut(res, ":")
		c.add(rundoc.Finding{Asset: res + "/collaborator/" + principal, Check: "identity.collaborator_unexpected", Title: principal + " has " + perm + " access to " + short + " and is not in the expected list", Severity: sev, Remediation: "remove the collaborator, or add them to identity.providers[].expected_collaborators after review", NeedsHuman: true})
	case "deploy_key":
		lu, ok := stamp(get(g, "last_used"))
		if ok && c.now-lu <= 180*day {
			return
		}
		principal := pyStr(get(g, "principal"))
		_, name, _ := strings.Cut(principal, "/")
		c.add(rundoc.Finding{Asset: pyStr(get(g, "resource")) + "/" + principal, Check: "identity.deploy_key_unused",
			Title:    "deploy key " + name + " (" + pyStr(get(g, "permission")) + ") not used for 180 days (or never)",
			Severity: "low", Remediation: "delete it (re-create when a pipeline needs it)", NeedsHuman: true})
	}
}

func (c *checker) policy(p *pyjson.Object) {
	name, value := pyStr(get(p, "name")), get(p, "value")
	if name == "fork_pr_approval" && truthy(get(p, "public")) && pyStr(value) != "all_external_contributors" {
		c.add(rundoc.Finding{Asset: pyStr(get(p, "resource")), Check: "identity.fork_pr_approval_weak", Title: "workflows from outside contributors run without approval for some contributors (" + pyStr(value) + ")", Severity: "low", Remediation: "require approval for all external contributors (repository Actions settings)", NeedsHuman: false})
	}
	if name == "acl_allow_all" && truthy(value) {
		c.add(rundoc.Finding{Asset: pyStr(get(p, "resource")), Check: "identity.overlay_acl_allow_all", Title: "the overlay network ACL allows every device to reach every device", Severity: "high", Remediation: "replace the default allow-all policy with grants per tag/group", NeedsHuman: true})
	}
}

// rotatable are the credential kinds that should be rotated every max_token_age_days.
func rotatable(kind string) bool {
	switch kind {
	case "oauth_token", "pat_classic", "pat_fine_grained", "api_key", "kube_token", "token_file", "registry":
		return true
	}
	return false
}

func days(sec float64) string { return strconv.FormatInt(int64(sec/day), 10) }

// cred is one credential record as the checks read it.
type cred struct {
	rec             *pyjson.Object
	asset, kind, id string
}

func (c *checker) credential(cr *pyjson.Object) {
	k := cred{rec: cr, asset: "credential:" + pyStr(get(cr, "store")) + "/" + pyStr(get(cr, "id")),
		kind: pyStr(get(cr, "kind")), id: pyStr(get(cr, "id"))}
	c.age(k)
	if (k.kind == "oauth_token" || k.kind == "pat_classic") && scopesHaveRepo(get(cr, "scopes")) {
		c.add(rundoc.Finding{Asset: k.asset, Check: "identity.token_classic_full_repo", Severity: "medium", NeedsHuman: true,
			Title: k.kind + " " + k.id + " has the full `repo` scope (all private repositories, read and write)",
			Remediation: "use a fine-grained token limited to the repositories and permissions automation needs; " +
				"keep the broad one for interactive use only"})
	}
	c.expiry(cr, k.asset, k.kind, k.id)
	if last, ok := stamp(get(cr, "last_used")); k.kind == "device_key" && ok && last != 0 && c.now-last > c.lim.dormant {
		c.add(rundoc.Finding{Asset: k.asset, Check: "identity.overlay_device_dormant", Severity: "low", NeedsHuman: true,
			Title:       "overlay device " + k.id + " not seen for " + days(c.now-last) + " days",
			Remediation: "remove the device from the overlay network"})
	}
	c.mode(k)
}

// age: rotatable tokens older than max_token_age_days, SSH keys older than max_ssh_key_age_days.
func (c *checker) age(k cred) {
	created, ok := stamp(get(k.rec, "created_at"))
	if !ok || created == 0 {
		return
	}
	if rotatable(k.kind) && c.now-created > c.lim.maxAge {
		sev := "low"
		if k.kind == "pat_classic" || k.kind == "oauth_token" || k.kind == "api_key" || k.kind == "kube_token" {
			sev = "medium"
		}
		c.add(rundoc.Finding{Asset: k.asset, Check: "identity.token_age_over_90d", Severity: sev, NeedsHuman: true,
			Title:       k.kind + " " + k.id + " is " + days(c.now-created) + " days old (rotate every " + days(c.lim.maxAge) + " days)",
			Remediation: "rotate it (or replace it with a short-lived / fine-grained credential)"})
	}
	if k.kind == "ssh_key" && c.now-created > c.lim.sshAge {
		c.add(rundoc.Finding{Asset: k.asset, Check: "identity.ssh_key_age_over_365d", Severity: "low", NeedsHuman: true,
			Title:       "SSH key " + k.id + " is " + days(c.now-created) + " days old",
			Remediation: "rotate yearly: new key, update authorized_keys / code host, delete the old one"})
	}
}

// mode: a credential file readable by group or others (an exec plugin holds no secret in the file).
func (c *checker) mode(k cred) {
	mode := get(k.rec, "mode")
	if !truthy(mode) || k.kind == "kube_exec" {
		return
	}
	if m, err := pyvalue.ParseInt(pyStr(mode), 8); err == nil && m&0o077 != 0 {
		c.add(rundoc.Finding{Asset: k.asset, Check: "identity.credential_file_readable", Severity: "high",
			Title: k.id + " file is readable by others (" + pyStr(mode) + ")", Remediation: "chmod 600"})
	}
}

func scopesHaveRepo(v pyjson.Value) bool {
	if !truthy(v) {
		return false
	}
	return pyIn("repo", v)
}

func (c *checker) expiry(cr *pyjson.Object, asset, kind, id string) {
	exp, ok := stamp(get(cr, "expires_at"))
	if !ok || exp == 0 {
		return
	}
	date := cut(pyStr(get(cr, "expires_at")), 10)
	switch {
	case exp <= c.now:
		c.add(rundoc.Finding{Asset: asset, Check: "identity.credential_expired", Title: kind + " " + id + " expired " + date + " and is still configured", Severity: "low", Remediation: "remove it or replace it", NeedsHuman: true})
	case exp-c.now < c.lim.soon:
		c.add(rundoc.Finding{Asset: asset, Check: "identity.token_expiring_soon", Title: kind + " " + id + " expires " + date, Severity: "medium", Remediation: "rotate it before it expires (outage) - and record where it is used", NeedsHuman: true})
	}
}
