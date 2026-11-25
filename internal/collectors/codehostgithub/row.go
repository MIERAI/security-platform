package codehostgithub

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// row is one repository's evidence (raw/codehost-github/repos.json) and what the findings are decided on.
type row struct {
	v                 map[string]any
	full, br, vis     string
	protected         bool
	ruleTypes         []string
	wfWrite, approves bool
	secretScanning    any
	pushProtection    any
	keys              []any
	ss, da            map[string]any
	secrets           []any
}

// protectingRules are the ruleset rule types that protect a branch as a classic protection does.
func protectingRules() []string { return []string{"pull_request", "non_fast_forward", "deletion"} }

// repoReads are the API answers about one repository (nil: absent or unreadable).
type repoReads struct {
	full, br, vis                   string
	prot, rules, wf, ap, keys, repo any
}

func newRow(in *repoReads) *row {
	full, br, vis, prot, rulesV, wf, ap, keys, fullR := in.full, in.br, in.vis, in.prot, in.rules, in.wf, in.ap, in.keys, in.repo
	set := map[string]bool{}
	for _, x := range rundoc.List(rulesV) {
		set[pyvalue.Str(rundoc.Get(x, "type"))] = true
	}
	types := make([]string, 0, len(set))
	for t := range set {
		types = append(types, t)
	}
	sort.Strings(types)
	protected := pyvalue.Truthy(prot)
	for _, t := range protectingRules() {
		protected = protected || set[t]
	}
	sa := rundoc.MapOr(rundoc.Get(fullR, "security_and_analysis"))
	status := func(k string) any { return rundoc.Loose(rundoc.Get(sa.Value(k), "status")) }
	r := &row{full: full, br: br, vis: vis, protected: protected, ruleTypes: types,
		wfWrite:  rundoc.Get(wf, "default_workflow_permissions") == "write",
		approves: pyvalue.Truthy(rundoc.Get(wf, "can_approve_pull_request_reviews")), keys: rundoc.List(keys),
		secretScanning: status("secret_scanning"), pushProtection: status("secret_scanning_push_protection")}
	deployKeys := make([]any, len(r.keys))
	for i, k := range r.keys {
		deployKeys[i] = map[string]any{"title": rundoc.Loose(rundoc.Get(k, "title")), "read_only": rundoc.Loose(rundoc.Get(k, "read_only")),
			"created_at": rundoc.Loose(rundoc.Get(k, "created_at")), "last_used": rundoc.Loose(rundoc.Get(k, "last_used"))}
	}
	r.v = map[string]any{"repo": full, "visibility": vis, "default_branch": br, "protected": protected,
		"ruleset_rules": toAny(types), "classic_protection": pyvalue.Truthy(prot),
		"workflow_default_permissions": rundoc.Loose(rundoc.Get(wf, "default_workflow_permissions")),
		"actions_can_approve_prs":      rundoc.Loose(rundoc.Get(wf, "can_approve_pull_request_reviews")),
		"allowed_actions":              rundoc.Loose(rundoc.Get(ap, "allowed_actions")), "actions_enabled": rundoc.Loose(rundoc.Get(ap, "enabled")),
		"deploy_keys": deployKeys, "secret_scanning": r.secretScanning, "push_protection": r.pushProtection,
		"dependabot_updates": status("dependabot_security_updates")}
	return r
}

// errKeys is jq's complaint about a group whose name is not text ({(.[0]): length} needs a string key).
const errKeys = "jq: error: Object keys must be strings"

// Grouped is jq's `group_by(.) | map({(.[0]): length}) | add` on a list of names: counts by name, nil for an empty list.
func Grouped(names []any) (map[string]any, bool) {
	if len(names) == 0 {
		return nil, true
	}
	out := map[string]any{}
	for _, n := range names {
		s, ok := n.(string)
		if !ok {
			return nil, false
		}
		c, _ := out[s].(int) // absent: 0
		out[s] = c + 1
	}
	return out, true
}

// SecretScanning is the reference's reduction of the open alerts: {count, types}. Only the type names are read from
// an alert; its secret, locations and URLs are never looked at.
func SecretScanning(alerts []any) map[string]any {
	names := make([]any, len(alerts))
	for i, a := range alerts {
		names[i] = rundoc.Get(a, "secret_type_display_name")
	}
	types, ok := Grouped(names)
	if !ok {
		return map[string]any{"error": errKeys}
	}
	var t any
	if types != nil {
		t = types
	}
	return map[string]any{"count": len(alerts), "types": t}
}

// Dependabot is the reference's reduction of the open alerts: counts by advisory severity ({} when none).
func Dependabot(alerts []any) map[string]any {
	sev := make([]any, len(alerts))
	for i, a := range alerts {
		sev[i] = rundoc.Get(rundoc.Get(a, "security_advisory"), "severity")
	}
	g, ok := Grouped(sev)
	if !ok {
		return map[string]any{"error": errKeys}
	}
	if g == nil {
		return map[string]any{}
	}
	return g
}

func (o *ownerScan) secretScanning(ctx context.Context, base string) map[string]any {
	alerts, err := o.list(ctx, base+"/secret-scanning/alerts?state=open&per_page=100")
	if err != nil {
		return map[string]any{"error": rundoc.Cut(err.Error(), 200)}
	}
	return SecretScanning(alerts)
}

func (o *ownerScan) dependabot(ctx context.Context, base string) map[string]any {
	alerts, err := o.list(ctx, base+"/dependabot/alerts?state=open&per_page=100")
	if err != nil {
		return map[string]any{"error": rundoc.Cut(err.Error(), 200)}
	}
	return Dependabot(alerts)
}

// actionsSecrets is [.secrets[] | {name, updated_at}]: names and dates, never a value (the API has none to give).
func (o *ownerScan) actionsSecrets(ctx context.Context, base string) []any {
	v, err := o.get(ctx, base+"/actions/secrets?per_page=100")
	out := []any{}
	if err != nil {
		return out
	}
	for _, s := range rundoc.List(rundoc.Get(v, "secrets")) {
		out = append(out, map[string]any{"name": rundoc.Loose(rundoc.Get(s, "name")), "updated_at": rundoc.Loose(rundoc.Get(s, "updated_at"))})
	}
	return out
}

func sevIf(cond bool, yes, no string) string {
	if cond {
		return yes
	}
	return no
}

func (o *ownerScan) findings(asset string, r *row) {
	doc, pub := o.c.doc, r.vis == "public"
	ev := "raw/codehost-github/repos.json#" + r.full
	add := func(layer, a, check, title, sev, fix string, human bool) {
		doc.AddFinding(&rundoc.Finding{Layer: layer, Asset: a, Check: check, Title: title, Severity: sev, Evidence: ev,
			Remediation: fix, NeedsHuman: human})

	}
	if !r.protected {
		if pub {
			o.publicUnprotected++
		}
		what := "no protection/ruleset"
		if len(r.ruleTypes) > 0 {
			what = "ruleset only has " + strings.Join(r.ruleTypes, ",") + " (no PR / force-push / deletion rules)"
		}
		add("supply-chain", asset, "repo.default_branch_unprotected", r.vis+" repo: default branch '"+r.br+"': "+what,
			sevIf(pub, "high", "medium"), "ruleset: require PR + status checks, block force-push/deletion", false)
	}
	if r.wfWrite {
		add("supply-chain", asset, "repo.actions_default_write", "GITHUB_TOKEN default permission is write",
			sevIf(pub, "medium", "low"), "set default workflow permissions to read; grant per job", false)
	}
	if r.approves {
		add("supply-chain", asset, "repo.actions_can_approve_prs", "Actions may approve pull requests", "medium",
			"disable 'Allow GitHub Actions to create and approve pull requests' unless needed", false)
	}
	if e, ok := r.da["error"]; ok && strings.Contains(pyvalue.Str(e), "disabled") {
		add("supply-chain", asset, "repo.dependabot_alerts_off", "Dependabot alerts are disabled", sevIf(pub, "medium", "low"),
			"enable Dependabot alerts + security updates", false)
	}
	if pub && r.secretScanning != "enabled" {
		add("supply-chain", asset, "repo.secret_scanning_off", "secret scanning is off", "medium", "enable it", false)
	}
	if pub && r.pushProtection != "enabled" {
		add("supply-chain", asset, "repo.push_protection_off", "secret push protection is off", "low", "enable it", false)
	}
	o.alertFindings(asset, r, pub, add)
	o.credentialFindings(asset, r, add)
}

type addFunc func(layer, asset, check, title, sev, fix string, human bool)

func (o *ownerScan) alertFindings(asset string, r *row, pub bool, add addFunc) {
	if n, _ := r.ss["count"].(int); n > 0 {
		types := sortedKeys(r.ss["types"])
		add("data-secrets", asset, "repo.secret_scanning_alerts_open",
			fmt.Sprintf("%d open secret-scanning alert(s) (types: %s)", n, strings.Join(types, ", ")),
			sevIf(pub, "critical", "high"), "revoke/rotate the secret, then close the alert", true)
	}
	crit, _ := r.da["critical"].(int)
	high, _ := r.da["high"].(int)
	if crit > 0 || high > 0 {
		var parts []string
		for _, k := range sortedKeys(r.da) {
			if k != "error" {
				parts = append(parts, fmt.Sprintf("%s=%v", k, r.da[k]))
			}
		}
		add("supply-chain", asset, "repo.dependabot_alerts_open", "open Dependabot alerts: "+strings.Join(parts, ", "),
			sevIf(crit > 0, "high", "medium"), "merge the security updates", false)
	}
}

func sortedKeys(v any) []string {
	m, _ := v.(map[string]any) // nil: no keys
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (o *ownerScan) credentialFindings(asset string, r *row, add addFunc) {
	for _, k := range r.keys {
		if pyvalue.Truthy(rundoc.Get(k, "read_only")) {
			continue
		}
		title := pyvalue.Str(rundoc.Get(k, "title"))
		add("identity", asset+"/deploy-key/"+title, "repo.deploy_key_write", "write-enabled deploy key '"+title+"' (created "+
			rundoc.Cut(pyvalue.Str(rundoc.Get(k, "created_at")), 10)+")", "low", "keep only if a pipeline needs push; rotate yearly", false)
	}
	for _, s := range r.secrets {
		m, _ := s.(map[string]any) // built by actionsSecrets
		day, err := time.Parse("2006-01-02", rundoc.Cut(pyvalue.Str(m["updated_at"]), 10))
		if err != nil {
			continue // no date: no age to judge
		}
		age := o.c.now.Sub(day).Hours() / 24
		if age > 90 {
			name := pyvalue.Str(m["name"])
			add("data-secrets", asset+"/actions-secret/"+name, "secret.age_over_90d",
				fmt.Sprintf("Actions secret %s not rotated for %d days", name, int(age)), "low", "rotate", true)
		}
	}
}
