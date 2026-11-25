package codehostgitea

import (
	"context"
	"strings"

	"github.com/MIERAI/security-platform/internal/collectors/codehost"
	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

type ownerScan struct {
	c                 *collector
	api               *codehost.Client
	kind, host        string
	summary           map[string]any
	publicUnprotected int
}

// ProtectionFor is the branch protection rule that applies to branch: an exact rule name first, then glob patterns.
func ProtectionFor(rules []any, branch string) *pyvalue.Map {
	name := func(r *pyvalue.Map) string {
		if n := r.Value("rule_name"); pyvalue.Truthy(n) {
			return pyvalue.Str(n)
		}
		return rundoc.Str(r.Value("branch_name"))
	}
	for _, v := range rules {
		if r, ok := v.(*pyvalue.Map); ok && pyvalue.Equal(nameValue(r), branch) {
			return r
		}
	}
	for _, v := range rules {
		if r, ok := v.(*pyvalue.Map); ok && codehost.FnmatchCase(branch, name(r)) {
			return r
		}
	}
	return nil
}

// nameValue is r.get("rule_name") or r.get("branch_name") as a value (it is compared with the branch name).
func nameValue(r *pyvalue.Map) any {
	if n := r.Value("rule_name"); pyvalue.Truthy(n) {
		return n
	}
	return r.Value("branch_name")
}

func (s *ownerScan) repo(ctx context.Context, r *pyvalue.Map) error {
	full := pyvalue.Str(r.Value("full_name"))
	br := rundoc.StrOr(r.Value("default_branch"), "main")
	asset := "repo:" + s.kind + "/" + s.host + "/" + full
	pub := !pyvalue.Truthy(r.Value("private")) && !pyvalue.Truthy(r.Value("internal"))
	rulesPage, rerr := s.api.Get(ctx, "/repos/"+codehost.Quote(full)+"/branch_protections")
	keys, kerr := list(ctx, s.api, "/repos/"+codehost.Quote(full)+"/keys")
	if rerr != nil {
		s.c.doc.Gap(asset, "cannot read branch protection: "+errText(rerr))
		return nil
	}
	s.c.doc.OK(asset)
	rule := ProtectionFor(rundoc.List(rulesPage.Value), br)
	rv := func(k string) any { return rule.Value(k) } // nil rule: every key absent
	restricted := rule != nil && (!pyvalue.Truthy(rv("enable_push")) || pyvalue.Truthy(rv("enable_push_whitelist")))
	approvals := any(int64(0))
	if rule != nil && rule.Has("required_approvals") {
		approvals = rule.Value("required_approvals")
	}
	vis := "private"
	if pub {
		vis = "public"
	}
	deployKeys := make([]any, 0, len(keys))
	for _, k := range keys {
		deployKeys = append(deployKeys, map[string]any{"title": rundoc.Loose(rundoc.Get(k, "title")),
			"read_only": rundoc.Loose(rundoc.Get(k, "read_only")), "created_at": rundoc.Loose(rundoc.Get(k, "created_at"))})
	}
	var keysErr any
	if kerr != "" {
		keysErr = kerr
	}
	s.summary[full] = map[string]any{"visibility": vis, "default_branch": br, "protected": rule != nil,
		"push_restricted": restricted, "required_approvals": rundoc.Loose(approvals),
		"status_checks": pyvalue.Truthy(rv("enable_status_check")), "mirror": pyvalue.Truthy(r.Value("mirror")),
		"deploy_keys": deployKeys, "deploy_keys_error": keysErr}
	s.findings(r, &repoState{asset: asset, br: br, vis: vis, hasRule: rule != nil, restricted: restricted,
		approvals: approvals, keys: keys})
	return nil
}

// repoState is what the findings of one repository are decided on.
type repoState struct {
	asset, br, vis      string
	hasRule, restricted bool
	approvals           any
	keys                []any
}

func (s *ownerScan) findings(r *pyvalue.Map, st *repoState) {
	asset, br, vis, hasRule, restricted, approvals, keys := st.asset, st.br, st.vis, st.hasRule, st.restricted, st.approvals, st.keys
	ev := "raw/" + s.c.doc.Name + "/repos.json#" + pyvalue.Str(r.Value("full_name"))
	doc := s.c.doc
	switch {
	case !hasRule || !restricted:
		sev := "medium"
		if vis == "public" {
			s.publicUnprotected++
			sev = "high"
		}
		title := vis + " repo: default branch '" + br + "' can be pushed to directly"
		if !hasRule {
			title += " (no branch protection rule)"
		}
		doc.Add(&rundoc.Finding{Layer: "supply-chain", Asset: asset, Check: "repo.default_branch_unprotected", Title: title,
			Severity: sev, Evidence: ev, Remediation: "add a branch protection rule for the default branch: disable direct " +
				"push, require a pull request with an approval and status checks"})
	case !pyvalue.Truthy(approvals):
		doc.Add(&rundoc.Finding{Layer: "supply-chain", Asset: asset, Check: "repo.protection_no_approvals",
			Title:    "default branch '" + br + "' is protected but merges need no approving review",
			Severity: "low", Evidence: ev, Remediation: "set required approvals to at least 1 in the branch protection rule"})
	}
	orig := "" // str(r.get("original_url", "")): absent is "", null is "None"
	if r.Has("original_url") {
		orig = pyvalue.Str(r.Value("original_url"))
	}
	if pyvalue.Truthy(r.Value("mirror")) && strings.HasPrefix(orig, "http://") {
		doc.Add(&rundoc.Finding{Layer: "supply-chain", Asset: asset, Check: "repo.mirror_unverified_remote",
			Title: "pull mirror fetches over plain http", Severity: "medium", Evidence: ev, Remediation: "mirror over https or ssh"})
	}
	for _, k := range keys {
		if pyvalue.Truthy(rundoc.Get(k, "read_only")) {
			continue
		}
		title := pyvalue.Str(rundoc.Get(k, "title"))
		doc.Add(&rundoc.Finding{Layer: "identity", Asset: asset + "/deploy-key/" + title, Check: "repo.deploy_key_write",
			Title:    "write-enabled deploy key '" + title + "' (created " + rundoc.Cut(pyvalue.Str(rundoc.Get(k, "created_at")), 10) + ")",
			Severity: "low", Evidence: ev, Remediation: "keep only if a pipeline needs push; rotate yearly"})
	}
}
