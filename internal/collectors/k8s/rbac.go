package k8s

import (
	"context"
	"strconv"
	"strings"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
)

// wide classifies a role's rules: wildcard, secrets-read, pods-exec, rbac-write.
func wide(rules []policyRule) map[string]bool {
	w := map[string]bool{}
	for _, r := range rules {
		v, res, g := set(r.Verbs), set(r.Resources), set(r.APIGroups)
		if v["*"] && res["*"] {
			w["wildcard"] = true
		}
		if hasAny(res, "secrets", "*") && hasAny(v, "get", "list", "watch", "*") && hasAny(g, "", "*") {
			w["secrets-read"] = true
		}
		if hasAny(res, "pods/exec", "*") && hasAny(v, "create", "*") {
			w["pods-exec"] = true
		}
		if hasAny(res, "clusterrolebindings", "rolebindings", "*") && hasAny(v, "create", "update", "patch", "bind", "escalate", "*") {
			w["rbac-write"] = true
		}
	}
	return w
}

func set(list []string) map[string]bool {
	m := make(map[string]bool, len(list))
	for _, s := range list {
		m[s] = true
	}
	return m
}

func hasAny(m map[string]bool, keys ...string) bool {
	for _, k := range keys {
		if m[k] {
			return true
		}
	}
	return false
}

// rbacGrant is one subject's wide grant through one binding (the evidence record).
type rbacGrant struct {
	binding, scope, subject, role string
	flags                         []string
}

type rbacSources struct {
	crbs, rbs    []roleBinding
	clusterRoles map[string]*role
	roles        map[string]*role // "<namespace>/<name>"
}

func (cr *clusterRun) listRBAC(ctx context.Context) (*rbacSources, error) {
	src := &rbacSources{clusterRoles: map[string]*role{}, roles: map[string]*role{}}
	var err error
	if src.crbs, err = get[roleBinding](ctx, cr.kube, "clusterrolebindings", false); err != nil {
		return nil, err
	}
	crs, err := get[role](ctx, cr.kube, "clusterroles", false)
	if err != nil {
		return nil, err
	}
	for i := range crs {
		src.clusterRoles[crs[i].Metadata.Name] = &crs[i]
	}
	if src.rbs, err = get[roleBinding](ctx, cr.kube, "rolebindings", true); err != nil {
		return nil, err
	}
	roles, err := get[role](ctx, cr.kube, "roles", true) // K8S-D4: namespaced Roles are judged too
	if err != nil {
		return nil, err
	}
	for i := range roles {
		src.roles[roles[i].Metadata.Namespace+"/"+roles[i].Metadata.Name] = &roles[i]
	}
	return src, nil
}

func (cr *clusterRun) rbac(ctx context.Context) error {
	src, err := cr.listRBAC(ctx)
	if err != nil {
		return err
	}
	var grants []rbacGrant
	all := append(append([]roleBinding(nil), src.crbs...), src.rbs...)
	for i := range all {
		grants = append(grants, bindingGrants(&all[i], src)...)
	}
	ev := make([]pyjson.Value, len(grants))
	for i, g := range grants {
		o := pyjson.NewObject()
		flags := make([]pyjson.Value, len(g.flags))
		for j, f := range g.flags {
			flags[j] = f
		}
		o.Set("binding", g.binding)
		o.Set("scope", g.scope)
		o.Set("subject", g.subject)
		o.Set("role", g.role)
		o.Set("flags", flags)
		ev[i] = o
	}
	evPtr, err := cr.raw("rbac.json", ev)
	if err != nil {
		return err
	}
	subjects := map[string]bool{}
	for _, g := range grants {
		cr.rbacFinding(&g, evPtr)
		subjects[g.subject] = true
	}
	cr.run.Doc.Metric("security_k8s_wide_rbac_subjects", float64(len(subjects)), "Subjects with wide RBAC",
		map[string]string{"cluster": cr.cfg.name})
	return nil
}

// bindingGrants: the wide grants of one binding, one per subject (system users/groups, kube-system service
// accounts and system: roles are platform internals and skipped, as in the reference).
func bindingGrants(b *roleBinding, src *rbacSources) []rbacGrant {
	ref := b.RoleRef
	flags := bindingFlags(b, src)
	if len(flags) == 0 {
		return nil
	}
	scope := "cluster"
	if b.Kind != "ClusterRoleBinding" {
		scope = "ns:" + b.Metadata.Namespace
	}
	var out []rbacGrant
	for _, s := range b.Subjects {
		if platformInternal(&s, ref.Name) {
			continue
		}
		subj := s.Kind + ":" + s.Name
		if s.Namespace != "" {
			subj = s.Kind + ":" + s.Namespace + "/" + s.Name
		}
		out = append(out, rbacGrant{binding: b.Metadata.Name, scope: scope, subject: subj, role: ref.Name,
			flags: sortedStrings(flags)})
	}
	return out
}

// bindingFlags: what the bound role allows that is wide (cluster-admin by name, the rules otherwise).
func bindingFlags(b *roleBinding, src *rbacSources) map[string]bool {
	var r *role
	switch b.RoleRef.Kind {
	case "ClusterRole":
		r = src.clusterRoles[b.RoleRef.Name]
	case "Role":
		r = src.roles[b.Metadata.Namespace+"/"+b.RoleRef.Name]
	}
	flags := map[string]bool{}
	if b.RoleRef.Name == "cluster-admin" {
		flags["cluster-admin"] = true
	}
	if r != nil {
		for f := range wide(r.Rules) {
			flags[f] = true
		}
	}
	return flags
}

// platformInternal: system users and groups, kube-system service accounts and bindings to system: roles.
func platformInternal(s *subject, roleName string) bool {
	return (strings.HasPrefix(s.Name, "system:") && s.Kind != "ServiceAccount") || s.Namespace == "kube-system" ||
		strings.HasPrefix(roleName, "system:")
}

func (cr *clusterRun) rbacFinding(g *rbacGrant, evPtr string) {
	sev := "medium"
	if (contains(g.flags, "cluster-admin") || contains(g.flags, "wildcard")) && g.scope == "cluster" && cr.cfg.prod {
		sev = "high"
	}
	parts := make([]string, len(g.flags))
	for i, f := range g.flags {
		parts[i] = strings.ReplaceAll(f, "-", "_")
	}
	cr.run.Doc.AddFinding(&rundoc.Finding{Layer: "identity", Asset: "k8s-identity:" + cr.cfg.name + "/" + g.subject,
		Check: "k8s.rbac." + strings.Join(parts, "_"), Severity: sev, Evidence: evPtr,
		Title:       g.subject + " has " + strings.Join(g.flags, ",") + " (" + g.scope + ", via " + g.role + ")",
		Remediation: "least privilege: scope to namespaces / specific verbs; document why if required"})
}

func itoa(n int) string { return strconv.Itoa(n) }
