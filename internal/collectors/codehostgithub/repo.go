package codehostgithub

import (
	"context"
	"errors"
	"net/http"
	"sort"

	"github.com/MIERAI/security-platform/internal/collectors/codehost"
	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

type ownerScan struct {
	c                 *collector
	api               *codehost.Client
	owner             string
	summary           map[string]any
	publicUnprotected int
}

// list reads every page of a listing (Link rel="next").
func (o *ownerScan) list(ctx context.Context, path string) ([]any, error) {
	items, err := o.api.GetAll(ctx, path, 0, nil)
	if err != nil {
		return nil, err
	}
	return items, nil
}

// get reads one endpoint: its value, or nil and the error.
func (o *ownerScan) get(ctx context.Context, path string) (any, error) {
	p, err := o.api.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	return p.Value, nil
}

func (o *ownerScan) scan(ctx context.Context, repos []any) error {
	byName := map[string]*pyvalue.Map{}
	for _, v := range repos {
		r, ok := v.(*pyvalue.Map)
		if ok && pyvalue.Str(rundoc.Get(r.Value("owner"), "login")) == o.owner {
			byName[pyvalue.Str(r.Value("full_name"))] = r
		}
	}
	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)
	o.summary = map[string]any{}
	for _, full := range names {
		r := byName[full]
		if pyvalue.Truthy(r.Value("archived")) {
			continue
		}
		o.repo(ctx, full, r)
	}
	if _, err := o.c.doc.Raw("repos.json", o.summary); err != nil {
		return err
	}
	o.c.doc.Metric("security_repos_public_without_protection", float64(o.publicUnprotected),
		"Public repos whose default branch has no protection/ruleset", [2]string{"owner", o.owner})
	o.c.doc.Metric("security_repos_total", float64(len(o.summary)), "Repos checked", [2]string{"owner", o.owner})
	return nil
}

// protection reads the classic branch protection: its value (nil = none) or, for a failure that says nothing about
// the protection (rate limit, server error, network), an error.
func (o *ownerScan) protection(ctx context.Context, full, br string) (any, error) {
	v, err := o.get(ctx, "/repos/"+codehost.Quote(full)+"/branches/"+codehost.Quote(br)+"/protection")
	var he *codehost.HTTPError
	switch {
	case err == nil:
		return v, nil
	case errors.As(err, &he) && (he.Status == http.StatusNotFound || he.Status == http.StatusForbidden && !he.RateLimited):
		return nil, nil // not protected, or the plan has no classic protection for this repository
	default:
		return nil, err
	}
}

func (o *ownerScan) repo(ctx context.Context, full string, r *pyvalue.Map) {
	asset := "repo:github/" + full
	o.c.doc.OK(asset)
	br, vis := pyvalue.Str(r.Value("default_branch")), pyvalue.Str(r.Value("visibility"))
	base := "/repos/" + codehost.Quote(full)
	prot, err := o.protection(ctx, full, br)
	if err != nil {
		o.c.doc.Gap(asset, "cannot read branch protection: "+rundoc.Cut(err.Error(), 200))
		return
	}
	// an error of these reads is read as absent (no ruleset, no finding, no keys), as in the reference
	in := &repoReads{full: full, br: br, vis: vis, prot: prot,
		rules: o.optional(ctx, base+"/rules/branches/"+codehost.Quote(br)),
		wf:    o.optional(ctx, base+"/actions/permissions/workflow"), ap: o.optional(ctx, base+"/actions/permissions"),
		keys: o.optional(ctx, base+"/keys"), repo: o.optional(ctx, base)}
	ss := o.secretScanning(ctx, base)
	da := o.dependabot(ctx, base)
	secrets := o.actionsSecrets(ctx, base)
	row := newRow(in)
	row.v["secret_scanning_alerts"], row.v["dependabot_alerts"], row.v["actions_secrets"] = ss, da, secrets
	row.ss, row.da, row.secrets = ss, da, secrets
	o.summary[full] = row.v
	o.findings(asset, row)
}

// optional is a read whose failure means "absent".
func (o *ownerScan) optional(ctx context.Context, path string) any {
	v, err := o.get(ctx, path)
	if err != nil {
		return nil
	}
	return v
}
