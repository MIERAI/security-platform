// Package identity is the Go implementation of the `identity` collector (collectors/identity): `sp identity collect`.
// The people pillar: accounts and their 2FA, organisations' 2FA policy, access grants (collaborators, members, deploy
// keys), token and key lifecycle, and the overlay network's devices and ACL — read-only, metadata only: no token,
// key or password value ever reaches the document, the evidence, a log line or a command line.
package identity

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// Version is the collector's version (collectors/identity/VERSION).
const Version = "0.1.0"

// adapterVersion is the version of the identity adapter the document reports as the tool "identity-adapter"
// (adapters/identity.py VERSION: this package implements that adapter's interface).
const adapterVersion = "0.2.0"

// Main is `sp identity ...`.
func Main(ctx context.Context, args []string, env *rundoc.Env, stdout io.Writer) int {
	return rundoc.Main(ctx, &rundoc.Collector{Name: "identity", Version: Version, Collect: collect}, args, env, stdout)
}

// provider is one identity provider of the instance (`identity.providers[]`).
type provider interface {
	collect(ctx context.Context) (*snapshot, error)
}

func collect(ctx context.Context, run *rundoc.Run, env *rundoc.Env) error {
	cfg := rundoc.Map(run.Instance.Value("identity"))
	if cfg == nil {
		cfg = pyvalue.NewMap()
	}
	data := run.Data
	if data == "" {
		data = run.Dir
	}
	r := &runtime{env: env, client: httpClient(env), home: run.Home, now: env.Clock()}
	total := &snapshot{}
	pr := &providers{r: r, doc: run.Doc, cache: filepath.Join(data, "cache", "identity"), total: total}
	for _, pc := range rundoc.List(cfg.Value("providers")) {
		if err := pr.run(ctx, rundoc.Map(pc)); err != nil {
			return err
		}
	}
	if creds := cfg.Value("credentials"); pyvalue.Truthy(creds) {
		cm := rundoc.Map(creds)
		if cm == nil {
			return fmt.Errorf("%w: identity.credentials must be a mapping", rundoc.ErrUsage)
		}
		s := newLocal(cm, run.Home).collect()
		total.credentials = append(total.credentials, s.credentials...)
		record(run.Doc, s)
	}
	return report(run, total, cfg, r.now())
}

// providers runs the instance's providers into one snapshot.
type providers struct {
	r     *runtime
	doc   *rundoc.Document
	cache string // <data>/cache/identity
	total *snapshot
}

// run collects one provider; a provider that fails is a gap, never the end of the run.
func (pr *providers) run(ctx context.Context, pc *pyvalue.Map) error {
	r, doc, cache, total := pr.r, pr.doc, pr.cache, pr.total
	if !pc.Has("type") {
		return fmt.Errorf("%w: identity.providers[] entry without type", rundoc.ErrUsage)
	}
	typ := pyvalue.Str(pc.Value("type"))
	var p provider
	switch typ {
	case "github":
		p = &github{cfg: pc, cache: cache, r: r}
	case "tailscale":
		p = &tailscale{cfg: pc, r: r}
	case "google-workspace", "okta", "entra", "gitlab":
		doc.Gap("identity-provider:"+typ, "identity provider "+pyvalue.Repr(pc.Value("type"))+
			" is a documented interface, not implemented", nil)
		return nil
	default:
		doc.Gap("identity-provider:"+typ, "KeyError: "+pyvalue.Repr(pc.Value("type")), nil)
		return nil
	}
	s, err := p.collect(ctx)
	if err != nil {
		if !errors.Is(err, errProvider) {
			return err
		}
		doc.Gap("identity-provider:"+typ, rundoc.Cut(err.Error()[len(errProvider.Error())+2:], 220), nil)
		return nil
	}
	total.add(s)
	record(doc, s)
	return nil
}

// record puts a snapshot's coverage into the document: its gaps first, then what it covered (an ok never
// replaces a gap of the same asset), as the Python collector does.
func record(doc *rundoc.Document, s *snapshot) {
	for _, g := range s.gaps {
		doc.Gap(g.asset, g.reason, g.checks)
	}
	for _, a := range s.covered {
		doc.OK(a, "")
	}
}

// report writes the inventory evidence, applies the checks and adds the metrics.
func report(run *rundoc.Run, total *snapshot, cfg *pyvalue.Map, now time.Time) error {
	t := float64(now.UnixNano()) / 1e9
	creds := make([]pyjson.Value, len(total.credentials))
	for i, cr := range total.credentials {
		c := pyjson.NewObject()
		for _, k := range cr.Keys() {
			if k != "value" {
				v, _ := cr.Get(k)
				c.Set(k, v)
			}
		}
		var age pyjson.Value
		if t0, ok := stamp(get(cr, "created_at")); ok && t0 != 0 {
			age = pyvalue.Round((t-t0)/day, 1)
		}
		c.Set("age_days", age)
		creds[i] = c
	}
	inv := object("accounts", objects(total.accounts), "orgs", objects(total.orgs), "grants", objects(total.grants),
		"policies", objects(total.policies), "credentials", creds)
	ev, err := run.Doc.Raw(run.Dir, "inventory.json", inv)
	if err != nil {
		return err
	}
	(&checker{doc: run.Doc, lim: newLimits(cfg), now: t, ev: ev}).run(total)
	metrics(run.Doc, total)
	run.Doc.Tools.Set("identity-adapter", adapterVersion)
	return nil
}

func metrics(doc *rundoc.Document, total *snapshot) {
	kinds := map[string]int{}
	for _, cr := range total.credentials {
		kinds[pyStr(get(cr, "kind"))]++
	}
	for _, k := range sortedKeys(kinds) {
		doc.Metric("security_identity_credentials", float64(kinds[k]), "Credentials found (metadata only), by kind",
			map[string]string{"kind": k})
	}
	unknown := 0
	for _, a := range total.accounts {
		if isNone(get(a, "mfa")) {
			unknown++
		}
	}
	doc.Metric("security_identity_accounts", float64(len(total.accounts)), "Accounts seen through identity providers", nil)
	doc.Metric("security_identity_mfa_unknown", float64(unknown), "Accounts whose MFA status no API could tell (attest them)", nil)
	doc.Metric("security_identity_grants", float64(len(total.grants)),
		"Access grants seen (collaborators, deploy keys, members)", nil)
}
