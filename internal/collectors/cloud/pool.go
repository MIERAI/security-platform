package cloud

import (
	"sort"
	"strings"

	"github.com/MIERAI/security-platform/internal/cloud/dyn"
)

func gcpService() map[string]string {
	return map[string]string{"cloudstorage": "storage", "cloudsql": "sqladmin", "gke": "container", "kms": "cloudkms",
		"cloudresourcemanager": "cloudresourcemanager", "dns": "dns", "compute": "compute", "iam": "iam"}
}

func azureService() map[string]string {
	return map[string]string{"vm": "compute", "aks": "containerservice", "sqlserver": "sql", "postgresql": "dbforpostgresql",
		"mysql": "dbformysql", "monitor": "insights", "containerregistry": "containerregistry"}
}

// ServiceNorm is the provider's own service name for an engine's service label.
func ServiceNorm(provider, service string) string {
	s := dyn.Lower(dyn.Or(service, "other"))
	var m map[string]string
	switch provider {
	case "gcp":
		m = gcpService()
	case "azure":
		m = azureService()
	default:
		return s
	}
	if v, ok := m[s]; ok {
		return v
	}
	return s
}

// AssetOf is the canonical asset of a resource, identical whichever engine or import reported it:
//
//	aws   cloud:aws/<account>/<service>/<region|global>/<ARN resource part>
//	gcp   cloud:gcp/<project>/<api service>/<resource name>
//	azure cloud:azure/<subscription>/<provider namespace>/<resource id below the subscription, lower case>
func AssetOf(provider, account string, r *Result) string {
	uid := dyn.Or(r.Resource, r.Name, "account")
	if strings.HasPrefix(uid, "arn:") {
		if p := strings.SplitN(uid, ":", 6); len(p) == 6 {
			return "cloud:aws/" + dyn.Or(p[4], account) + "/" + p[2] + "/" + dyn.Or(p[3], "global") + "/" + p[5]
		}
	}
	if provider == "azure" && strings.HasPrefix(dyn.Lower(uid), "/subscriptions/") {
		if a, ok := azureAsset(uid, r.Service); ok {
			return a
		}
	}
	svc := ServiceNorm(provider, r.Service)
	if provider == "aws" {
		return "cloud:aws/" + account + "/" + svc + "/" + dyn.Or(r.Region, "global") + "/" + uid
	}
	name := ""
	if provider == "gcp" {
		name = r.Name
	}
	if name == "" {
		name = uid[strings.LastIndex(uid, "/")+1:]
	}
	return "cloud:" + provider + "/" + account + "/" + svc + "/" + name
}

func azureAsset(uid, service string) (string, bool) {
	parts := strings.Split(strings.Trim(uid, "/"), "/")
	if len(parts) < 2 {
		return "", false
	}
	ns := ""
	found := false
	for i := 0; i < len(parts)-1; i++ {
		if dyn.Lower(parts[i]) == "providers" {
			seg := parts[i+1]
			if _, after, ok := strings.Cut(seg, "."); ok {
				seg = after
			}
			ns, found = dyn.Lower(seg), true
			break
		}
	}
	if !found {
		ns = ServiceNorm("azure", service)
	}
	return "cloud:azure/" + dyn.Lower(parts[1]) + "/" + ns + "/" + dyn.Lower(strings.Join(parts[2:], "/")), true
}

func sevOrder(s string) int {
	for i, v := range []string{"info", "low", "medium", "high", "critical"} {
		if v == s {
			return i
		}
	}
	return -1
}

// Source is one engine's or import's view of a merged finding.
type Source struct{ Source, Check, Detail string }

// Merged is one finding of the run: a (asset, control) with every source that reported it.
type Merged struct {
	Asset, Check, Pillar, Layer, Severity, Title, Remediation string
	Refs                                                      []string
	Sources                                                   []Source
	Provider, Account, Resource                               string
	CISBenchmark                                              map[string][]string
}

type poolKey struct{ asset, check string }

// Pool holds the run's findings, merged: key (asset, control); a source whose own check maps to no control joins
// an existing finding on the same asset when they share a CIS benchmark reference. Never double counted.
type Pool struct {
	keys  []poolKey
	items map[poolKey]*Merged
}

// NewPool returns an empty pool.
func NewPool() *Pool { return &Pool{items: map[poolKey]*Merged{}} }

// Add merges one verdict (PASS and coverage-only verdicts are not findings).
func (p *Pool) Add(provider, account string, r *Result) {
	if r.Status != "FAIL" || r.CoverageOnly {
		return
	}
	asset := AssetOf(provider, account, r)
	c := Classify(provider, r.Check, r.Control)
	key := poolKey{asset, c.Check}
	if _, ok := p.items[key]; !ok && len(r.Refs) > 0 {
		key = p.sharedRefKey(asset, r.Refs, key)
	}
	f := p.items[key]
	if f == nil {
		f = &Merged{Asset: asset, Check: c.Check, Pillar: c.Pillar, Layer: c.Layer, Severity: r.Severity,
			Title: dyn.Or(c.Title, r.Title, c.Check), Remediation: dyn.Or(c.Remediation, r.Remediation),
			Refs: []string{}, Provider: provider, Account: account, Resource: r.Resource,
			CISBenchmark: map[string][]string{}}
		if secs, ok := c.CIS[provider]; ok {
			f.CISBenchmark[provider] = versioned(CISVersions()[provider], secs)
		}
		p.items[key] = f
		p.keys = append(p.keys, key)
	}
	if sevOrder(r.Severity) > sevOrder(f.Severity) {
		f.Severity = r.Severity
	}
	src := Source{Source: r.Source, Check: r.Check, Detail: dyn.Cut(r.Detail, 200)}
	if !containsSource(f.Sources, src) {
		f.Sources = append(f.Sources, src)
	}
	f.Refs = union(f.Refs, r.Refs)
}

func (p *Pool) sharedRefKey(asset string, refs []string, def poolKey) poolKey {
	for _, k := range p.keys {
		if k.asset == asset && len(intersect(p.items[k].Refs, refs)) > 0 {
			return k
		}
	}
	return def
}

func versioned(version string, secs []string) []string {
	out := make([]string, len(secs))
	for i, x := range secs {
		out[i] = version + "/" + x
	}
	return out
}

func containsSource(list []Source, s Source) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func union(a, b []string) []string {
	set := map[string]bool{}
	for _, x := range append(append([]string{}, a...), b...) {
		set[x] = true
	}
	out := make([]string, 0, len(set))
	for x := range set {
		out = append(out, x)
	}
	sort.Strings(out)
	return out
}

func intersect(a, b []string) []string {
	in := map[string]bool{}
	for _, x := range a {
		in[x] = true
	}
	var out []string
	for _, x := range b {
		if in[x] {
			out = append(out, x)
		}
	}
	return out
}

// Items returns the merged findings in insertion order.
func (p *Pool) Items() []*Merged {
	out := make([]*Merged, len(p.keys))
	for i, k := range p.keys {
		out[i] = p.items[k]
	}
	return out
}

// Sorted returns the merged findings ordered by (asset, check).
func (p *Pool) Sorted() []*Merged {
	out := p.Items()
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Asset != out[j].Asset {
			return out[i].Asset < out[j].Asset
		}
		return out[i].Check < out[j].Check
	})
	return out
}
