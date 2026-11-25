package ledger

import (
	_ "embed" // the bundled SLI catalog
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/MIERAI/security-platform/internal/ledger/instant"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
	"github.com/MIERAI/security-platform/internal/ledger/yamlcfg"
)

// sliCatalog is a copy of generators/sli-catalog.yaml (a test keeps them identical): bundled with the
// implementation, not an operator input (contract §1).
//
//go:embed sli-catalog.yaml
var sliCatalog []byte // never written after initialisation (go:embed)

// ErrCatalog is returned for a bundled SLI catalog the merge cannot evaluate.
var ErrCatalog = errors.New("bundled SLI catalog")

const thirtyDays = 30 * 86400

// sliDef is one catalog entry.
type sliDef struct {
	name        string
	description pyjson.Value
	target      pyjson.Value
	findings    *pyjson.Object // one of findings, metric, ledger
	metric      *pyjson.Object
	ledger      string
}

func loadCatalog() ([]sliDef, error) {
	v, err := yamlcfg.Parse(sliCatalog)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCatalog, err)
	}
	root, _ := v.(*pyjson.Object)
	if root == nil {
		return nil, fmt.Errorf("%w: not a mapping", ErrCatalog)
	}
	var out []sliDef
	for _, x := range root.List("slis") {
		s, _ := x.(*pyjson.Object)
		if s == nil || s.Obj("source") == nil || s.Obj("objective") == nil {
			return nil, fmt.Errorf("%w: an entry without source or objective", ErrCatalog)
		}
		d := sliDef{name: s.Str("name"), findings: s.Obj("source").Obj("findings"), metric: s.Obj("source").Obj("metric"),
			ledger: s.Obj("source").Str("ledger")}
		d.description, _ = s.Get("description")
		d.target, _ = s.Obj("objective").Get("target")
		if !pyjson.IsNumber(d.target) || (d.findings == nil && d.metric == nil && d.ledger == "") {
			return nil, fmt.Errorf("%w: SLI %q", ErrCatalog, d.name)
		}
		out = append(out, d)
	}
	return out, nil
}

// sliResult is one computed SLI, in catalog order.
type sliResult struct {
	name  string
	value pyjson.Value // rounded to one decimal
	ok    bool
	def   sliDef
}

// computeSLIs evaluates the bundled catalog and updates sli_members / sli_new_total.
func (m *merger) computeSLIs(cur []document, gaps gapCounts) ([]sliResult, error) {
	defs, err := loadCatalog()
	if err != nil {
		return nil, err
	}
	open := m.byStatus(statusOpen)
	computed, err := m.computedQuantities(open, gaps)
	if err != nil {
		return nil, err
	}
	metrics := collectorMetrics(cur)
	var out []sliResult
	for _, d := range defs {
		var v pyjson.Value
		switch {
		case d.findings != nil:
			v = m.findingsSLI(d, open)
		case d.metric != nil:
			v = metricSLI(d.metric, metrics)
		default:
			var ok bool
			if v, ok = computed[d.ledger]; !ok {
				return nil, fmt.Errorf("%w: unknown ledger quantity %q", ErrCatalog, d.ledger)
			}
		}
		out = append(out, sliResult{name: d.name, value: pyjson.RoundValue(v, 1), ok: !pyjson.Less(d.target, v), def: d})
	}
	return out, nil
}

func (m *merger) byStatus(status string) []*pyjson.Object {
	var out []*pyjson.Object
	for _, id := range m.entries.Keys() {
		if e := m.entries.Obj(id); e != nil && e.Str("status") == status {
			out = append(out, e)
		}
	}
	return out
}

func (m *merger) findingsSLI(d sliDef, open []*pyjson.Object) pyjson.Value {
	var members []string
	for _, e := range open {
		if selected(e, d.findings) {
			members = append(members, e.Str("id"))
		}
	}
	sort.Strings(members)
	all := m.ledger.GetOrCreateObj("sli_members")
	counts := m.ledger.GetOrCreateObj("sli_new_total")
	prev, had := all.Get(d.name)
	if had && prev != nil { // first sight of an SLI is a baseline, not "new"
		c, _ := counts.Get(d.name)
		if c == nil {
			c = int64(0)
		}
		counts.Set(d.name, pyjson.Add(c, entered(prev, members)))
	} else if !counts.Has(d.name) {
		counts.Set(d.name, int64(0))
	}
	list := make([]pyjson.Value, len(members))
	for i, s := range members {
		list[i] = s
	}
	all.Set(d.name, list)
	return int64(len(members))
}

// entered counts the members that were not in the previous member list.
func entered(prev pyjson.Value, members []string) int64 {
	old := map[string]bool{}
	for _, s := range stringList(asList(prev)) {
		old[s] = true
	}
	var n int64
	for _, s := range uniq(members) {
		if !old[s] {
			n++
		}
	}
	return n
}

func asList(v pyjson.Value) []pyjson.Value {
	l, _ := v.([]pyjson.Value) // anything else holds no members
	return l
}

func uniq(sorted []string) []string {
	var out []string
	for i, s := range sorted {
		if i == 0 || s != sorted[i-1] {
			out = append(out, s)
		}
	}
	return out
}

// selected is the catalog's findings selector.
func selected(e, sel *pyjson.Object) bool {
	at := e.Obj("attributes")
	if at == nil {
		at = pyjson.NewObject()
	}
	check := e.Str("check")
	return in(sel, "check_in", check) && prefixed(sel, check) && in(sel, "severity_in", e.Str("severity")) &&
		in(sel, "layer_in", e.Str("layer")) && equal(sel, "kind", e.Str("kind"), true) &&
		equal(sel, "kind_not", e.Str("kind"), false) && (!sel.Has("attr_true") || at.Truthy(sel.Str("attr_true"))) &&
		anyTrue(sel, at)
}

func in(sel *pyjson.Object, key, value string) bool {
	c, ok := sel.Get(key)
	return !ok || pyjson.Contains(c, value)
}

func equal(sel *pyjson.Object, key, value string, want bool) bool {
	v, ok := sel.Get(key)
	if !ok {
		return true
	}
	s, isStr := v.(string)
	return (isStr && s == value) == want
}

func prefixed(sel *pyjson.Object, check string) bool {
	v, ok := sel.Get("check_prefix")
	if !ok {
		return true
	}
	for _, p := range iterStrings(v) {
		if strings.HasPrefix(check, p) {
			return true
		}
	}
	return false
}

func anyTrue(sel, at *pyjson.Object) bool {
	v, ok := sel.Get("attr_any_true")
	if !ok {
		return true
	}
	for _, k := range iterStrings(v) {
		if at.Truthy(k) {
			return true
		}
	}
	return false
}

// iterStrings is Python's iteration over a selector value: the elements of a list, the characters of a string.
func iterStrings(v pyjson.Value) []string {
	if s, ok := v.(string); ok {
		out := make([]string, 0, len(s))
		for _, r := range s {
			out = append(out, string(r))
		}
		return out
	}
	return stringList(asList(v))
}

func collectorMetrics(docs []document) map[string][]pyjson.Value {
	out := map[string][]pyjson.Value{}
	for _, d := range docs {
		for _, x := range d.obj.List("metrics") {
			if mo, ok := x.(*pyjson.Object); ok {
				v, _ := mo.Get("value")
				out[mo.Str("name")] = append(out[mo.Str("name")], v)
			}
		}
	}
	return out
}

func metricSLI(src *pyjson.Object, metrics map[string][]pyjson.Value) pyjson.Value {
	vals := metrics[src.Str("name")]
	if len(vals) == 0 {
		return int64(0)
	}
	if src.Str("agg") == "max" {
		return pyjson.Max(vals)
	}
	return pyjson.Sum(vals)
}

// computedQuantities are the catalog's `source.ledger` values.
func (m *merger) computedQuantities(open []*pyjson.Object, gaps gapCounts) (map[string]pyjson.Value, error) {
	age, err := m.catalogAge()
	if err != nil {
		return nil, err
	}
	return map[string]pyjson.Value{
		"oldest_fixable_critical_cve_days": m.oldestFixableCritical(open),
		"coverage_gaps":                    gaps.total,
		"check_catalog_age_days":           age,
		"time_to_know_hours_max_30d":       maxOrZero(m.urgentKnowTimes()),
	}, nil
}

func maxOrZero(vals []pyjson.Value) pyjson.Value {
	if len(vals) == 0 {
		return int64(0)
	}
	return pyjson.Max(vals)
}

func (m *merger) oldestFixableCritical(open []*pyjson.Object) pyjson.Value {
	var days []pyjson.Value
	for _, e := range open {
		at := e.Obj("attributes")
		if at == nil || e.Str("kind") != "vulnerability" || at.Str("base_severity") != "critical" ||
			!at.Truthy("fixed") || !at.Truthy("published_at") {
			continue
		}
		p, _ := at.Get("published_at")
		t, err := instant.Parse(pyjson.Str(p))
		if err != nil {
			continue
		}
		days = append(days, (m.opt.Now-t)/86400)
	}
	return maxOrZero(days)
}

func (m *merger) catalogAge() (pyjson.Value, error) {
	review, err := loadYAMLObject(filepath.Join(m.opt.Data, "catalog-review.yaml"), m.warn)
	if err != nil {
		return nil, err
	}
	last, _ := review.Get("last_reviewed")
	if !pyjson.Truthy(last) {
		return int64(-1), nil
	}
	t, ok := m.parseOrWarn(last, "catalog-review.yaml: last_reviewed")
	if !ok {
		return int64(-1), nil
	}
	return (m.opt.Now - t) / 86400, nil
}

// parseOrWarn parses a timestamp value; an unparseable one is reported and ok is false.
func (m *merger) parseOrWarn(v pyjson.Value, what string) (float64, bool) {
	t, err := instant.Parse(pyjson.Str(v))
	if err != nil {
		m.warn("%s %s is not a date", what, pyjson.Repr(v))
		return 0, false
	}
	return t, true
}

// recentKnowTimes are the entries counted for time-to-know: ttk_counted, with a value, first seen in the
// last 30 days.
func (m *merger) recentKnowTimes() []*pyjson.Object {
	var out []*pyjson.Object
	for _, id := range m.entries.Keys() {
		e := m.entries.Obj(id)
		if e == nil || !e.Truthy("ttk_counted") {
			continue
		}
		if h, ok := e.Get("time_to_know_hours"); !ok || h == nil {
			continue
		}
		if t, err := instant.Parse(e.Str("first_seen")); err == nil && m.opt.Now-t < thirtyDays {
			out = append(out, e)
		}
	}
	return out
}

func (m *merger) urgentKnowTimes() []pyjson.Value {
	var out []pyjson.Value
	for _, e := range m.recentKnowTimes() {
		if urgent(e) {
			h, _ := e.Get("time_to_know_hours")
			out = append(out, h)
		}
	}
	return out
}

// urgent is the time-to-know objective's class: KEV, or critical/high (base or prioritized).
func urgent(e *pyjson.Object) bool {
	at := e.Obj("attributes")
	if at == nil {
		at = pyjson.NewObject()
	}
	sev := e.Str("severity")
	return at.Truthy("kev") || sev == "critical" || sev == "high" || at.Str("base_severity") == "critical"
}

func assetClass(asset string) string {
	typ, _, _ := strings.Cut(asset, ":")
	switch typ {
	case "image", "repo", "host":
		return typ
	default:
		return "other"
	}
}
