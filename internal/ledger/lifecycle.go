package ledger

import (
	"math"
	"sort"
	"strings"

	"github.com/MIERAI/security-platform/internal/ledger/instant"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
	"github.com/MIERAI/security-platform/internal/remediation"
)

// Statuses of a ledger entry.
const (
	statusOpen     = "open"
	statusFixed    = "fixed"
	statusAccepted = "accepted"
)

// copiedFields are copied from the finding into its entry on every sighting (`kind` is handled apart: D1).
func copiedFields() []string {
	return []string{"id", "check", "layer", "asset", "title", "severity", "evidence", "remediation", "needs_human", "owner"}
}

// runCoverage is what one document says about coverage.
type runCoverage struct {
	ok, gaps, all *Coverage
	okAssets      []string
	gapNames      []string    // the part after "<type>:" of every gap (reference behaviour of LEDGER-D3)
	scopes        []string    // complete_scope prefixes of ok entries
	narrow        []narrowGap // gaps on <asset>/<part> limited to some checks
}

type narrowGap struct {
	asset    string
	patterns []string
}

func newRunCoverage(d document) runCoverage {
	var rc runCoverage
	var gaps, all []string
	for _, c := range d.coverage {
		asset := c.Str("asset")
		all = append(all, asset)
		switch c.Str("status") {
		case "ok":
			rc.okAssets = append(rc.okAssets, asset)
			if sc := c.Str("complete_scope"); sc != "" {
				rc.scopes = append(rc.scopes, sc)
			}
		case "gap":
			gaps = append(gaps, asset)
			_, name, found := strings.Cut(asset, ":")
			if !found {
				name = asset
			}
			rc.gapNames = append(rc.gapNames, name)
			if i := strings.LastIndex(asset, "/"); i >= 0 && c.Truthy("checks") {
				rc.narrow = append(rc.narrow, narrowGap{asset: asset[:i], patterns: stringList(c.List("checks"))})
			}
		}
	}
	rc.ok, rc.gaps, rc.all = NewCoverage(rc.okAssets), NewCoverage(gaps), NewCoverage(all)
	return rc
}

func stringList(l []pyjson.Value) []string {
	out := make([]string, 0, len(l))
	for _, x := range l {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// applyDocument runs the lifecycle of §4 for one document.
func (m *merger) applyDocument(d document) {
	rc := newRunCoverage(d)
	seenAll := m.ledger.Obj("coverage_seen")
	prevOK := stringList(seenAll.List(d.collector))
	prevCov := NewCoverage(prevOK)
	seen := map[string]bool{}
	for _, f := range d.findings {
		m.recordFinding(f, d, prevCov, seen)
	}
	seenAll.Set(d.collector, sortedUnion(prevOK, rc.okAssets))
	m.resolveUnreported(d, rc, seen)
}

func sortedUnion(a, b []string) []pyjson.Value {
	set := map[string]bool{}
	for _, s := range append(append([]string(nil), a...), b...) {
		set[s] = true
	}
	keys := make([]string, 0, len(set))
	for s := range set {
		keys = append(keys, s)
	}
	sort.Strings(keys)
	out := make([]pyjson.Value, len(keys))
	for i, s := range keys {
		out[i] = s
	}
	return out
}

// recordFinding creates, reopens or refreshes the entry of one reported finding.
func (m *merger) recordFinding(f *pyjson.Object, d document, prevCov *Coverage, seen map[string]bool) {
	id := f.Str("id")
	seen[id] = true
	observed := f.Str("observed_at")
	e := m.entries.Obj(id)
	clockStarts := false
	switch {
	case e == nil:
		e = pyjson.ObjectOf("first_seen", observed, "status", statusOpen, "fixed_at", nil, "reopened_count", int64(0),
			"ttk_counted", !prevCov.Empty() && prevCov.Covers(f.Str("asset")))
		m.entries.Set(id, e)
		clockStarts = true
	case e.Str("status") == statusFixed: // regression
		count, _ := e.Get("reopened_count")
		if count == nil {
			count = int64(0)
		}
		e.Set("status", statusOpen)
		e.Set("fixed_at", nil)
		e.Set("fixed_reason", nil)
		e.Set("reopened_count", pyjson.Add(count, int64(1)))
		e.Set("time_to_fix_days", nil)
		clockStarts = true
	}
	copyFinding(e, f, d)
	m.knowTime(e)
	if clockStarts && !m.opt.Reference[DeviationDueDate] {
		m.setDue(e, observed)
	}
}

func copyFinding(e, f *pyjson.Object, d document) {
	for _, k := range copiedFields() {
		v, _ := f.Get(k)
		e.Set(k, v)
	}
	kind, ok := f.Get("kind")
	if !ok {
		kind = "compliance" // LEDGER-D1: optional in findings 1.x; the SDK's default
	}
	e.Set("kind", kind)
	refs, ok := f.Get("refs")
	if !ok {
		refs = []pyjson.Value{}
	}
	e.Set("refs", refs)
	attrs, ok := f.Get("attributes")
	if !ok {
		attrs = pyjson.NewObject()
	}
	e.Set("attributes", attrs)
	e.Set("collector", d.collector)
	e.Set("collector_version", d.version)
	e.Set("last_seen", f.Str("observed_at"))
}

// setDue is LEDGER-D2: the remediation due date from the moment the clock starts (first record or reopen).
func (m *merger) setDue(e *pyjson.Object, start string) {
	t, err := instant.Parse(start)
	if err != nil {
		e.Set("due_at", nil)
		return
	}
	if due, ok := remediation.DueAt(t, remediation.ClassOf(e), m.slo); ok {
		e.Set("due_at", instant.ISO(due))
		return
	}
	e.Set("due_at", nil)
}

// knowTime sets disclosed_at and time_to_know_hours of an advisory (§4).
func (m *merger) knowTime(e *pyjson.Object) {
	at := e.Obj("attributes")
	if at == nil || e.Str("kind") != "vulnerability" || (!at.Truthy("cve") && !at.Truthy("advisory")) {
		return
	}
	disclosed := ""
	for _, k := range []string{"published_at", "kev_added"} {
		if s := at.Str(k); s > disclosed {
			disclosed = s
		}
	}
	if disclosed == "" {
		return
	}
	e.Set("disclosed_at", disclosed)
	first, err1 := instant.Parse(e.Str("first_seen"))
	dis, err2 := instant.Parse(disclosed)
	if err1 != nil || err2 != nil {
		m.warn("entry %s: cannot date its disclosure %q: time to know not computed", e.Str("id"), disclosed)
		return
	}
	e.Set("time_to_know_hours", pyjson.Round(math.Max(0, first-dis)/3600, 1))
}

// resolveUnreported fixes, per §4 steps 1-4, the open or accepted entries of this collector that the document
// did not report.
func (m *merger) resolveUnreported(d document, rc runCoverage, seen map[string]bool) {
	for _, id := range m.entries.Keys() {
		e := m.entries.Obj(id)
		if e == nil || e.Str("collector") != d.collector || seen[id] {
			continue
		}
		if st := e.Str("status"); st != statusOpen && st != statusAccepted {
			continue
		}
		if reason := fixReason(e, rc, m.opt.Reference[DeviationGapSubstring]); reason != "" {
			m.fix(e, d.finished, reason)
		}
	}
}

// fixReason is "" when the entry keeps its state.
func fixReason(e *pyjson.Object, rc runCoverage, substringGaps bool) string {
	asset := e.Str("asset")
	for _, n := range rc.narrow {
		if n.asset == asset && matchesAny(e.Str("check"), n.patterns) {
			return "" // this check could not be evaluated this time: unknown
		}
	}
	if gapConcerns(rc, asset, substringGaps) {
		return ""
	}
	if rc.ok.Covers(asset) {
		return "not_observed"
	}
	if hasPrefix(asset, rc.scopes) && !rc.all.Covers(asset) {
		return "asset_retired"
	}
	return ""
}

// gapConcerns: LEDGER-D3, a gap concerns the assets it would cover (§3); the reference protects every asset
// that contains a gap's name.
func gapConcerns(rc runCoverage, asset string, substring bool) bool {
	if !substring {
		return rc.gaps.Covers(asset)
	}
	for _, g := range rc.gapNames {
		if g != "" && strings.Contains(asset, g) {
			return true
		}
	}
	return false
}

func matchesAny(check string, patterns []string) bool {
	for _, p := range patterns {
		if fnmatch(check, p) {
			return true
		}
	}
	return false
}

func hasPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func (m *merger) fix(e *pyjson.Object, finished, reason string) {
	e.Set("status", statusFixed)
	e.Set("fixed_at", finished)
	e.Set("fixed_reason", reason)
	fin, err1 := instant.Parse(finished)
	first, err2 := instant.Parse(e.Str("first_seen"))
	if err1 != nil || err2 != nil {
		m.warn("entry %s: cannot date first_seen %q: time to fix not computed", e.Str("id"), e.Str("first_seen"))
		e.Set("time_to_fix_days", nil)
		return
	}
	e.Set("time_to_fix_days", pyjson.Round((fin-first)/86400, 2))
}
