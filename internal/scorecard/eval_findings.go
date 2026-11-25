package scorecard

import (
	"sort"
	"strconv"
	"strings"

	pv "github.com/MIERAI/security-platform/internal/pyvalue"
)

// maxListedChecks bounds the check names a findings detail lists.
const maxListedChecks = 6

// evalFindings counts the ledger entries the selector matches; pass when the count is at most `max` (default
// 0). require_collector: unknown unless the collectors covered something recently; require_coverage: unknown
// unless a newest document has an ok coverage entry with that asset prefix.
func evalFindings(e *evaluator, src *pv.Map) (outcome, error) {
	if out, done, err := e.requireCoverage(src); done || err != nil {
		return out, err
	}
	hits, err := e.matchingEntries(src)
	if err != nil {
		return outcome{}, err
	}
	mx, err := pv.ToInt(src.GetOr("max", int64(0)))
	if err != nil {
		return outcome{}, err
	}
	detail := strconv.Itoa(len(hits)) + " matching finding(s) (max " + strconv.FormatInt(mx, 10) + ")"
	if len(hits) > 0 {
		checks, err := checkNames(hits)
		if err != nil {
			return outcome{}, err
		}
		detail += ": " + strings.Join(checks, ", ")
	}
	if int64(len(hits)) <= mx {
		return outcome{"pass", detail}, nil
	}
	return outcome{"fail", detail}, nil
}

// requireCoverage returns done=true with an unknown outcome when the source's coverage requirements fail.
func (e *evaluator) requireCoverage(src *pv.Map) (outcome, bool, error) {
	req := src.Value("require_collector")
	if pv.Truthy(req) {
		maxAge, err := duration(src.Value("max_age"), 3*day)
		if err != nil {
			return outcome{}, true, err
		}
		ok, why, err := e.collectorsFresh(req, maxAge)
		if err != nil || !ok {
			return outcome{"unknown", "no recent coverage (" + why + ")"}, true, err
		}
	}
	pre := src.Value("require_coverage")
	if !pv.Truthy(pre) {
		return outcome{}, false, nil
	}
	covered, err := e.coveredOK(pre, req)
	if err != nil || covered {
		return outcome{}, err != nil, err
	}
	return outcome{"unknown", "nothing covered " + pv.Str(pre) + "* (adapter not configured or failing)"}, true, nil
}

// coveredOK: a newest document of the required collectors (any, without one) has an ok coverage entry for an
// asset with the prefix.
func (e *evaluator) coveredOK(prefix, req any) (bool, error) {
	var cols map[string]bool
	if pv.Truthy(req) && !pv.Equal(req, "*") {
		cols = map[string]bool{}
		for _, n := range pv.AsList(req) {
			cols[collectorKey(n)] = true
		}
	}
	for _, g := range e.in.coverage {
		hit, err := pv.HasPrefix(g.asset, prefix)
		if err != nil {
			return false, err
		}
		if hit && pv.Equal(g.status, "ok") && (cols == nil || cols[collectorKey(g.collector)]) {
			return true, nil
		}
	}
	return false, nil
}

func (e *evaluator) matchingEntries(src *pv.Map) ([]*pv.Map, error) {
	entries, err := e.in.ledgerSection("entries")
	if err != nil {
		return nil, err
	}
	statusIn := src.GetOr("status_in", []any{"open"})
	var hits []*pv.Map
	for _, id := range entries.Keys() {
		v := entries.Value(id)
		en, ok := v.(*pv.Map)
		if !ok {
			return nil, pv.AttributeError(v, "get")
		}
		in, err := pv.In(en.Value("status"), statusIn)
		if err != nil || !in {
			if err != nil {
				return nil, err
			}
			continue
		}
		sel, err := selected(en, src)
		if err != nil {
			return nil, err
		}
		if sel {
			hits = append(hits, en)
		}
	}
	return hits, nil
}

// checkNames is the sorted distinct check names of the entries, at most maxListedChecks.
func checkNames(hits []*pv.Map) ([]string, error) {
	seen := map[string]bool{}
	for _, h := range hits {
		v, err := item(h, "check")
		if err != nil {
			return nil, err
		}
		s, ok := v.(string)
		if !ok {
			return nil, pv.TypeError("'<' not supported between instances of '" + pv.TypeName(v) + "' and 'str'")
		}
		seen[s] = true
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	if len(out) > maxListedChecks {
		out = out[:maxListedChecks]
	}
	return out, nil
}

// selected applies the ledger's selector keys to an entry, in the contract's order.
func selected(en, sel *pv.Map) (bool, error) {
	for _, clause := range selectorClauses() {
		if !sel.Has(clause.key) {
			continue
		}
		ok, err := clause.match(en, sel.Value(clause.key))
		if err != nil || !ok {
			return false, err
		}
	}
	return true, nil
}

type selectorClause struct {
	key   string
	match func(en *pv.Map, arg any) (bool, error)
}

func selectorClauses() []selectorClause {
	return []selectorClause{
		{"check_in", func(en *pv.Map, arg any) (bool, error) { return fieldIn(en, "check", arg) }},
		{"check_prefix", checkPrefix},
		{"severity_in", func(en *pv.Map, arg any) (bool, error) { return fieldIn(en, "severity", arg) }},
		{"layer_in", func(en *pv.Map, arg any) (bool, error) { return fieldIn(en, "layer", arg) }},
		{"kind", func(en *pv.Map, arg any) (bool, error) { return pv.Equal(en.Value("kind"), arg), nil }},
		{"kind_not", func(en *pv.Map, arg any) (bool, error) { return !pv.Equal(en.Value("kind"), arg), nil }},
		{"asset_contains", assetContains},
		{"attr_true", attrTrue},
		{"attr_any_true", attrAnyTrue},
	}
}

func fieldIn(en *pv.Map, field string, arg any) (bool, error) {
	v, err := item(en, field)
	if err != nil {
		return false, err
	}
	return pv.In(v, arg)
}

func checkPrefix(en *pv.Map, arg any) (bool, error) {
	check, err := item(en, "check")
	if err != nil {
		return false, err
	}
	prefixes, err := pv.Iter(arg)
	if err != nil {
		return false, err
	}
	for _, p := range prefixes {
		ok, err := pv.HasPrefix(check, p)
		if err != nil || ok {
			return ok, err
		}
	}
	return false, nil
}

func assetContains(en *pv.Map, arg any) (bool, error) {
	for _, x := range pv.AsList(arg) {
		asset, err := item(en, "asset")
		if err != nil {
			return false, err
		}
		ok, err := pv.In(x, asset)
		if err != nil || ok {
			return ok, err
		}
	}
	return false, nil
}

func attributes(en *pv.Map) (*pv.Map, error) {
	at, ok := orEmpty(en.Value("attributes"))
	if !ok {
		return nil, pv.AttributeError(en.Value("attributes"), "get")
	}
	return at, nil
}

func attrTrue(en *pv.Map, arg any) (bool, error) {
	at, err := attributes(en)
	if err != nil {
		return false, err
	}
	v, _ := lookup(at, arg)
	return pv.Truthy(v), nil
}

func attrAnyTrue(en *pv.Map, arg any) (bool, error) {
	at, err := attributes(en)
	if err != nil {
		return false, err
	}
	names, err := pv.Iter(arg)
	if err != nil {
		return false, err
	}
	for _, n := range names {
		if v, _ := lookup(at, n); pv.Truthy(v) {
			return true, nil
		}
	}
	return false, nil
}
