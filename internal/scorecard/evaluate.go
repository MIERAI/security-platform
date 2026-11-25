package scorecard

import (
	"context"
	"errors"
	"strings"

	pv "github.com/MIERAI/security-platform/internal/scorecard/pyvalue"
)

// maxDetail bounds the error text in an "evaluator error" detail (characters).
const maxDetail = 160

// GitLog returns the commit time (epoch seconds, as text) of the last commit that touched path in the work tree
// of dir, "" when there is none. Injected so that tests need no git.
type GitLog func(ctx context.Context, dir, path string) string

// evaluator decides automated and evidence controls from their `source` (SPEC §3.4, docs/scorecard.md).
type evaluator struct {
	ctx      context.Context //nolint:containedctx // one evaluation pass; every subprocess it starts uses it
	now      float64
	in       *inputs
	att      *pv.Map
	controls []*Control
	pillars  any
	data     string
	product  string
	home     string
	gitLog   GitLog
	current  *Control
}

type evalFunc func(e *evaluator, src *pv.Map) (outcome, error)

// evaluators is the registry of source types. A fresh map on every call.
func evaluators() map[string]evalFunc {
	return map[string]evalFunc{
		"findings": evalFindings, "sli": evalSLI, "metric": evalMetric, "collector_fresh": evalCollectorFresh,
		"job": evalJob, "file": evalFile, "all": evalAll, "any": evalAny, "first_known": evalFirstKnown,
		"attestation": evalAttestation, "builtin": evalBuiltin, "none": evalNone,
	}
}

// evaluate runs a source. A failing evaluator gives "unknown" with an "evaluator error" detail (one broken
// control never hides the others); a source that is not a mapping is an error of the enclosing source.
func (e *evaluator) evaluate(src any) (outcome, error) {
	m, ok := src.(*pv.Map)
	if !ok {
		return outcome{}, pv.AttributeError(src, "get")
	}
	t := m.Value("type")
	switch t.(type) {
	case []any, *pv.Map:
		return outcome{}, pv.TypeError("unhashable type: '" + pv.TypeName(t) + "'")
	}
	name, _ := t.(string)
	fn, known := evaluators()[name]
	if !known {
		return outcome{"unknown", "unknown source type " + pv.Repr(t)}, nil
	}
	out, err := fn(e, m)
	var pe *pv.Error
	if errors.As(err, &pe) {
		return outcome{"unknown", "evaluator error: " + pe.Type + ": " + truncate(pe.Msg, maxDetail)}, nil
	}
	return out, err
}

func truncate(s string, n int) string {
	i := 0
	for pos := range s {
		if i == n {
			return s[:pos]
		}
		i++
	}
	return s
}

// subSources evaluates every source of src["of"] in order.
func (e *evaluator) subSources(src *pv.Map) ([]outcome, error) {
	of, err := item(src, "of")
	if err != nil {
		return nil, err
	}
	items, err := pv.Iter(of)
	if err != nil {
		return nil, err
	}
	res := make([]outcome, 0, len(items))
	for _, s := range items {
		r, err := e.evaluate(s)
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

// item is m[key]; a missing key is a KeyError.
func item(m *pv.Map, key string) (any, error) {
	v, ok := m.Get(key)
	if !ok {
		return nil, pv.KeyError(key)
	}
	return v, nil
}

func joinDetails(res []outcome, skipPass bool) string {
	var parts []string
	for _, r := range res {
		if !skipPass || r.status != "pass" {
			parts = append(parts, r.detail)
		}
	}
	return strings.Join(parts, "; ")
}

// evalAll passes when every sub-source passes; unknown wins over fail.
func evalAll(e *evaluator, src *pv.Map) (outcome, error) {
	res, err := e.subSources(src)
	if err != nil {
		return outcome{}, err
	}
	status := "pass"
	for _, r := range res {
		switch {
		case r.status == "unknown":
			status = "unknown"
		case r.status != "pass" && status == "pass":
			status = "fail"
		}
	}
	if status == "pass" {
		return outcome{"pass", joinDetails(res, false)}, nil
	}
	return outcome{status, joinDetails(res, true)}, nil
}

// evalAny passes with the first passing sub-source; unknown only when every one is unknown.
func evalAny(e *evaluator, src *pv.Map) (outcome, error) {
	res, err := e.subSources(src)
	if err != nil {
		return outcome{}, err
	}
	status := "unknown"
	for _, r := range res {
		if r.status == "pass" {
			return r, nil
		}
		if r.status != "unknown" {
			status = "fail"
		}
	}
	return outcome{status, joinDetails(res, false)}, nil
}

// evalFirstKnown: the first sub-source that is not unknown decides.
func evalFirstKnown(e *evaluator, src *pv.Map) (outcome, error) {
	of, err := item(src, "of")
	if err != nil {
		return outcome{}, err
	}
	items, err := pv.Iter(of)
	if err != nil {
		return outcome{}, err
	}
	res := outcome{"unknown", "no sources"}
	for _, s := range items {
		if res, err = e.evaluate(s); err != nil || res.status != "unknown" {
			return res, err
		}
	}
	return res, nil
}

// evalAttestation decides the control from its own attestation.
func evalAttestation(e *evaluator, _ *pv.Map) (outcome, error) {
	c := e.current
	res, err := attestationStatus(c, e.att.Value(c.ID), e.now)
	if err != nil {
		return outcome{}, err
	}
	c.Expires, c.hasExpires = res.expires, res.hasExpiry
	return res.outcome, nil
}

func evalNone(_ *evaluator, src *pv.Map) (outcome, error) {
	return outcome{"not_implemented", pv.Str(src.GetOr("reason", "not implemented yet"))}, nil
}

// evalSLI passes while the ledger's SLI meets its objective.
func evalSLI(e *evaluator, src *pv.Map) (outcome, error) {
	sli, err := e.in.ledgerSection("sli")
	if err != nil {
		return outcome{}, err
	}
	name, err := item(src, "sli")
	if err != nil {
		return outcome{}, err
	}
	s, found := lookup(sli, name)
	if !found || s == nil {
		return outcome{"unknown", "SLI " + pv.Str(name) + " not computed yet"}, nil
	}
	m, ok := s.(*pv.Map)
	if !ok {
		return outcome{}, pv.AttributeError(s, "get")
	}
	status := "fail"
	if pv.Truthy(m.Value("ok")) {
		status = "pass"
	}
	return outcome{status, "SLI " + pv.Str(name) + " = " + pv.Str(m.Value("value")) + " (objective <= " +
		pv.Str(m.Value("target")) + ")"}, nil
}

// lookup is m.get(key) for a key value: text keys only (a key of another type is never found).
func lookup(m *pv.Map, key any) (any, bool) {
	s, ok := key.(string)
	if !ok {
		return nil, false
	}
	return m.Get(s)
}
