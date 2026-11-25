package scorecard

import (
	"regexp"

	pv "github.com/MIERAI/security-platform/internal/scorecard/pyvalue"
)

type compareOp func(a, b float64) bool

func compareOps() map[string]compareOp {
	return map[string]compareOp{
		"<=": func(a, b float64) bool { return a <= b }, ">=": func(a, b float64) bool { return a >= b },
		"==": func(a, b float64) bool { return a == b }, "<": func(a, b float64) bool { return a < b },
		">": func(a, b float64) bool { return a > b }, "!=": func(a, b float64) bool { return a != b },
	}
}

// evalMetric compares an aggregate of the published samples of one metric (labels matched by whole-value
// regular expressions) with a value; with `age`, the aggregate is an epoch and its age is compared with a
// duration. No sample: the `absent` status (default unknown).
func evalMetric(e *evaluator, src *pv.Map) (outcome, error) {
	match, err := labelMatchers(src.Value("match"))
	if err != nil {
		return outcome{}, err
	}
	name, err := item(src, "name")
	if err != nil {
		return outcome{}, err
	}
	vals := e.metricValues(name, match)
	if len(vals) == 0 {
		return outcome{pv.Str(src.GetOr("absent", "unknown")), "metric " + pv.Str(name) + " absent"}, nil
	}
	agg := src.GetOr("agg", "max")
	v, err := aggregate(agg, vals)
	if err != nil {
		return outcome{}, err
	}
	if pv.Truthy(src.Value("age")) {
		return metricAge(e.now-v, src, name)
	}
	opName := src.GetOr("op", "<=")
	op, err := lookupOp(opName)
	if err != nil {
		return outcome{}, err
	}
	target := src.GetOr("value", int64(0))
	t, err := pv.ToFloat(target)
	if err != nil {
		return outcome{}, err
	}
	detail := pv.Str(agg) + "(" + pv.Str(name) + ") = " + pv.FormatG(v) + " (" + pv.Str(opName) + " " + pv.Str(target) + ")"
	return verdict(op(v, t), detail), nil
}

func metricAge(age float64, src *pv.Map, name any) (outcome, error) {
	value, err := item(src, "value")
	if err != nil {
		return outcome{}, err
	}
	target, err := duration(value, 0)
	if err != nil {
		return outcome{}, err
	}
	opName := src.GetOr("op", "<=")
	op, err := lookupOp(opName)
	if err != nil {
		return outcome{}, err
	}
	return verdict(op(age, target), pv.Str(name)+" age "+ageText(age)+" ("+pv.Str(opName)+" "+pv.Str(value)+")"), nil
}

func verdict(ok bool, detail string) outcome {
	if ok {
		return outcome{"pass", detail}
	}
	return outcome{"fail", detail}
}

func lookupOp(name any) (compareOp, error) {
	s, _ := name.(string)
	op, ok := compareOps()[s]
	if !ok {
		return nil, &pv.Error{Type: "KeyError", Msg: pv.Repr(name)}
	}
	return op, nil
}

type labelMatcher struct {
	label string
	re    *regexp.Regexp
}

func labelMatchers(match any) ([]labelMatcher, error) {
	m, ok := orEmpty(match)
	if !ok {
		return nil, pv.AttributeError(match, "items")
	}
	out := make([]labelMatcher, 0, m.Len())
	for _, k := range m.Keys() {
		re, err := regexp.Compile(`^(?:` + pv.Str(m.Value(k)) + `)$`)
		if err != nil {
			return nil, &pv.Error{Type: "error", Msg: err.Error()}
		}
		out = append(out, labelMatcher{label: k, re: re})
	}
	return out, nil
}

func (e *evaluator) metricValues(name any, match []labelMatcher) []float64 {
	var vals []float64
	for _, s := range e.in.metrics {
		if !pv.Equal(s.name, name) || !labelsMatch(s, match) {
			continue
		}
		vals = append(vals, s.value)
	}
	return vals
}

func labelsMatch(s sample, match []labelMatcher) bool {
	for _, m := range match {
		if !m.re.MatchString(s.labels[m.label]) {
			return false
		}
	}
	return true
}

// aggregate is max (the first largest), min (the first smallest), sum (SPEC §4 arithmetic) or count.
func aggregate(agg any, vals []float64) (float64, error) {
	name, _ := agg.(string)
	switch name {
	case "max":
		return extreme(vals, func(a, b float64) bool { return a > b }), nil
	case "min":
		return extreme(vals, func(a, b float64) bool { return a < b }), nil
	case "sum":
		items := make([]any, len(vals))
		for i, v := range vals {
			items[i] = v
		}
		s, err := pv.Sum(items)
		f, _ := pv.ToFloat64(s)
		return f, err
	case "count":
		return float64(len(vals)), nil
	}
	return 0, &pv.Error{Type: "KeyError", Msg: pv.Repr(agg)}
}

func extreme(vals []float64, better func(a, b float64) bool) float64 {
	best := vals[0]
	for _, v := range vals[1:] {
		if better(v, best) {
			best = v
		}
	}
	return best
}
