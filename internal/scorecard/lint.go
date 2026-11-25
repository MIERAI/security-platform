package scorecard

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	pv "github.com/MIERAI/security-platform/internal/pyvalue"
)

// controlID is the form of a control id: <dimension>.<name>, lowercase. Compiled once, never written.
var controlID = regexp.MustCompile(`^[a-z0-9-]+\.[a-z0-9_.-]+$`)

const (
	checksText     = "('automated', 'attested', 'evidence')"
	functionsText  = "['DE', 'GV', 'ID', 'PR', 'RC', 'RS']"
	pillarsText    = "['network', 'device', 'people', 'software']"
	evaluatorsText = "['all', 'any', 'attestation', 'builtin', 'collector_fresh', 'file', 'findings', 'first_known', " +
		"'job', 'metric', 'none', 'sli']"
)

// Lint checks the catalog against the catalog contract and returns one message per problem.
func Lint(cat *Catalog) []string {
	var errs []string
	for _, d := range cat.Dims {
		where := "dimension " + pv.Str(d.raw.Value("id"))
		for _, k := range []string{"id", "title", "order"} {
			if !d.raw.Has(k) {
				errs = append(errs, where+": "+k+" missing")
			}
		}
		errs = lintApplies(where, d.raw.Value("applies_when"), d.raw.Has("applies_when"), errs)
	}
	for _, c := range cat.Controls {
		errs = append(errs, lintControl(c)...)
	}
	return errs
}

func lintControl(c *Control) []string {
	var errs []string
	add := func(msg string) { errs = append(errs, c.ID+": "+msg) }
	switch {
	case !controlID.MatchString(c.ID):
		add("id must be <dimension>.<name> (lowercase)")
	case strings.SplitN(c.ID, ".", 2)[0] != c.Dimension:
		add("id prefix must be its dimension " + pv.Repr(c.Dimension) + " (one catalog file per dimension)")
	}
	for _, k := range []string{"title", "csf", "check", "weight"} {
		if !c.raw.Has(k) {
			add(k + " missing")
		}
	}
	if !oneOf(c.get("check"), "automated", "attested", "evidence") {
		add("check must be one of " + checksText)
	}
	errs = lintApplies(c.ID, c.get("applies_when"), c.raw.Has("applies_when"), errs)
	if !textList(c.raw.GetOr("tags", []any{})) {
		add("tags must be a list of strings")
	}
	if _, ok := functionTitles()[c.Function]; !ok {
		add("csf " + pv.Repr(c.get("csf")) + " must start with one of " + functionsText)
	}
	if !validPillars(c.get("pillars")) {
		add("pillars must be a non-empty subset of " + pillarsText)
	}
	if w, ok := numberValue(c.get("weight")); !ok || w < 0 {
		add("weight must be a number >= 0")
	}
	return append(errs, lintSources(c)...)
}

func lintSources(c *Control) []string {
	var errs []string
	add := func(msg string) { errs = append(errs, c.ID+": "+msg) }
	if oneOf(c.get("check"), "automated", "evidence") {
		src, _ := orEmpty(c.get("source"))
		name, _ := src.Value("type").(string)
		if _, ok := evaluators()[name]; !ok || src == nil {
			add("source.type must be one of " + evaluatorsText)
		}
	}
	if !c.isAttested() && !attestable(c) {
		return errs
	}
	if _, err := duration(c.get("validity"), 0); err != nil {
		add("validity: " + strings.TrimPrefix(err.Error(), "ValueError: "))
	}
	if !pv.Truthy(c.get("validity")) {
		add("attested controls need a validity (e.g. 90d): attestations expire and reopen")
	}
	if !pv.Truthy(c.get("question")) {
		add("attested controls need the question a human answers")
	}
	return errs
}

// lintApplies checks an applies_when: exactly one of instance, coverage_prefix, any (whose items are checked).
func lintApplies(where string, spec any, present bool, errs []string) []string {
	if !present || spec == nil {
		return errs
	}
	m, ok := spec.(*pv.Map)
	if !ok || m.Len() != 1 || !oneOf(m.Keys()[0], "instance", "coverage_prefix", "any") {
		return append(errs, where+": applies_when must be one of {instance: <dotted key>}, "+
			"{coverage_prefix: <asset prefix>}, {any: [..]}")
	}
	if !m.Has("any") || !pv.Truthy(m.Value("any")) {
		return errs
	}
	items, err := pv.Iter(m.Value("any"))
	if err != nil {
		return append(errs, where+": applies_when.any must be a list")
	}
	for i, x := range items {
		errs = lintApplies(fmt.Sprintf("%s.any[%d]", where, i), x, true, errs)
	}
	return errs
}

func oneOf(v any, options ...string) bool {
	for _, o := range options {
		if pv.Equal(v, o) {
			return true
		}
	}
	return false
}

func textList(v any) bool {
	l, ok := v.([]any)
	if !ok {
		return false
	}
	for _, x := range l {
		if _, ok := x.(string); !ok {
			return false
		}
	}
	return true
}

func validPillars(v any) bool {
	if !pv.Truthy(v) {
		return false
	}
	items, err := pv.Iter(v)
	if err != nil {
		return false
	}
	for _, x := range items {
		if !oneOf(x, pillarOrder()...) {
			return false
		}
	}
	return true
}

// numberValue is a numeric value (bool, int or float) as a float.
func numberValue(v any) (float64, bool) { return pv.ToFloat64(v) }

// padRight pads s with spaces to n characters.
func padRight(s string, n int) string {
	if k := utf8.RuneCountInString(s); k < n {
		return s + strings.Repeat(" ", n-k)
	}
	return s
}

// listLine is one line of `list`: id, check, weight, pillars, csf, title in fixed-width columns.
func listLine(c *Control) (string, error) {
	check, ok1 := c.get("check").(string)
	csf, ok2 := c.raw.GetOr("csf", "").(string)
	pillars, err := pv.JoinStrings(",", c.get("pillars"))
	if !ok1 || !ok2 || err != nil {
		return "", configErr("%s: check, csf and pillars must be text", c.ID)
	}
	w, _ := pv.ToFloat64(c.get("weight")) // a number (validateForCompute)
	return padRight(c.ID, 45) + " " + padRight(check, 9) + " w=" + padRight(pv.FormatG(w), 3) + " " +
		padRight(pillars, 24) + " " + padRight(csf, 8) + " " + pv.Str(c.get("title")), nil
}
