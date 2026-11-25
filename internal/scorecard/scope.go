package scorecard

import (
	"regexp"
	"sort"
	"strings"

	pv "github.com/MIERAI/security-platform/internal/scorecard/pyvalue"
)

// applicable decides a dimension's or control's applies_when (SPEC §3): true with no condition; else the
// reason it does not apply.
func applicable(spec, inst any, in *inputs) (bool, string, error) {
	if !pv.Truthy(spec) {
		return true, "", nil
	}
	m, ok := spec.(*pv.Map)
	if !ok {
		return false, "", configErr("applies_when must be a mapping, not %s", pv.Repr(spec))
	}
	switch {
	case m.Has("any"):
		return applicableAny(m.Value("any"), inst, in)
	case m.Has("instance"):
		key := pv.Str(m.Value("instance"))
		if pv.Truthy(dotted(inst, key)) {
			return true, "", nil
		}
		return false, "instance has no " + key, nil
	case m.Has("coverage_prefix"):
		return coveragePrefix(m.Value("coverage_prefix"), in)
	}
	return true, "", nil
}

func applicableAny(list, inst any, in *inputs) (bool, string, error) {
	if !pv.Truthy(list) {
		return false, "", nil
	}
	items, err := pv.Iter(list)
	if err != nil {
		return false, "", configErr("applies_when.any: %v", err)
	}
	var reasons []string
	for _, x := range items {
		ok, why, err := applicable(x, inst, in)
		if err != nil || ok {
			return ok, "", err
		}
		reasons = append(reasons, why)
	}
	return false, strings.Join(reasons, " and "), nil
}

// dotted is the value at a dotted key of the instance, nil when a step is not a mapping.
func dotted(inst any, key string) any {
	v := inst
	if !pv.Truthy(v) {
		v = pv.NewMap()
	}
	for _, k := range strings.Split(key, ".") {
		m, ok := v.(*pv.Map)
		if !ok {
			return nil
		}
		v = m.Value(k)
	}
	return v
}

func coveragePrefix(prefix any, in *inputs) (bool, string, error) {
	for _, g := range in.coverage {
		hit, err := pv.HasPrefix(g.asset, prefix)
		if err != nil {
			return false, "", configErr("coverage_prefix: %v", err)
		}
		if hit {
			return true, "", nil
		}
	}
	return false, "no " + pv.Str(prefix) + "* asset in scope", nil
}

// lintInstance checks the instance's scorecard block: unconfigured_collectors and not_applicable reasons.
func lintInstance(sc *pv.Map) []string {
	var errs []string
	u := sc.GetOr("unconfigured_collectors", "unknown")
	if !pv.Equal(u, "unknown") && !pv.Equal(u, "not_applicable") {
		errs = append(errs, "unconfigured_collectors must be unknown or not_applicable")
	}
	na, ok := orEmpty(sc.Value("not_applicable"))
	if !ok {
		return append(errs, "not_applicable must be a map {<control id | glob | tag:<tag>>: <reason>}")
	}
	for _, k := range na.Keys() {
		v := na.Value(k)
		if !pv.Truthy(v) || strings.TrimFunc(pv.Str(v), isSpace) == "" {
			errs = append(errs, "not_applicable "+pv.Repr(k)+": a reason is required")
		}
	}
	return errs
}

// scope holds the instance's scope decisions (SPEC §3): not_applicable selectors in order, whether controls
// of unconfigured collectors are out of scope, and the collectors this instance runs or has run.
type scope struct {
	selectors  []selector
	naUnconfig bool
	configured map[string]bool
}

type selector struct {
	text   string
	reason any
	tag    string         // for tag:<tag>
	glob   *regexp.Regexp // for an id or glob
}

func newScope(sc *pv.Map, inst any, in *inputs) (*scope, error) {
	s := &scope{naUnconfig: pv.Equal(sc.GetOr("unconfigured_collectors", "unknown"), "not_applicable")}
	na, _ := orEmpty(sc.Value("not_applicable")) // checked by lintInstance
	for _, k := range na.Keys() {
		sel := selector{text: k, reason: na.Value(k)}
		if t, ok := strings.CutPrefix(k, "tag:"); ok {
			sel.tag = t
		} else {
			re, err := globRegexp(k)
			if err != nil {
				return nil, configErr("not_applicable: %v", err)
			}
			sel.glob = re
		}
		s.selectors = append(s.selectors, sel)
	}
	var err error
	s.configured, err = configuredCollectors(inst, in)
	return s, err
}

// configuredCollectors: every collector of the ledger and of the newest documents, and every collector or
// command job of the runner (its name, collector and as).
func configuredCollectors(inst any, in *inputs) (map[string]bool, error) {
	out := map[string]bool{}
	cols, err := in.ledgerSection("collectors")
	if err != nil {
		return nil, configErr("ledger collectors: %v", err)
	}
	for _, k := range cols.Keys() {
		out[k] = true
	}
	for _, g := range in.coverage {
		out[collectorKey(g.collector)] = true
	}
	jobs, err := runnerJobs(inst)
	if err != nil {
		return nil, err
	}
	for _, name := range jobs.Keys() {
		addJobCollectors(out, name, jobs.Value(name))
	}
	return out, nil
}

func runnerJobs(inst any) (*pv.Map, error) {
	root, ok := orEmpty(inst)
	if !ok {
		return nil, configErr("the instance is not a mapping")
	}
	runner, err := section(root, "runner", "")
	if err != nil {
		return nil, err
	}
	return section(runner, "jobs", "runner.")
}

func addJobCollectors(out map[string]bool, name string, job any) {
	j, ok := orEmpty(job)
	if !ok {
		return
	}
	t := j.GetOr("type", "collector")
	if !pv.Equal(t, "collector") && !pv.Equal(t, "command") {
		return
	}
	out[name] = true
	for _, k := range []string{"collector", "as"} {
		if v := j.Value(k); pv.Truthy(v) {
			out[collectorKey(v)] = true
		}
	}
}

// decide is the instance's scope for one control: "" when in scope, else the reason it is not.
func (s *scope) decide(c *Control) (bool, string, error) {
	if d := c.get("disabled"); pv.Truthy(d) {
		if text, ok := d.(string); ok {
			return false, "disabled by the instance: " + text, nil
		}
		return false, "disabled by the instance", nil
	}
	tags, err := controlTags(c)
	if err != nil {
		return false, "", err
	}
	for _, sel := range s.selectors {
		if (sel.glob == nil && tags[sel.tag]) || (sel.glob != nil && sel.glob.MatchString(c.ID)) {
			return false, "out of scope for the instance (" + sel.text + "): " + pv.Str(sel.reason), nil
		}
	}
	if s.naUnconfig && !attestable(c) {
		return s.unconfigured(c)
	}
	return true, "", nil
}

func (s *scope) unconfigured(c *Control) (bool, string, error) {
	req := map[string]bool{}
	requiredCollectors(c.get("source"), req)
	names := make([]string, 0, len(req))
	for n := range req {
		if s.configured[n] {
			return true, "", nil
		}
		names = append(names, n)
	}
	if len(names) == 0 {
		return true, "", nil
	}
	sort.Strings(names)
	return false, "collector not configured: " + strings.Join(names, ", "), nil
}

func controlTags(c *Control) (map[string]bool, error) {
	tags := map[string]bool{}
	t := c.get("tags")
	if !pv.Truthy(t) {
		return tags, nil
	}
	items, err := pv.Iter(t)
	if err != nil {
		return nil, configErr("%s: tags: %v", c.ID, err)
	}
	for _, x := range items {
		if s, ok := x.(string); ok {
			tags[s] = true
		}
	}
	return tags, nil
}
