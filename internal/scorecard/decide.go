package scorecard

import (
	"sort"
	"strings"

	pv "github.com/MIERAI/security-platform/internal/pyvalue"
)

// decideWithoutSource settles a control that needs no evaluator (SPEC §3 steps 1-3): not applicable (catalog,
// instance or a human), attested, or a source with an unset ${var}. Otherwise it returns the source to evaluate.
func (e *evaluator) decideWithoutSource(c *Control, s *scope, inst any, dimNA map[string]string,
	vars map[string]string) (*pv.Map, bool, error) {
	a := e.att.Value(c.ID)
	humanNA, by, err := humanNotApplicable(a, e.now)
	if err != nil {
		return nil, false, err
	}
	c.Expires, c.hasExpires = 0, false
	ok, why, err := e.inScope(c, s, inst)
	if err != nil {
		return nil, false, err
	}
	if reason, dimOut := dimNA[c.Dimension]; dimOut || !ok {
		if reason == "" {
			reason = why
		}
		c.Status, c.Detail = "na", "not applicable: "+reason
		return nil, true, nil
	}
	if pv.Truthy(humanNA) {
		c.Status, c.Detail = "na", "not applicable (approved by "+pv.Str(by)+"): "+pv.Str(humanNA)
		return nil, true, nil
	}
	if c.isAttested() {
		res, err := attestationStatus(c, a, e.now)
		if err != nil {
			return nil, false, configErr("%s: attestation: %v", c.ID, err)
		}
		c.Status, c.Detail, c.Expires, c.hasExpires = res.status, res.detail, res.expires, res.hasExpiry
		return nil, true, nil
	}
	return e.source(c, vars)
}

func (e *evaluator) inScope(c *Control, s *scope, inst any) (bool, string, error) {
	ok, why, err := applicable(c.get("applies_when"), inst, e.in)
	if err != nil || !ok {
		return ok, why, err
	}
	return s.decide(c)
}

// source is the control's source with its variables substituted; unknown when one is not set.
func (e *evaluator) source(c *Control, vars map[string]string) (*pv.Map, bool, error) {
	raw := c.get("source")
	if !pv.Truthy(raw) {
		raw = pv.NewMap()
	}
	missing := map[string]bool{}
	src := substitute(raw, vars, missing)
	if len(missing) > 0 {
		names := make([]string, 0, len(missing))
		for n := range missing {
			names = append(names, n)
		}
		sort.Strings(names)
		c.Status, c.Detail = "unknown", "configure scorecard.vars: "+strings.Join(names, ", ")
		return nil, true, nil
	}
	m, ok := src.(*pv.Map)
	if !ok {
		return nil, false, configErr("%s: source must be a mapping", c.ID)
	}
	return m, false, nil
}

// buildVars: data and product, then the instance's scorecard.vars (which may not redefine them).
func buildVars(sc *pv.Map, data, product string) (map[string]string, error) {
	vars := map[string]string{"data": data, "product": product}
	own, ok := orEmpty(sc.Value("vars"))
	if !ok {
		return nil, configErr("scorecard.vars must be a mapping")
	}
	for _, k := range own.Keys() {
		if _, taken := vars[k]; taken {
			return nil, configErr("scorecard.vars may not set %s", k)
		}
		vars[k] = pv.Str(own.Value(k))
	}
	return vars, nil
}

// substitute replaces ${name} in every text value (mapping keys are left alone) and records unset names.
func substitute(v any, vars map[string]string, missing map[string]bool) any {
	switch x := v.(type) {
	case string:
		return variable.ReplaceAllStringFunc(x, func(m string) string {
			name := m[2 : len(m)-1]
			if val, ok := vars[name]; ok {
				return val
			}
			missing[name] = true
			return m
		})
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = substitute(e, vars, missing)
		}
		return out
	case *pv.Map:
		out := pv.NewMap()
		for _, k := range x.Keys() {
			out.Set(k, substitute(x.Value(k), vars, missing))
		}
		return out
	}
	return v
}
