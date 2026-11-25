package scorecard

import (
	"sort"
	"strings"

	pv "github.com/MIERAI/security-platform/internal/scorecard/pyvalue"
)

// buildControls derives every control's function (the CSF function, the part of `csf` before the first dot),
// defaults weight 1 and cis [], and sorts the controls by dimension order, then id.
func (cat *Catalog) buildControls(idx *controlIndex) error {
	cat.Controls = make([]*Control, 0, len(idx.ids))
	keys := map[*Control]float64{}
	for _, id := range idx.ids {
		raw := idx.byID[id]
		c, err := newControl(raw)
		if err != nil {
			return err
		}
		k, err := orderKey(cat.dimByID[c.Dimension])
		if err != nil {
			return err
		}
		keys[c] = k
		cat.Controls = append(cat.Controls, c)
	}
	sort.SliceStable(cat.Controls, func(i, j int) bool {
		a, b := cat.Controls[i], cat.Controls[j]
		if keys[a] != keys[b] {
			return keys[a] < keys[b]
		}
		return a.ID < b.ID
	})
	return nil
}

func newControl(raw *pv.Map) (*Control, error) {
	id, ok := raw.Value("id").(string)
	if !ok {
		return nil, configErr("a control needs a text id")
	}
	dim, ok := raw.Value("dimension").(string)
	if !ok {
		return nil, configErr("%s: dimension must be text", id)
	}
	fn, _, _ := strings.Cut(pv.Str(raw.GetOr("csf", "")), ".")
	raw.Set("function", fn)
	raw.SetDefault("weight", int64(1))
	raw.SetDefault("cis", []any{})
	return &Control{raw: raw, ID: id, Dimension: dim, Function: fn}, nil
}

// validateForCompute checks what computing needs of a control (title, check, a numeric weight).
func validateForCompute(c *Control) error {
	for _, k := range []string{"title", "check"} {
		if !c.raw.Has(k) {
			return configErr("%s: %s missing", c.ID, k)
		}
	}
	if _, ok := pv.ToFloat64(c.get("weight")); !ok {
		return configErr("%s: weight must be a number", c.ID)
	}
	return nil
}

// attestable: a human may attest the control (check attested, or a source that names the attestation type
// anywhere).
func attestable(c *Control) bool {
	return c.isAttested() || mentions(c.get("source"), "attestation")
}

// mentions reports whether a key or a text value anywhere in v equals s.
func mentions(v any, s string) bool {
	switch x := v.(type) {
	case string:
		return x == s
	case []any:
		for _, e := range x {
			if mentions(e, s) {
				return true
			}
		}
	case *pv.Map:
		for _, k := range x.Keys() {
			if k == s || mentions(x.Value(k), s) {
				return true
			}
		}
	}
	return false
}

// requiredCollectors lists every require_collector named anywhere in a source ("*" excluded).
func requiredCollectors(src any, out map[string]bool) {
	switch x := src.(type) {
	case *pv.Map:
		if req := x.Value("require_collector"); pv.Truthy(req) && !pv.Equal(req, "*") {
			for _, n := range pv.AsList(req) {
				out[collectorKey(n)] = true
			}
		}
		for _, k := range x.Keys() {
			requiredCollectors(x.Value(k), out)
		}
	case []any:
		for _, e := range x {
			requiredCollectors(e, out)
		}
	}
}

// collectorKey identifies a collector name value: text as is, anything else by its type and representation
// (never equal to a text name, which cannot hold a NUL).
func collectorKey(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return "\x00" + pv.TypeName(v) + ":" + pv.Repr(v)
}
