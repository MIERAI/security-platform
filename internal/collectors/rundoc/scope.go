package rundoc

import (
	"errors"
	"fmt"
	"strings"

	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// GapError is a target a run cannot cover: it becomes a coverage gap with Reason; it does not fail the run.
type GapError struct{ Reason string }

func (e *GapError) Error() string { return e.Reason }

// Gap returns a GapError.
func Gap(reason string) error { return &GapError{Reason: reason} }

// AsGap is the reason of the GapError in err's chain.
func AsGap(err error) (string, bool) {
	var g *GapError
	if errors.As(err, &g) {
		return g.Reason, true
	}
	return "", false
}

// Targets is the list at key of the instance with every element a mapping that has nameKey (absent or null:
// none); anything else is a configuration error (ErrUsage).
func Targets(inst *pyvalue.Map, key, nameKey string) ([]*pyvalue.Map, error) {
	var items []any
	switch v := inst.Value(key).(type) {
	case nil:
	case []any:
		items = v
	default:
		return nil, fmt.Errorf("%w: %s must be a list, not %s", ErrUsage, key, pyvalue.TypeName(v))
	}
	out := make([]*pyvalue.Map, len(items))
	for i, it := range items {
		m, ok := it.(*pyvalue.Map)
		if !ok || !m.Has(nameKey) {
			return nil, fmt.Errorf("%w: %s[%d] needs %s", ErrUsage, key, i, nameKey)
		}
		out[i] = m
	}
	return out, nil
}

// InScope is false when the instance's `scope:` limits the asset `name` to other collectors (it is then skipped,
// not a gap): the first entry whose `names` holds name decides (spsdk.in_scope).
func InScope(inst *pyvalue.Map, name any, collector string) bool {
	scopes, _ := inst.Value("scope").([]any) // absent or not a list: no per-asset scope
	for _, s := range scopes {
		sm, ok := s.(*pyvalue.Map)
		if !ok {
			continue
		}
		if in, err := pyvalue.In(name, orEmpty(sm.Value("names"))); err == nil && in {
			ok, err := pyvalue.In(collector, orEmpty(sm.Value("scope")))
			return err == nil && ok
		}
	}
	return true
}

func orEmpty(v any) any {
	if !pyvalue.Truthy(v) {
		return []any{}
	}
	return v
}

// SafeFileName reports whether a configured name can be a file name inside the run directory (evidence files are
// named after hosts): no path separators, not "." or "..", no NUL.
func SafeFileName(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.ContainsAny(s, "/\\\x00")
}
