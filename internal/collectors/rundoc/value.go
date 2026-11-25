package rundoc

import (
	"strconv"

	"github.com/MIERAI/security-platform/internal/collectors/cloud/pyjson"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// Get is d.get(key) on a mapping; nil when v is not a mapping or the key is absent.
func Get(v any, key string) any {
	if m, ok := v.(*pyvalue.Map); ok {
		return m.Value(key)
	}
	return nil
}

// Map returns v as a mapping (an empty one for anything else: `x.get(k) or {}`).
func Map(v any) *pyvalue.Map {
	if m, ok := v.(*pyvalue.Map); ok && m != nil {
		return m
	}
	return pyvalue.NewMap()
}

// List returns v as a sequence (nil for anything else: `x.get(k) or []`).
func List(v any) []any {
	if l, ok := v.([]any); ok {
		return l
	}
	return nil
}

// Str returns v as text when it is text, "" otherwise (a value read where text is expected).
func Str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// StrOr returns v as text when it is non-empty text, def otherwise (`x.get(k) or def` for text).
func StrOr(v any, def string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return def
}

// Strings returns the text elements of a sequence (other elements skipped).
func Strings(v any) []string {
	var out []string
	for _, e := range List(v) {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// Loose turns a pyvalue document into a JSON value the evidence writer accepts: mappings become map[string]any,
// dates their text (Python's json.dumps(default=str)), everything else unchanged.
func Loose(v any) any {
	switch x := v.(type) {
	case *pyvalue.Map:
		if x == nil {
			return nil
		}
		m := make(map[string]any, x.Len())
		for _, k := range x.Keys() {
			m[k] = Loose(x.Value(k))
		}
		return m
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = Loose(e)
		}
		return out
	case pyvalue.Date:
		return x.String()
	case pyvalue.DateTime:
		return x.String()
	default:
		return v
	}
}

// FormatG is Python's format(v, "g") (the SDK prints metric values with it).
func FormatG(v float64) string { return pyvalue.FormatG(v) }

// FloatRepr is Python's repr(float).
func FloatRepr(v float64) string { return pyjson.FloatRepr(v) }

// Itoa is strconv.Itoa (for labels and titles).
func Itoa(n int) string { return strconv.Itoa(n) }
