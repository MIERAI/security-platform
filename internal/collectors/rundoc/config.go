package rundoc

import (
	"sort"

	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// Map is v as a mapping (nil when it is not one; every accessor of a nil *pyvalue.Map reads as absent).
func Map(v any) *pyvalue.Map {
	m, _ := v.(*pyvalue.Map) // not a mapping: absent
	return m
}

// List is v as a sequence (nil when it is not one).
func List(v any) []any {
	l, _ := v.([]any) // not a sequence: empty
	return l
}

// Str is a configured value as text: a string as it is, "" when absent or null, Python's str() otherwise.
func Str(v any) string {
	if v == nil {
		return ""
	}
	return pyvalue.Str(v)
}

// Strings is a configured sequence of values as text (Str of each element).
func Strings(v any) []string {
	l := List(v)
	out := make([]string, 0, len(l))
	for _, x := range l {
		out = append(out, Str(x))
	}
	return out
}

// Float is a configured number (def when absent, null or not a number).
func Float(v any, def float64) float64 {
	if v == nil {
		return def
	}
	if f, err := pyvalue.ToFloat(v); err == nil {
		return f
	}
	return def
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
