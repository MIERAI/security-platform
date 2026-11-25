package events

import (
	"sort"

	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// item is v[key] on an API record: KeyError when absent, TypeError when v is not an object.
func item(v any, key string) (any, error) {
	m, ok := v.(*pyvalue.Map)
	if !ok {
		return nil, pyErr("TypeError", subscriptMsg(v))
	}
	x, ok := m.Get(key)
	if !ok {
		return nil, keyError(key)
	}
	return x, nil
}

func subscriptMsg(v any) string {
	switch v.(type) {
	case []any:
		return "list indices must be integers or slices, not str"
	case string:
		return "string indices must be integers, not 'str'"
	}
	return "'" + pyvalue.TypeName(v) + "' object is not subscriptable"
}

// getOr is v.get(key, def) on an API record: AttributeError when v is not an object.
func getOr(v any, key string, def any) (any, error) {
	m, ok := v.(*pyvalue.Map)
	if !ok {
		return nil, pyErr("AttributeError", "'"+pyvalue.TypeName(v)+"' object has no attribute 'get'")
	}
	return m.GetOr(key, def), nil
}

// iterate is `for x in v`: a list's elements, an object's keys, a text's characters.
func iterate(v any) ([]any, error) {
	switch x := v.(type) {
	case []any:
		return x, nil
	case *pyvalue.Map:
		out := make([]any, 0, x.Len())
		for _, k := range x.Keys() {
			out = append(out, k)
		}
		return out, nil
	case string:
		out := []any{}
		for _, r := range x {
			out = append(out, string(r))
		}
		return out, nil
	}
	return nil, pyErr("TypeError", "'"+pyvalue.TypeName(v)+"' object is not iterable")
}

// or is Python's `a or b or c`: the first truthy value, else the last.
func or(vals ...any) any {
	for _, v := range vals[:len(vals)-1] {
		if pyvalue.Truthy(v) {
			return v
		}
	}
	return vals[len(vals)-1]
}

// sortedIDs is sorted(ids) for text or integer ids (a mix is a TypeError, as in Python).
func sortedIDs(ids []any) ([]any, error) {
	var texts []string
	var ints []int64
	for _, x := range ids {
		switch v := x.(type) {
		case string:
			texts = append(texts, v)
		case int64:
			ints = append(ints, v)
		default:
			return nil, pyErr("TypeError", "'<' not supported between instances of '"+pyvalue.TypeName(x)+"'")
		}
	}
	if len(texts) > 0 && len(ints) > 0 {
		return nil, pyErr("TypeError", "'<' not supported between instances of 'int' and 'str'")
	}
	sort.Strings(texts)
	sort.Slice(ints, func(i, j int) bool { return ints[i] < ints[j] })
	out := make([]any, 0, len(ids))
	for _, s := range texts {
		out = append(out, s)
	}
	for _, n := range ints {
		out = append(out, n)
	}
	return out, nil
}

// unionIDs is set(a) | set(b) as a list (hashable scalars only).
func unionIDs(a, b []any) []any {
	seen := map[any]bool{}
	var out []any
	for _, x := range append(append([]any(nil), a...), b...) {
		switch x.(type) {
		case string, int64, bool, nil:
			if !seen[x] {
				seen[x] = true
				out = append(out, x)
			}
		default:
			out = append(out, x) // unhashable: sortedIDs reports it
		}
	}
	return out
}

// tail is l[-n:].
func tail(l []any, n int) []any {
	if len(l) > n {
		return l[len(l)-n:]
	}
	return l
}
