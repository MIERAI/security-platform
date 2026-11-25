package vulnintel

import (
	"sort"
	"strings"

	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
)

// The helpers below read decoded JSON (trivy reports, inventories, feeds) the way the Python collector reads its
// dicts: a missing key or a value of another type reads as absent instead of failing the run.

func obj(v pyjson.Value) *pyjson.Object {
	o, _ := v.(*pyjson.Object) // not an object: absent
	return o
}

func get(o *pyjson.Object, key string) pyjson.Value {
	if o == nil {
		return nil
	}
	v, _ := o.Get(key)
	return v
}

// getOr is Python's d.get(key, def): def only when the key is absent (a present null stays null).
func getOr(o *pyjson.Object, key string, def pyjson.Value) pyjson.Value {
	if o == nil {
		return def
	}
	if v, ok := o.Get(key); ok {
		return v
	}
	return def
}

func sget(o *pyjson.Object, key string) string {
	s, _ := get(o, key).(string) // not a string: ""
	return s
}

func oget(o *pyjson.Object, key string) *pyjson.Object { return obj(get(o, key)) }

func lget(o *pyjson.Object, key string) []pyjson.Value {
	l, _ := get(o, key).([]pyjson.Value) // not a list: empty
	return l
}

func truthy(o *pyjson.Object, key string) bool { return pyjson.Truthy(get(o, key)) }

// strs is the string elements of a list (others dropped).
func strs(l []pyjson.Value) []string {
	out := make([]string, 0, len(l))
	for _, v := range l {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// pystr is Python's str() of a JSON value, as an f-string prints it.
func pystr(v pyjson.Value) string { return pyjson.Str(v) }

// cut is Python's s[:n] (characters); tail is s[-n:].
func cut(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

func tail(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[len(r)-n:])
}

// strip is Python's str.strip() for the whitespace tools print.
func strip(s string) string { return strings.TrimSpace(s) }

func list(ss []string) []pyjson.Value {
	out := make([]pyjson.Value, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

// sortedSet returns the distinct strings, sorted.
func sortedSet(ss []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func noneOr(s string, ok bool) pyjson.Value {
	if !ok {
		return nil
	}
	return s
}

func first(ss []string) pyjson.Value {
	if len(ss) == 0 {
		return nil
	}
	return ss[0]
}

func firstN(ss []string, n int) []string {
	if len(ss) > n {
		return ss[:n]
	}
	return ss
}

// nonEmpty is Python's truthiness of a decoded object (a nil pointer is None).
func nonEmpty(o *pyjson.Object) bool { return o != nil && o.Len() > 0 }
