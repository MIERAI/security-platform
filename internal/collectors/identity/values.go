package identity

import (
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// The adapter's records are JSON objects (pyjson) with the values the APIs returned, as the Python adapter keeps
// them; these helpers read them with Python's semantics (dict.get, truthiness, str()).

// object builds a record from alternating keys and values.
func object(kv ...any) *pyjson.Object {
	o := pyjson.NewObject()
	for i := 0; i+1 < len(kv); i += 2 {
		k, _ := kv[i].(string) // keys are literals of this package
		o.Set(k, kv[i+1])
	}
	return o
}

// get is dict.get(key) on a JSON value (nil when v is not an object or has no such key).
func get(v pyjson.Value, key string) pyjson.Value {
	o, ok := v.(*pyjson.Object)
	if !ok || o == nil {
		return nil
	}
	x, _ := o.Get(key)
	return x
}

// has reports whether v is an object with key.
func has(v pyjson.Value, key string) bool {
	o, ok := v.(*pyjson.Object)
	return ok && o != nil && o.Has(key)
}

// list is v as a JSON array (nil otherwise).
func list(v pyjson.Value) []pyjson.Value {
	l, _ := v.([]pyjson.Value) // not an array: empty
	return l
}

// truthy is Python's bool() of a JSON or YAML value.
func truthy(v any) bool {
	switch x := v.(type) {
	case *pyjson.Object:
		return x != nil && x.Len() > 0
	case pyjson.BigInt:
		return x != "0"
	default:
		return pyvalue.Truthy(v)
	}
}

// isNone reports a JSON null (or a missing key read with get).
func isNone(v pyjson.Value) bool { return v == nil }

// isFalse is Python's `v is False`.
func isFalse(v pyjson.Value) bool {
	b, ok := v.(bool)
	return ok && !b
}

// pyStr is Python's str() of a JSON value (f-string formatting).
func pyStr(v pyjson.Value) string {
	switch x := v.(type) {
	case string:
		return x
	case *pyjson.Object:
		return repr(x)
	case []pyjson.Value:
		return repr(x)
	case pyjson.BigInt:
		return string(x)
	case int:
		return strconv.Itoa(x)
	default:
		return pyvalue.Str(v)
	}
}

// repr is Python's repr() of a JSON value.
func repr(v pyjson.Value) string {
	switch x := v.(type) {
	case string:
		return reprString(x)
	case []pyjson.Value:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = repr(e)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case *pyjson.Object:
		if x == nil {
			return "None"
		}
		keys := x.Keys()
		parts := make([]string, len(keys))
		for i, k := range keys {
			e, _ := x.Get(k)
			parts[i] = reprString(k) + ": " + repr(e)
		}
		return "{" + strings.Join(parts, ", ") + "}"
	default:
		return pyStr(v)
	}
}

// reprString quotes s as Python's repr does: single quotes unless s holds one and no double quote.
func reprString(s string) string {
	q := byte('\'')
	if strings.ContainsRune(s, '\'') && !strings.ContainsRune(s, '"') {
		q = '"'
	}
	var b strings.Builder
	b.WriteByte(q)
	for _, r := range s {
		switch {
		case r == '\\' || r == rune(q):
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case !unicode.IsPrint(r) || r == utf8.RuneError:
			b.WriteString(escapeRune(r))
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte(q)
	return b.String()
}

// escapeRune is Python's escape of a non-printable character: \xhh, \uhhhh or \Uhhhhhhhh.
func escapeRune(r rune) string {
	h := strconv.FormatInt(int64(r), 16)
	switch {
	case r < 0x100:
		return `\x` + strings.Repeat("0", 2-len(h)) + h
	case r < 0x10000:
		return `\u` + strings.Repeat("0", 4-len(h)) + h
	default:
		return `\U` + strings.Repeat("0", 8-len(h)) + h
	}
}

// pyIn is Python's `x in container` for a string x and a JSON container (substring for a string container).
func pyIn(x string, container pyjson.Value) bool {
	switch c := container.(type) {
	case string:
		return strings.Contains(c, x)
	case []pyjson.Value:
		for _, e := range c {
			if s, ok := e.(string); ok && s == x {
				return true
			}
		}
	case *pyjson.Object:
		return c != nil && c.Has(x)
	}
	return false
}

// iterStrings is `for d in v` over a JSON value, keeping the string elements (characters of a string).
func iterStrings(v pyjson.Value) []string {
	switch c := v.(type) {
	case string:
		out := make([]string, 0, len(c))
		for _, r := range c {
			out = append(out, string(r))
		}
		return out
	case []pyjson.Value:
		out := make([]string, 0, len(c))
		for _, e := range c {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case *pyjson.Object:
		if c == nil {
			return nil
		}
		return c.Keys()
	}
	return nil
}

// strList is a list of strings as a JSON array.
func strList(s []string) []pyjson.Value {
	out := make([]pyjson.Value, len(s))
	for i, x := range s {
		out[i] = x
	}
	return out
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
