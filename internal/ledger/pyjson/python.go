package pyjson

import (
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// Truthy is Python's bool(x).
func Truthy(v Value) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	case int64:
		return t != 0
	case int:
		return t != 0
	case BigInt:
		return true // only integers beyond int64 are kept as text
	case float64:
		return t != 0
	case []Value:
		return len(t) > 0
	case *Object:
		return t.Len() > 0
	default:
		return true
	}
}

// Str is Python's str(x).
func Str(v Value) string {
	if s, ok := v.(string); ok {
		return s
	}
	return Repr(v)
}

// Repr is Python's repr(x) for JSON-like values.
func Repr(v Value) string {
	switch t := v.(type) {
	case nil:
		return "None"
	case bool:
		if t {
			return "True"
		}
		return "False"
	case string:
		return reprString(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case int:
		return strconv.Itoa(t)
	case BigInt:
		return string(t)
	case float64:
		return FloatRepr(t)
	default:
		return reprContainer(v)
	}
}

func reprContainer(v Value) string {
	switch t := v.(type) {
	case []Value:
		parts := make([]string, len(t))
		for i, x := range t {
			parts[i] = Repr(x)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case *Object:
		parts := make([]string, 0, t.Len())
		for _, k := range t.keys {
			parts = append(parts, reprString(k)+": "+Repr(t.vals[k]))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	default:
		return "<unknown>"
	}
}

// reprString quotes like Python's str.__repr__: single quotes unless the text holds a single quote and no
// double quote; non-printable characters as \x, \u or \U escapes.
func reprString(s string) string {
	q := byte('\'')
	if strings.Contains(s, "'") && !strings.Contains(s, `"`) {
		q = '"'
	}
	var b strings.Builder
	b.WriteByte(q)
	for _, r := range s {
		b.WriteString(reprRune(r, rune(q)))
	}
	b.WriteByte(q)
	return b.String()
}

func reprRune(r, quote rune) string {
	switch r {
	case quote, '\\':
		return `\` + string(r)
	case '\t':
		return `\t`
	case '\n':
		return `\n`
	case '\r':
		return `\r`
	}
	if (r >= 0x20 && r < 0x7f) || (r > 0x7f && unicode.IsPrint(r)) {
		return string(r)
	}
	return escapeRune(r)
}

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

// IsNumber reports whether v is a JSON number (not a boolean).
func IsNumber(v Value) bool {
	switch v.(type) {
	case int64, int, BigInt, float64:
		return true
	default:
		return false
	}
}

// IsInteger reports whether v is an integer (Python int, not bool).
func IsInteger(v Value) bool {
	switch v.(type) {
	case int64, int, BigInt:
		return true
	default:
		return false
	}
}

// Float converts a number (or bool) to float64; ok is false for anything else.
func Float(v Value) (float64, bool) {
	switch t := v.(type) {
	case int64:
		return float64(t), true
	case int:
		return float64(t), true
	case float64:
		return t, true
	case bool:
		if t {
			return 1, true
		}
		return 0, true
	case BigInt:
		f, _, err := big.ParseFloat(string(t), 10, 64, big.ToNearestEven)
		if err != nil {
			return 0, false
		}
		x, _ := f.Float64()
		return x, true
	default:
		return 0, false
	}
}

// Int converts an integer value (or bool) to int64; ok is false for anything else.
func Int(v Value) (int64, bool) {
	switch t := v.(type) {
	case int64:
		return t, true
	case int:
		return int64(t), true
	case bool:
		if t {
			return 1, true
		}
		return 0, true
	default:
		return 0, false
	}
}

// Add is Python's a + b on numbers: int + int stays an int, anything with a float is a float.
func Add(a, b Value) Value {
	x, xi := Int(a)
	y, yi := Int(b)
	if xi && yi && !overflowAdd(x, y) {
		return x + y
	}
	fa, _ := Float(a)
	fb, _ := Float(b)
	return fa + fb
}

func overflowAdd(x, y int64) bool {
	s := x + y
	return (x > 0 && y > 0 && s < 0) || (x < 0 && y < 0 && s >= 0)
}

// Less is Python's a < b on numbers.
func Less(a, b Value) bool {
	x, xi := Int(a)
	y, yi := Int(b)
	if xi && yi {
		return x < y
	}
	fa, _ := Float(a)
	fb, _ := Float(b)
	return fa < fb
}

// RoundValue is Python's round(x, n): an int stays the same int, a float is rounded.
func RoundValue(v Value, n int) Value {
	if f, ok := v.(float64); ok {
		return Round(f, n)
	}
	return v
}

// Max is Python's max(list) on numbers: the first largest element, with its type.
func Max(vals []Value) Value {
	var best Value
	for i, v := range vals {
		if i == 0 || Less(best, v) {
			best = v
		}
	}
	return best
}

// Sum is Python's sum(list) on numbers (starting from the int 0).
func Sum(vals []Value) Value {
	var s Value = int64(0)
	for _, v := range vals {
		s = Add(s, v)
	}
	return s
}

// Median is Python's statistics.median: the middle element of the sorted list (with its type), or the mean of
// the two middle ones as a float.
func Median(vals []Value) Value {
	s := append([]Value(nil), vals...)
	sortValues(s)
	n := len(s)
	if n == 0 {
		return nil
	}
	if n%2 == 1 {
		return s[n/2]
	}
	a, _ := Float(Add(s[n/2-1], s[n/2]))
	return a / 2
}

func sortValues(s []Value) {
	sort.SliceStable(s, func(i, j int) bool { return Less(s[i], s[j]) }) // stable, as Python's sort
}

// Contains is Python's `needle in container` for a string needle: substring of a string, element of a list,
// key of an object; false for anything else (Python would raise).
func Contains(container Value, needle string) bool {
	switch t := container.(type) {
	case string:
		return strings.Contains(t, needle)
	case []Value:
		for _, x := range t {
			if s, ok := x.(string); ok && s == needle {
				return true
			}
		}
		return false
	case *Object:
		return t.Has(needle)
	default:
		return false
	}
}

// IsFinite reports whether a number is neither infinite nor NaN.
func IsFinite(f float64) bool {
	return !math.IsNaN(f) && !math.IsInf(f, 0)
}
