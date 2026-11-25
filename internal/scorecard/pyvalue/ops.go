package pyvalue

import (
	"math"
	"strconv"
	"strings"
	"unicode"
)

// Error is a failed operation on a value (a wrong type, a missing key, a malformed number). Type names the kind
// of failure as the contract's evaluator details spell it (KeyError, TypeError, ValueError, ...).
type Error struct {
	Type string
	Msg  string
}

func (e *Error) Error() string { return e.Type + ": " + e.Msg }

// KeyError is a missing mapping key.
func KeyError(key string) *Error { return &Error{Type: "KeyError", Msg: quote(key)} }

// TypeError is an operation on a value of the wrong type.
func TypeError(msg string) *Error { return &Error{Type: "TypeError", Msg: msg} }

// ValueError is a value of the right type with unusable content.
func ValueError(msg string) *Error { return &Error{Type: "ValueError", Msg: msg} }

// AttributeError is a method call on a value that has no such method (e.g. get on a list).
func AttributeError(v any, attr string) *Error {
	return &Error{Type: "AttributeError", Msg: "'" + TypeName(v) + "' object has no attribute '" + attr + "'"}
}

// Truthy is v's truth value: null, false, zero, empty text, empty sequence or mapping are false.
func Truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case int64:
		return x != 0
	case float64:
		return x != 0
	case string:
		return x != ""
	case []any:
		return len(x) > 0
	case *Map:
		return x.Len() > 0
	default:
		return true
	}
}

// number returns v as a float when it is a number (bool, int, float).
func number(v any) (float64, bool) {
	switch x := v.(type) {
	case bool:
		if x {
			return 1, true
		}
		return 0, true
	case int64:
		return float64(x), true
	case float64:
		return x, true
	}
	return 0, false
}

// Equal is value equality: numbers by value across bool/int/float, sequences element-wise, mappings by key set
// and values, everything else by type and value.
func Equal(a, b any) bool {
	if x, ok := number(a); ok {
		y, ok := number(b)
		return ok && x == y
	}
	switch x := a.(type) {
	case []any:
		y, ok := b.([]any)
		return ok && equalLists(x, y)
	case *Map:
		y, ok := b.(*Map)
		return ok && equalMaps(x, y)
	}
	return a == b
}

func equalLists(x, y []any) bool {
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if !Equal(x[i], y[i]) {
			return false
		}
	}
	return true
}

func equalMaps(x, y *Map) bool {
	if x.Len() != y.Len() {
		return false
	}
	for _, k := range x.Keys() {
		w, ok := y.Get(k)
		if !ok || !Equal(x.Value(k), w) {
			return false
		}
	}
	return true
}

// In is membership (`x in container`): a substring of a string, an element of a sequence, a key of a mapping.
func In(x, container any) (bool, error) {
	switch c := container.(type) {
	case string:
		s, ok := x.(string)
		if !ok {
			return false, TypeError("'in <string>' requires string as left operand, not " + TypeName(x))
		}
		return strings.Contains(c, s), nil
	case []any:
		for _, e := range c {
			if Equal(x, e) {
				return true, nil
			}
		}
		return false, nil
	case *Map:
		if err := hashable(x); err != nil {
			return false, err
		}
		s, ok := x.(string)
		return ok && c.Has(s), nil
	}
	return false, TypeError("argument of type '" + TypeName(container) + "' is not iterable")
}

func hashable(x any) error {
	switch x.(type) {
	case []any, *Map:
		return TypeError("unhashable type: '" + TypeName(x) + "'")
	}
	return nil
}

// Iter returns the elements of an iterable: a sequence's elements, a string's characters, a mapping's keys.
func Iter(v any) ([]any, error) {
	switch x := v.(type) {
	case []any:
		return x, nil
	case string:
		out := make([]any, 0, len(x))
		for _, r := range x {
			out = append(out, string(r))
		}
		return out, nil
	case *Map:
		keys := x.Keys()
		out := make([]any, len(keys))
		for i, k := range keys {
			out[i] = k
		}
		return out, nil
	}
	return nil, TypeError("'" + TypeName(v) + "' object is not iterable")
}

// AsList is v when it is a sequence, else a one-element sequence holding v.
func AsList(v any) []any {
	if l, ok := v.([]any); ok {
		return l
	}
	return []any{v}
}

// JoinStrings joins the elements of an iterable that must all be strings.
func JoinStrings(sep string, v any) (string, error) {
	items, err := Iter(v)
	if err != nil {
		return "", TypeError("can only join an iterable")
	}
	parts := make([]string, len(items))
	for i, x := range items {
		s, ok := x.(string)
		if !ok {
			return "", TypeError("sequence item " + strconv.Itoa(i) + ": expected str instance, " + TypeName(x) + " found")
		}
		parts[i] = s
	}
	return strings.Join(parts, sep), nil
}

// HasPrefix is s.startswith(prefix) for a value s and a value prefix, both of which must be strings.
func HasPrefix(s, prefix any) (bool, error) {
	str, ok := s.(string)
	if !ok {
		return false, AttributeError(s, "startswith")
	}
	p, ok := prefix.(string)
	if !ok {
		return false, TypeError("startswith first arg must be str or a tuple of str, not " + TypeName(prefix))
	}
	return strings.HasPrefix(str, p), nil
}

// Sub is now - v for a number v.
func Sub(now float64, v any) (float64, error) {
	f, ok := number(v)
	if !ok {
		return 0, TypeError("unsupported operand type(s) for -: 'float' and '" + TypeName(v) + "'")
	}
	return now - f, nil
}

// ToFloat converts v to a float as Python's float(): numbers, and text such as " 1.5 ", "1e3", "1_000", "inf",
// "nan".
func ToFloat(v any) (float64, error) {
	if f, ok := number(v); ok {
		return f, nil
	}
	s, ok := v.(string)
	if !ok {
		return 0, TypeError("float() argument must be a string or a real number, not '" + TypeName(v) + "'")
	}
	f, ok := parseFloatText(s)
	if !ok {
		return 0, ValueError("could not convert string to float: " + quote(s))
	}
	return f, nil
}

func parseFloatText(s string) (float64, bool) {
	t := strings.TrimFunc(s, unicode.IsSpace)
	body := strings.TrimLeft(t, "+-")
	switch strings.ToLower(body) {
	case "inf", "infinity", "nan":
		f, err := strconv.ParseFloat(t, 64)
		return f, err == nil
	}
	if !validUnderscores(t) || strings.ContainsAny(t, "xXpP") || t == "" {
		return 0, false
	}
	f, err := strconv.ParseFloat(strings.ReplaceAll(t, "_", ""), 64)
	if err != nil && !math.IsInf(f, 0) {
		return 0, false
	}
	return f, true
}

// validUnderscores: an underscore only between two digits.
func validUnderscores(s string) bool {
	for i := range len(s) {
		if s[i] != '_' {
			continue
		}
		if i == 0 || i == len(s)-1 || !isDigit(s[i-1]) || !isDigit(s[i+1]) {
			return false
		}
	}
	return true
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

// ToInt converts v to an integer as Python's int(): bools, integers, floats truncated toward zero, and decimal
// text (sign, surrounding spaces and underscores between digits allowed).
func ToInt(v any) (int64, error) {
	switch x := v.(type) {
	case bool:
		if x {
			return 1, nil
		}
		return 0, nil
	case int64:
		return x, nil
	case float64:
		return floatToInt(x)
	case string:
		return ParseInt(x, 10)
	}
	return 0, TypeError("int() argument must be a string, a bytes-like object or a real number, not '" + TypeName(v) + "'")
}

func floatToInt(f float64) (int64, error) {
	switch {
	case math.IsNaN(f):
		return 0, ValueError("cannot convert float NaN to integer")
	case math.IsInf(f, 0):
		return 0, &Error{Type: "OverflowError", Msg: "cannot convert float infinity to integer"}
	case f >= 9.223372036854775807e18 || f < -9.223372036854775808e18:
		return 0, &Error{Type: "OverflowError", Msg: "integer out of range"}
	}
	return int64(f), nil
}

// ParseInt parses text as Python's int(text, base): spaces around, a sign, underscores between digits, and for
// base 8 or 16 an optional 0o / 0x prefix.
func ParseInt(text string, base int) (int64, error) {
	t := strings.TrimFunc(text, unicode.IsSpace)
	body := strings.TrimLeft(t, "+-")
	neg := len(t)-len(body) == 1 && t[0] == '-'
	if len(t)-len(body) > 1 {
		body = "!" // two signs: invalid
	}
	body = stripPrefix(body, base)
	n, err := strconv.ParseInt(strings.ReplaceAll(body, "_", ""), base, 64)
	if err != nil || !validUnderscores(body) || body == "" || body[0] == '_' {
		return 0, ValueError("invalid literal for int() with base " + strconv.Itoa(base) + ": " + quote(text))
	}
	if neg {
		n = -n
	}
	return n, nil
}

func stripPrefix(body string, base int) string {
	l := strings.ToLower(body)
	if (base == 8 && strings.HasPrefix(l, "0o")) || (base == 16 && strings.HasPrefix(l, "0x")) {
		return strings.TrimPrefix(body[2:], "_")
	}
	return body
}

// Sum adds numbers as the contract specifies (SPEC §4, "Arithmetic"), in order: integers exactly while every
// value is an integer; from the first float on, a double-precision sum in which every further float is added
// with Neumaier compensation (integers without), the compensation added once at the end when it is finite and
// non-zero. The result is an int64 when every value is an integer (or there is none), else a float64.
// Python 3.12's sum().
func Sum(values []any) (any, error) {
	var acc int64
	for i, v := range values {
		switch x := v.(type) {
		case bool, int64:
			n, _ := number(x) // a bool or an integer is always a number
			acc += int64(n)
		case float64:
			return sumFloats(float64(acc)+x, values[i+1:])
		default:
			return nil, TypeError("unsupported operand type(s) for +: 'int' and '" + TypeName(v) + "'")
		}
	}
	return acc, nil
}

func sumFloats(f float64, rest []any) (any, error) {
	c := 0.0
	for _, v := range rest {
		switch x := v.(type) {
		case float64:
			t := f + x
			if math.Abs(f) >= math.Abs(x) {
				c += (f - t) + x
			} else {
				c += (x - t) + f
			}
			f = t
		case bool, int64:
			n, _ := number(x) // a bool or an integer is always a number
			f += n
		default:
			return nil, TypeError("unsupported operand type(s) for +: 'float' and '" + TypeName(v) + "'")
		}
	}
	if c != 0 && !math.IsInf(c, 0) && !math.IsNaN(c) {
		f += c
	}
	return f, nil
}

// ToFloat64 is a number value as a float64 (int64 and bool converted).
func ToFloat64(v any) (float64, bool) { return number(v) }
