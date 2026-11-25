// Package pyjson writes JSON byte for byte as Python's json.dumps(obj, indent=N, sort_keys=True) does (ASCII only,
// "\uXXXX" escapes, floats in Python's repr, ": " and "," separators), so that documents written by the Go and
// the Python implementations of a component compare equal.
package pyjson

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Marshal encodes v with the given indent. Supported values: nil, bool, string, int, int64, float64,
// json.Number, []any, []string, map[string]any, map[string]string, map[string][]string.
func Marshal(v any, indent int) ([]byte, error) {
	var b strings.Builder
	if err := encode(&b, v, strings.Repeat(" ", indent), 0); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

func encode(b *strings.Builder, v any, ind string, level int) error {
	switch x := v.(type) {
	case []string:
		return encodeList(b, len(x), func(i int) any { return x[i] }, ind, level)
	case []any:
		return encodeList(b, len(x), func(i int) any { return x[i] }, ind, level)
	case map[string]any:
		return encodeMap(b, keys(x), func(k string) any { return x[k] }, ind, level)
	case map[string]string:
		return encodeMap(b, keys(x), func(k string) any { return x[k] }, ind, level)
	case map[string][]string:
		return encodeMap(b, keys(x), func(k string) any { return x[k] }, ind, level)
	default:
		return encodeScalar(b, v)
	}
}

func encodeScalar(b *strings.Builder, v any) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case string:
		writeString(b, x)
	case int:
		b.WriteString(strconv.Itoa(x))
	case int64:
		b.WriteString(strconv.FormatInt(x, 10))
	case float64:
		writeFloat(b, x)
	case json.Number:
		b.WriteString(x.String())
	default:
		return fmt.Errorf("pyjson: unsupported type %T", v)
	}
	return nil
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func encodeList(b *strings.Builder, n int, at func(int) any, ind string, level int) error {
	if n == 0 {
		b.WriteString("[]")
		return nil
	}
	b.WriteString("[")
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		newline(b, ind, level+1)
		if err := encode(b, at(i), ind, level+1); err != nil {
			return err
		}
	}
	newline(b, ind, level)
	b.WriteString("]")
	return nil
}

func encodeMap(b *strings.Builder, ks []string, at func(string) any, ind string, level int) error {
	if len(ks) == 0 {
		b.WriteString("{}")
		return nil
	}
	b.WriteString("{")
	for i, k := range ks {
		if i > 0 {
			b.WriteString(",")
		}
		newline(b, ind, level+1)
		writeString(b, k)
		b.WriteString(": ")
		if err := encode(b, at(k), ind, level+1); err != nil {
			return err
		}
	}
	newline(b, ind, level)
	b.WriteString("}")
	return nil
}

func newline(b *strings.Builder, ind string, level int) {
	b.WriteString("\n")
	b.WriteString(strings.Repeat(ind, level))
}

func writeString(b *strings.Builder, s string) {
	b.WriteString(`"`)
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r < 0x20 || r > 0x7e:
			writeEscaped(b, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteString(`"`)
}

func writeEscaped(b *strings.Builder, r rune) {
	if r > 0xffff {
		hi, lo := utf16.EncodeRune(r)
		fmt.Fprintf(b, `\u%04x\u%04x`, hi, lo)
		return
	}
	fmt.Fprintf(b, `\u%04x`, r)
}

// writeFloat writes Python's repr of a float (NaN and infinities as Python's json module writes them).
func writeFloat(b *strings.Builder, f float64) {
	switch {
	case math.IsNaN(f):
		b.WriteString("NaN")
	case math.IsInf(f, 1):
		b.WriteString("Infinity")
	case math.IsInf(f, -1):
		b.WriteString("-Infinity")
	default:
		b.WriteString(FloatRepr(f))
	}
}

// FloatRepr is Python's repr(float): the shortest round-tripping digits, positional for exponents -4..15,
// scientific ("1e+16", "1.5e-05") otherwise, and always a ".0" for whole numbers in positional form.
func FloatRepr(f float64) string {
	if f == 0 {
		if math.Signbit(f) {
			return "-0.0"
		}
		return "0.0"
	}
	exp := int(math.Floor(math.Log10(math.Abs(f))))
	sci := strconv.FormatFloat(f, 'e', -1, 64)
	// the decimal exponent of the shortest representation (Log10 can be off by one at powers of ten)
	if i := strings.LastIndexByte(sci, 'e'); i >= 0 {
		if n, err := strconv.Atoi(sci[i+1:]); err == nil {
			exp = n
		}
	}
	if exp < -4 || exp >= 16 {
		mant, e, _ := strings.Cut(sci, "e")
		sign := e[0]
		digits := strings.TrimLeft(e[1:], "0")
		if len(digits) < 2 {
			digits = strings.Repeat("0", 2-len(digits)) + digits
		}
		return mant + "e" + string(sign) + digits
	}
	s := strconv.FormatFloat(f, 'f', -1, 64)
	if !strings.Contains(s, ".") {
		s += ".0"
	}
	return s
}
