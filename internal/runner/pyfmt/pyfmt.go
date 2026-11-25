// Package pyfmt writes values exactly as the Python reference implementation writes them, so that files written
// by the Go runner and by the Python runner are byte-for-byte interchangeable: JSON as `json.dump(v, indent=1,
// sort_keys=True)` (ASCII only, Python's float repr), numbers as `str()`, `repr()` and `format(v, "g")`.
//
// Values are the ones encoding/json produces with UseNumber (nil, bool, string, json.Number, []any,
// map[string]any) plus Go integers and floats.
package pyfmt

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// ErrUnsupported is returned for a value of a type JSON cannot hold.
var ErrUnsupported = errors.New("pyfmt: unsupported value")

// Decode parses JSON keeping numbers as json.Number, so integers stay integers and floats keep their text.
func Decode(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("decode json: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("decode json: %w", errors.New("extra data after the value"))
	}
	return v, nil
}

// JSONIndent1 encodes v as Python's json.dumps(v, indent=1, sort_keys=True).
func JSONIndent1(v any) ([]byte, error) {
	var b bytes.Buffer
	if err := encode(&b, v, 0); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func encode(b *bytes.Buffer, v any, depth int) error {
	switch x := v.(type) {
	case map[string]any:
		return encodeMap(b, x, depth)
	case []any:
		return encodeList(b, x, depth)
	case []string:
		l := make([]any, len(x))
		for i, s := range x {
			l[i] = s
		}
		return encodeList(b, l, depth)
	default:
		s, err := scalar(v)
		if err != nil {
			return err
		}
		b.WriteString(s)
		return nil
	}
}

func encodeMap(b *bytes.Buffer, m map[string]any, depth int) error {
	if len(m) == 0 {
		b.WriteString("{}")
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
	b.WriteString("{")
	for i, k := range keys {
		if i > 0 {
			b.WriteString(",")
		}
		newline(b, depth+1)
		b.WriteString(Quote(k))
		b.WriteString(": ")
		if err := encode(b, m[k], depth+1); err != nil {
			return err
		}
	}
	newline(b, depth)
	b.WriteString("}")
	return nil
}

func encodeList(b *bytes.Buffer, l []any, depth int) error {
	if len(l) == 0 {
		b.WriteString("[]")
		return nil
	}
	b.WriteString("[")
	for i, v := range l {
		if i > 0 {
			b.WriteString(",")
		}
		newline(b, depth+1)
		if err := encode(b, v, depth+1); err != nil {
			return err
		}
	}
	newline(b, depth)
	b.WriteString("]")
	return nil
}

func newline(b *bytes.Buffer, depth int) {
	b.WriteString("\n")
	b.WriteString(strings.Repeat(" ", depth))
}

// lessUTF16 orders keys as Python sorts str (by code point).
func lessUTF16(a, b string) bool {
	ra, rb := []rune(a), []rune(b)
	for i := 0; i < len(ra) && i < len(rb); i++ {
		if ra[i] != rb[i] {
			return ra[i] < rb[i]
		}
	}
	return len(ra) < len(rb)
}

func scalar(v any) (string, error) {
	switch x := v.(type) {
	case nil:
		return "null", nil
	case bool:
		if x {
			return "true", nil
		}
		return "false", nil
	case string:
		return Quote(x), nil
	case json.Number:
		return x.String(), nil
	case int:
		return strconv.Itoa(x), nil
	case int64:
		return strconv.FormatInt(x, 10), nil
	case float64:
		return jsonFloat(x), nil
	default:
		return "", fmt.Errorf("%w: %T", ErrUnsupported, v)
	}
}

func jsonFloat(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	}
	return FloatRepr(f)
}

// Quote is Python's json string encoding with ensure_ascii: every non-ASCII character as \uXXXX (surrogate pairs
// above the BMP).
func Quote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		writeRune(&b, r)
	}
	b.WriteByte('"')
	return b.String()
}

// shortEscapes are the two-character escapes Python's json uses. A fresh map on every call.
func shortEscapes() map[rune]string {
	return map[rune]string{'"': `\"`, '\\': `\\`, '\n': `\n`, '\r': `\r`, '\t': `\t`, '\b': `\b`, '\f': `\f`}
}

func writeRune(b *strings.Builder, r rune) {
	if esc, ok := shortEscapes()[r]; ok {
		b.WriteString(esc)
		return
	}
	switch {
	case r < 0x20 || (r > 0x7e && r <= 0xffff):
		fmt.Fprintf(b, `\u%04x`, r)
	case r > 0xffff:
		hi, lo := utf16.EncodeRune(r)
		fmt.Fprintf(b, `\u%04x\u%04x`, hi, lo)
	default:
		b.WriteRune(r)
	}
}

// FloatRepr is Python's repr(float): the shortest round-trip digits, fixed notation for decimal exponents from
// -4 to 15 (always with a fractional part), scientific notation with a two-digit exponent otherwise.
func FloatRepr(f float64) string {
	switch {
	case math.IsNaN(f):
		return "nan"
	case math.IsInf(f, 1):
		return "inf"
	case math.IsInf(f, -1):
		return "-inf"
	}
	e := strconv.FormatFloat(f, 'e', -1, 64) // [-]d[.ddd]e±XX
	_, expText, _ := strings.Cut(e, "e")
	exp, err := strconv.Atoi(expText)
	if err != nil {
		return e // unreachable: FormatFloat always writes an integer exponent
	}
	if exp < -4 || exp >= 16 {
		return e
	}
	s := strconv.FormatFloat(f, 'f', -1, 64)
	if !strings.ContainsAny(s, ".") {
		s += ".0"
	}
	return s
}

// FormatG is Python's format(f, "g"): six significant digits, trailing zeros removed.
func FormatG(f float64) string {
	switch {
	case math.IsNaN(f):
		return "nan"
	case math.IsInf(f, 1):
		return "inf"
	case math.IsInf(f, -1):
		return "-inf"
	}
	return strconv.FormatFloat(f, 'g', 6, 64)
}

// Str is Python's str() of a JSON/YAML value: True/False/None, integers in decimal, floats as repr.
func Str(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case bool:
		if x {
			return "True"
		}
		return "False"
	case string:
		return x
	case json.Number:
		if f, err := x.Float64(); err == nil && strings.ContainsAny(x.String(), ".eE") {
			return FloatRepr(f)
		}
		return x.String()
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		return FloatRepr(x)
	default:
		return fmt.Sprint(v)
	}
}
