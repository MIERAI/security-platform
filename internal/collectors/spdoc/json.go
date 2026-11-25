package spdoc

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// Compact is the indent of Python's json.dumps without indent: one line, ", " and ": " separators.
const Compact = -1

// Marshal writes v as Python's json.dumps(v, indent=indent, sort_keys=sortKeys) with the default ensure_ascii:
// non-ASCII text as \uXXXX escapes, floats as repr(float) (NaN, Infinity), "," at line ends and ": " after keys
// when indented (indent 0 = a line break without indentation), ", " and ": " when Compact. Mappings are
// *pyvalue.Map (insertion order unless sortKeys), map[string]any and map[string]string (always sorted: their
// order carries no meaning); sequences []any and []string; scalars nil, bool, int, int64, float64, string.
func Marshal(v any, indent int, sortKeys bool) ([]byte, error) {
	e := encoder{indent: indent, sortKeys: sortKeys}
	if err := e.value(v, 0); err != nil {
		return nil, err
	}
	return []byte(e.b.String()), nil
}

type encoder struct {
	b        strings.Builder
	indent   int
	sortKeys bool
}

func (e *encoder) value(v any, level int) error {
	switch x := v.(type) {
	case []any:
		return e.list(len(x), func(i int) any { return x[i] }, level)
	case []string:
		return e.list(len(x), func(i int) any { return x[i] }, level)
	case *pyvalue.Map:
		keys := x.Keys()
		if e.sortKeys {
			sort.Strings(keys)
		}
		return e.object(keys, x.Value, level)
	case map[string]any:
		return e.object(sortedKeys(x), func(k string) any { return x[k] }, level)
	case map[string]string:
		return e.object(sortedKeys(x), func(k string) any { return x[k] }, level)
	}
	return e.scalar(v)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (e *encoder) scalar(v any) error {
	switch x := v.(type) {
	case nil:
		e.b.WriteString("null")
	case bool:
		e.b.WriteString(strconv.FormatBool(x))
	case int:
		e.b.WriteString(strconv.Itoa(x))
	case int64:
		e.b.WriteString(strconv.FormatInt(x, 10))
	case float64:
		e.b.WriteString(floatJSON(x))
	case string:
		writeString(&e.b, x)
	default:
		return fmt.Errorf("spdoc: a %T value cannot be written as JSON", v)
	}
	return nil
}

func floatJSON(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	}
	return pyvalue.FloatRepr(f)
}

// sep is written between two elements; open after "[" or "{", close before "]" or "}".
func (e *encoder) sep(level int) {
	if e.indent < 0 {
		e.b.WriteString(", ")
		return
	}
	e.b.WriteByte(',')
	e.newline(level)
}

func (e *encoder) newline(level int) {
	if e.indent >= 0 {
		e.b.WriteByte('\n')
		e.b.WriteString(strings.Repeat(" ", e.indent*level))
	}
}

func (e *encoder) list(n int, at func(int) any, level int) error {
	if n == 0 {
		e.b.WriteString("[]")
		return nil
	}
	e.b.WriteByte('[')
	e.newline(level + 1)
	for i := range n {
		if i > 0 {
			e.sep(level + 1)
		}
		if err := e.value(at(i), level+1); err != nil {
			return err
		}
	}
	e.newline(level)
	e.b.WriteByte(']')
	return nil
}

func (e *encoder) object(keys []string, at func(string) any, level int) error {
	if len(keys) == 0 {
		e.b.WriteString("{}")
		return nil
	}
	e.b.WriteByte('{')
	e.newline(level + 1)
	for i, k := range keys {
		if i > 0 {
			e.sep(level + 1)
		}
		writeString(&e.b, k)
		e.b.WriteString(": ")
		if err := e.value(at(k), level+1); err != nil {
			return err
		}
	}
	e.newline(level)
	e.b.WriteByte('}')
	return nil
}

// writeString writes s as a JSON string with ensure_ascii escapes (UTF-16 surrogate pairs above U+FFFF).
func writeString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			writeRune(b, r)
		}
	}
	b.WriteByte('"')
}

func writeRune(b *strings.Builder, r rune) {
	switch {
	case r >= 0x20 && r < 0x7f:
		b.WriteRune(r)
	case r > 0xffff:
		hi, lo := utf16.EncodeRune(r)
		b.WriteString(`\u` + hex4(hi) + `\u` + hex4(lo))
	default:
		b.WriteString(`\u` + hex4(r))
	}
}

func hex4(r rune) string {
	s := strconv.FormatInt(int64(r), 16)
	return strings.Repeat("0", 4-len(s)) + s
}
