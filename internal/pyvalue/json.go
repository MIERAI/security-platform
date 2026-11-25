package pyvalue

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// maxDepth bounds the nesting of a decoded document.
const maxDepth = 512

// ErrDocument is returned for input that is not one well-formed document.
var ErrDocument = errors.New("malformed document")

// DecodeJSON decodes one JSON document: objects to *Map (member order kept; the last duplicate wins), numbers
// without a fraction or exponent to int64, other numbers to float64. Invalid UTF-8, trailing data and integers
// beyond 64 bits are errors.
func DecodeJSON(data []byte) (any, error) {
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("%w: not UTF-8", ErrDocument)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := decodeValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: extra data after the document", ErrDocument)
	}
	return v, nil
}

func decodeValue(dec *json.Decoder, depth int) (any, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("%w: nested too deeply", ErrDocument)
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDocument, err)
	}
	switch t := tok.(type) {
	case json.Delim:
		if t == '{' {
			return decodeObject(dec, depth)
		}
		return decodeArray(dec, depth)
	case json.Number:
		return decodeNumber(t)
	case float64: // not produced with UseNumber
		return t, nil
	default:
		return t, nil // nil, bool, string
	}
}

func decodeObject(dec *json.Decoder, depth int) (any, error) {
	m := NewMap()
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrDocument, err)
		}
		key, _ := tok.(string) // object keys are always strings in a token stream
		v, err := decodeValue(dec, depth+1)
		if err != nil {
			return nil, err
		}
		m.Set(key, v)
	}
	_, err := dec.Token() // the closing brace
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDocument, err)
	}
	return m, nil
}

func decodeArray(dec *json.Decoder, depth int) (any, error) {
	out := []any{}
	for dec.More() {
		v, err := decodeValue(dec, depth+1)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDocument, err)
	}
	return out, nil
}

func decodeNumber(n json.Number) (any, error) {
	s := string(n)
	if !strings.ContainsAny(s, ".eE") {
		i, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%w: integer %s out of range", ErrDocument, s)
		}
		return i, nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil && !math.IsInf(f, 0) {
		return nil, fmt.Errorf("%w: number %s", ErrDocument, s)
	}
	return f, nil
}

// EncodeJSON writes v as the contract's documents are printed (SPEC §5): keys sorted, one-space indentation,
// ", "-free separators ("," at line ends, ": " after keys), floats in FloatRepr form (NaN, Infinity), and
// non-ASCII text as is (asciiOnly=false) or as \uXXXX escapes (asciiOnly=true). No trailing newline.
// Python's json.dumps(v, indent=1, sort_keys=True, ensure_ascii=asciiOnly).
func EncodeJSON(v any, asciiOnly bool) ([]byte, error) {
	e := encoder{ascii: asciiOnly}
	if err := e.value(v, 0); err != nil {
		return nil, err
	}
	return e.buf.Bytes(), nil
}

type encoder struct {
	buf   bytes.Buffer
	ascii bool
}

func (e *encoder) value(v any, level int) error {
	switch x := v.(type) {
	case nil:
		e.buf.WriteString("null")
	case bool:
		e.buf.WriteString(strconv.FormatBool(x))
	case int64:
		e.buf.WriteString(strconv.FormatInt(x, 10))
	case float64:
		e.buf.WriteString(jsonFloat(x))
	case string:
		e.str(x)
	case []any:
		return e.list(x, level)
	case *Map:
		return e.object(x, level)
	default:
		return fmt.Errorf("%w: a %s value cannot be written as JSON", ErrDocument, TypeName(v))
	}
	return nil
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

func (e *encoder) newline(level int) {
	e.buf.WriteByte('\n')
	e.buf.WriteString(strings.Repeat(" ", level))
}

func (e *encoder) list(l []any, level int) error {
	if len(l) == 0 {
		e.buf.WriteString("[]")
		return nil
	}
	e.buf.WriteByte('[')
	for i, x := range l {
		if i > 0 {
			e.buf.WriteByte(',')
		}
		e.newline(level + 1)
		if err := e.value(x, level+1); err != nil {
			return err
		}
	}
	e.newline(level)
	e.buf.WriteByte(']')
	return nil
}

func (e *encoder) object(m *Map, level int) error {
	if m.Len() == 0 {
		e.buf.WriteString("{}")
		return nil
	}
	keys := m.Keys()
	sort.Strings(keys)
	e.buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			e.buf.WriteByte(',')
		}
		e.newline(level + 1)
		e.str(k)
		e.buf.WriteString(": ")
		if err := e.value(m.Value(k), level+1); err != nil {
			return err
		}
	}
	e.newline(level)
	e.buf.WriteByte('}')
	return nil
}

func (e *encoder) str(s string) {
	e.buf.WriteByte('"')
	for _, r := range s {
		e.rune(r)
	}
	e.buf.WriteByte('"')
}

func (e *encoder) rune(r rune) {
	switch r {
	case '"':
		e.buf.WriteString(`\"`)
	case '\\':
		e.buf.WriteString(`\\`)
	case '\n':
		e.buf.WriteString(`\n`)
	case '\r':
		e.buf.WriteString(`\r`)
	case '\t':
		e.buf.WriteString(`\t`)
	case '\b':
		e.buf.WriteString(`\b`)
	case '\f':
		e.buf.WriteString(`\f`)
	default:
		e.other(r)
	}
}

func (e *encoder) other(r rune) {
	switch {
	case r < 0x20 || (e.ascii && r >= 0x7f && r < 0x10000):
		e.buf.WriteString(`\u` + pad(strconv.FormatInt(int64(r), 16), 4))
	case e.ascii && r >= 0x10000:
		r -= 0x10000
		e.buf.WriteString(`\u` + strconv.FormatInt(int64(0xd800+(r>>10)), 16))
		e.buf.WriteString(`\u` + strconv.FormatInt(int64(0xdc00+(r&0x3ff)), 16))
	default:
		e.buf.WriteRune(r)
	}
}
