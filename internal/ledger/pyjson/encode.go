package pyjson

import (
	"bytes"
	"fmt"
	"strconv"
	"unicode/utf8"
)

// Options select the json.dumps variant to reproduce.
type Options struct {
	Indent      int  // json.dumps(indent=N); 0 = no indentation (separators ", " and ": ")
	SortKeys    bool // sort_keys=True
	EnsureASCII bool // ensure_ascii=True (Python's default)
}

// Ledger is json.dump(x, indent=1, sort_keys=True, ensure_ascii=False): ledger.json, tracker/items.json.
func Ledger() Options {
	return Options{Indent: 1, SortKeys: true}
}

// Compact is json.dumps(x) with Python's defaults: ocsf.jsonl lines.
func Compact() Options {
	return Options{EnsureASCII: true}
}

// Marshal renders v exactly as json.dumps would with these options. Values of other Go types are an error.
func Marshal(v Value, opt Options) ([]byte, error) {
	var b bytes.Buffer
	if err := encode(&b, v, opt, 0); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func encode(b *bytes.Buffer, v Value, opt Options, level int) error {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(t))
	case string:
		writeString(b, t, opt.EnsureASCII)
	case int64:
		b.WriteString(strconv.FormatInt(t, 10))
	case int:
		b.WriteString(strconv.Itoa(t))
	case BigInt:
		b.WriteString(string(t))
	case float64:
		b.WriteString(FloatJSON(t))
	case []Value:
		return encodeArray(b, t, opt, level)
	case *Object:
		return encodeObject(b, t, opt, level)
	default:
		return fmt.Errorf("pyjson: cannot encode %T", v)
	}
	return nil
}

func newline(b *bytes.Buffer, opt Options, level int) {
	if opt.Indent <= 0 {
		return
	}
	b.WriteByte('\n')
	for i := 0; i < level*opt.Indent; i++ {
		b.WriteByte(' ')
	}
}

func separator(b *bytes.Buffer, opt Options) {
	if opt.Indent > 0 {
		b.WriteByte(',')
		return
	}
	b.WriteString(", ")
}

func encodeArray(b *bytes.Buffer, a []Value, opt Options, level int) error {
	if len(a) == 0 {
		b.WriteString("[]")
		return nil
	}
	b.WriteByte('[')
	for i, x := range a {
		if i > 0 {
			separator(b, opt)
		}
		newline(b, opt, level+1)
		if err := encode(b, x, opt, level+1); err != nil {
			return err
		}
	}
	newline(b, opt, level)
	b.WriteByte(']')
	return nil
}

func encodeObject(b *bytes.Buffer, o *Object, opt Options, level int) error {
	if o.Len() == 0 {
		b.WriteString("{}")
		return nil
	}
	keys := o.keys
	if opt.SortKeys {
		keys = o.SortedKeys()
	}
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			separator(b, opt)
		}
		newline(b, opt, level+1)
		writeString(b, k, opt.EnsureASCII)
		b.WriteString(": ")
		if err := encode(b, o.vals[k], opt, level+1); err != nil {
			return err
		}
	}
	newline(b, opt, level)
	b.WriteByte('}')
	return nil
}

const hexDigits = "0123456789abcdef"

// writeString quotes s as Python's json module does (lower-case \u escapes; ensure_ascii escapes everything
// outside printable ASCII, astral characters as surrogate pairs).
func writeString(b *bytes.Buffer, s string, ascii bool) {
	b.WriteByte('"')
	for _, r := range s {
		writeRune(b, r, ascii)
	}
	b.WriteByte('"')
}

func writeRune(b *bytes.Buffer, r rune, ascii bool) {
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
		writeOther(b, r, ascii)
	}
}

func writeOther(b *bytes.Buffer, r rune, ascii bool) {
	switch {
	case r < 0x20 || (ascii && r > 0x7e):
		if r > 0xffff {
			r -= 0x10000
			writeU(b, 0xd800+(r>>10))
			writeU(b, 0xdc00+(r&0x3ff))
			return
		}
		writeU(b, r)
	default:
		var buf [utf8.UTFMax]byte
		n := utf8.EncodeRune(buf[:], r)
		b.Write(buf[:n])
	}
}

func writeU(b *bytes.Buffer, r rune) {
	b.WriteString(`\u`)
	for shift := 12; shift >= 0; shift -= 4 {
		b.WriteByte(hexDigits[(r>>uint(shift))&0xf])
	}
}
