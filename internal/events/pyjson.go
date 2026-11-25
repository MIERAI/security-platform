package events

import (
	"errors"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/MIERAI/security-platform/internal/collectors/cloud/pyjson"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// dumpOpts are the json.dumps options the reference uses: ensure_ascii is always on (its default).
type dumpOpts struct {
	sortKeys bool
	compact  bool // separators=(",", ":")
	indent   int  // -1: none
}

// Encodings of ship.py, by use.
func lineJSON() dumpOpts    { return dumpOpts{compact: true, indent: -1} }  // json.dumps(x, separators=(",", ":"))
func defaultJSON() dumpOpts { return dumpOpts{indent: -1} }                 // json.dumps(x)
func sortedJSON() dumpOpts  { return dumpOpts{sortKeys: true, indent: -1} } // json.dumps(x, sort_keys=True)
func dryRunJSON() dumpOpts  { return dumpOpts{indent: 1} }                  // json.dumps(x, indent=1)

var errUnencodable = errors.New("value cannot be written as JSON")

// dumps is Python's json.dumps with the given options over pyvalue values (*pyvalue.Map keeps insertion order,
// as a dict does) and the plain Go JSON values (map[string]any is written in key order: only used sorted).
func dumps(v any, o dumpOpts) (string, error) {
	var b strings.Builder
	if err := o.value(&b, v, 0); err != nil {
		return "", err
	}
	return b.String(), nil
}

func (o dumpOpts) seps() (item, key string) {
	switch {
	case o.compact:
		return ",", ":"
	case o.indent >= 0:
		return ",", ": "
	default:
		return ", ", ": "
	}
}

func (o dumpOpts) value(b *strings.Builder, v any, level int) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(map[bool]string{true: "true", false: "false"}[x])
	case int:
		b.WriteString(strconv.Itoa(x))
	case int64:
		b.WriteString(strconv.FormatInt(x, 10))
	case float64:
		b.WriteString(floatJSON(x))
	case string:
		quote(b, x)
	case pyvalue.Date, pyvalue.DateTime:
		quote(b, pyvalue.Str(x)) // default=str
	default:
		return o.composite(b, v, level)
	}
	return nil
}

// composite writes a list or an object.
func (o dumpOpts) composite(b *strings.Builder, v any, level int) error {
	switch x := v.(type) {
	case []any:
		return o.list(b, x, level)
	case []string:
		l := make([]any, len(x))
		for i, s := range x {
			l[i] = s
		}
		return o.list(b, l, level)
	case *pyvalue.Map:
		return o.object(b, x.Keys(), x.Value, level)
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return o.object(b, keys, func(k string) any { return x[k] }, level)
	default:
		return errUnencodable
	}
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
	return pyjson.FloatRepr(f)
}

func (o dumpOpts) newline(b *strings.Builder, level int) {
	if o.indent >= 0 {
		b.WriteByte('\n')
		b.WriteString(strings.Repeat(" ", o.indent*level))
	}
}

func (o dumpOpts) list(b *strings.Builder, l []any, level int) error {
	if len(l) == 0 {
		b.WriteString("[]")
		return nil
	}
	item, _ := o.seps()
	b.WriteByte('[')
	for i, x := range l {
		if i > 0 {
			b.WriteString(item)
		}
		o.newline(b, level+1)
		if err := o.value(b, x, level+1); err != nil {
			return err
		}
	}
	o.newline(b, level)
	b.WriteByte(']')
	return nil
}

func (o dumpOpts) object(b *strings.Builder, keys []string, at func(string) any, level int) error {
	if len(keys) == 0 {
		b.WriteString("{}")
		return nil
	}
	if o.sortKeys {
		keys = append([]string(nil), keys...)
		sort.Strings(keys)
	}
	item, key := o.seps()
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteString(item)
		}
		o.newline(b, level+1)
		quote(b, k)
		b.WriteString(key)
		if err := o.value(b, at(k), level+1); err != nil {
			return err
		}
	}
	o.newline(b, level)
	b.WriteByte('}')
	return nil
}

// quote writes s as json.dumps(ensure_ascii=True) does.
func quote(b *strings.Builder, s string) {
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
			escapeOther(b, r)
		}
	}
	b.WriteByte('"')
}

func escapeOther(b *strings.Builder, r rune) {
	switch {
	case r >= 0x20 && r < 0x7f:
		b.WriteRune(r)
	case r >= 0x10000:
		r -= 0x10000
		b.WriteString(`\u` + hex4(0xd800+(r>>10)) + `\u` + hex4(0xdc00+(r&0x3ff)))
	default:
		b.WriteString(`\u` + hex4(r))
	}
}

func hex4(r rune) string {
	s := strconv.FormatInt(int64(r), 16)
	return strings.Repeat("0", 4-len(s)) + s
}
