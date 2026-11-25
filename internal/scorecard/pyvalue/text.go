package pyvalue

import (
	"math"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// TypeName is the name of v's type as the contract's error details spell it (NoneType, bool, int, float, str,
// list, dict, date, datetime).
func TypeName(v any) string {
	switch v.(type) {
	case nil:
		return "NoneType"
	case bool:
		return "bool"
	case int64:
		return "int"
	case float64:
		return "float"
	case string:
		return "str"
	case []any:
		return "list"
	case *Map:
		return "dict"
	case Date:
		return "date"
	case DateTime:
		return "datetime"
	default:
		return "object"
	}
}

// Str is v as text (Python str()): None, True/False, decimal integers, FloatRepr, strings unchanged, Repr for
// sequences and mappings, timestamps in their text form.
func Str(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case Date:
		return x.String()
	case DateTime:
		return x.String()
	default:
		return Repr(v)
	}
}

// Repr is v's representation (Python repr()): strings quoted, None, True/False.
func Repr(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case bool:
		if x {
			return "True"
		}
		return "False"
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		return FloatRepr(x)
	case string:
		return quote(x)
	case []any:
		return reprList(x)
	case *Map:
		return reprMap(x)
	case Date:
		return "datetime.date(" + strconv.Itoa(x.Year) + ", " + strconv.Itoa(x.Month) + ", " + strconv.Itoa(x.Day) + ")"
	case DateTime:
		return "datetime.datetime(" + quote(x.Text) + ")"
	default:
		return "<object>"
	}
}

func reprList(l []any) string {
	parts := make([]string, len(l))
	for i, x := range l {
		parts[i] = Repr(x)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func reprMap(m *Map) string {
	keys := m.Keys()
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = quote(k) + ": " + Repr(m.Value(k))
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// quote is Python's string repr: single quotes unless the text holds a single quote and no double quote;
// backslash, the quote, \t \n \r escaped; other non-printable characters as \xhh, \uhhhh or \Uhhhhhhhh.
func quote(s string) string {
	q := byte('\'')
	if strings.ContainsRune(s, '\'') && !strings.ContainsRune(s, '"') {
		q = '"'
	}
	var b strings.Builder
	b.WriteByte(q)
	for _, r := range s {
		writeQuoted(&b, r, rune(q))
	}
	b.WriteByte(q)
	return b.String()
}

func writeQuoted(b *strings.Builder, r, q rune) {
	switch {
	case r == '\\' || r == q:
		b.WriteByte('\\')
		b.WriteRune(r)
	case r == '\t':
		b.WriteString(`\t`)
	case r == '\n':
		b.WriteString(`\n`)
	case r == '\r':
		b.WriteString(`\r`)
	case r == ' ' || (unicode.IsPrint(r) && r != utf8.RuneError):
		b.WriteRune(r)
	case r < 0x100:
		b.WriteString(`\x` + pad(strconv.FormatInt(int64(r), 16), 2))
	case r < 0x10000:
		b.WriteString(`\u` + pad(strconv.FormatInt(int64(r), 16), 4))
	default:
		b.WriteString(`\U` + pad(strconv.FormatInt(int64(r), 16), 8))
	}
}

// pad left-pads s with zeros to at least n characters.
func pad(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return strings.Repeat("0", n-len(s)) + s
}

// FloatRepr is the shortest text that reads back as f (Python repr(float)): fixed notation with at least one
// decimal ("100.0") when the decimal exponent is in [-4, 16), else d.ddde±XX ("1e+16", "1.5e-05"); "inf",
// "-inf", "nan".
func FloatRepr(f float64) string {
	if s, ok := special(f); ok {
		return s
	}
	digits, exp := shortest(f)
	neg := ""
	if math.Signbit(f) {
		neg = "-"
	}
	decpt := exp + 1
	if decpt <= -4 || decpt > 16 {
		return neg + expForm(digits, exp)
	}
	return neg + fixedForm(digits, decpt)
}

func special(f float64) (string, bool) {
	switch {
	case math.IsNaN(f):
		return "nan", true
	case math.IsInf(f, 1):
		return "inf", true
	case math.IsInf(f, -1):
		return "-inf", true
	}
	return "", false
}

// shortest returns the shortest round-trip decimal digits of |f| and the decimal exponent of the first digit.
func shortest(f float64) (string, int) {
	s := strconv.FormatFloat(math.Abs(f), 'e', -1, 64) // d.ddde±XX
	mant, e, _ := strings.Cut(s, "e")
	exp, err := strconv.Atoi(e)
	if err != nil {
		exp = 0 // unreachable: strconv's own exponent
	}
	return strings.Replace(mant, ".", "", 1), exp
}

func expForm(digits string, exp int) string {
	m := digits[:1]
	if len(digits) > 1 {
		m += "." + digits[1:]
	}
	sign := "+"
	if exp < 0 {
		sign, exp = "-", -exp
	}
	return m + "e" + sign + pad(strconv.Itoa(exp), 2)
}

func fixedForm(digits string, decpt int) string {
	switch {
	case decpt <= 0:
		return "0." + strings.Repeat("0", -decpt) + digits
	case decpt >= len(digits):
		return digits + strings.Repeat("0", decpt-len(digits)) + ".0"
	default:
		return digits[:decpt] + "." + digits[decpt:]
	}
}

// FormatG formats f as Python's format(f, "g"): six significant digits, trailing zeros removed, exponent form
// when the exponent is < -4 or >= 6; "inf", "-inf", "nan".
func FormatG(f float64) string {
	if s, ok := special(f); ok {
		return s
	}
	return strconv.FormatFloat(f, 'g', 6, 64)
}

// FormatFixed formats f with n decimals, correctly rounded (half to even on the exact binary value), as
// Python's format(f, ".<n>f").
func FormatFixed(f float64, n int) string {
	if s, ok := special(f); ok {
		return s
	}
	return strconv.FormatFloat(f, 'f', n, 64)
}

// Round rounds f to n decimals the way the contract specifies (SPEC §4): the exact binary value of f, rounded
// half to even, read back as the nearest double. Python's round(f, n).
func Round(f float64, n int) float64 {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return f
	}
	r, err := strconv.ParseFloat(strconv.FormatFloat(f, 'f', n, 64), 64)
	if err != nil {
		return f // unreachable: strconv reads back its own output
	}
	return r
}
