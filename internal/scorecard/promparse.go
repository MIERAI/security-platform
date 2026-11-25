package scorecard

import (
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	pv "github.com/MIERAI/security-platform/internal/pyvalue"
)

// A line of the Prometheus text format and its labels, as the `metric` evaluator reads the published metrics
// (SPEC §6). Compiled once, never written.
var (
	promLine = regexp.MustCompile(`^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{(.*)\})?` + ws + `+(` + nonWS + `+)(` + ws +
		`+[0-9]+)?$`)
	promLabel = regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"`)
)

const nonWS = `[^\t\n\v\f\r \x1c-\x1f\x85\p{Z}]`

// sample is one series of the published metrics.
type sample struct {
	name   string
	labels map[string]string
	value  float64
}

// parseProm reads the text format: blank lines and comments skipped, every other line one sample; label
// values unescaped. Any malformed line or value fails the whole text.
func parseProm(text string) ([]sample, bool) {
	var out []sample
	for _, line := range splitLines(text) {
		line = strings.TrimFunc(line, isSpace)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m := promLine.FindStringSubmatch(line)
		if m == nil {
			return nil, false
		}
		labels := map[string]string{}
		for _, l := range promLabel.FindAllStringSubmatch(m[3], -1) {
			v, ok := unescapeLabel(l[2])
			if !ok {
				return nil, false
			}
			labels[l[1]] = v
		}
		f, err := pv.ToFloat(m[4])
		if err != nil {
			return nil, false
		}
		out = append(out, sample{name: m[1], labels: labels, value: f})
	}
	return out, true
}

func isSpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0x1c, 0x1d, 0x1e, 0x1f, 0x85, 0x2028, 0x2029:
		return true
	}
	return r == 0xa0 || r == 0x1680 || (r >= 0x2000 && r <= 0x200a) || r == 0x202f || r == 0x205f || r == 0x3000
}

// splitLines splits at every line boundary: \n, \r, \r\n, \v, \f, \x1c-\x1e, \x85, U+2028, U+2029.
func splitLines(s string) []string {
	var out []string
	start := 0
	for i, r := range s {
		if i < start {
			continue
		}
		if !isLineBreak(r) {
			continue
		}
		out = append(out, s[start:i])
		start = i + utf8.RuneLen(r)
		if r == '\r' && strings.HasPrefix(s[start:], "\n") {
			start++
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

func isLineBreak(r rune) bool {
	switch r {
	case '\n', '\r', '\v', '\f', 0x1c, 0x1d, 0x1e, 0x85, 0x2028, 0x2029:
		return true
	}
	return false
}

// unescapeLabel decodes a label value's escapes the way the reference reader does: the UTF-8 bytes are taken
// one by one as characters U+0000-U+00FF, and \\ \' \" \a \b \f \n \r \t \v, \ooo, \xhh, \uhhhh and \Uhhhhhhhh
// are decoded; an unknown escape is kept as is. A truncated escape fails (\N{name} is not supported).
func unescapeLabel(s string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteRune(rune(s[i]))
			continue
		}
		if i+1 >= len(s) {
			return "", false
		}
		n, ok := escape(&b, s[i+1:])
		if !ok {
			return "", false
		}
		i += n
	}
	return b.String(), true
}

// escape decodes the escape after a backslash and returns how many bytes it used.
func escape(b *strings.Builder, rest string) (int, bool) {
	simple := map[byte]rune{'\\': '\\', '\'': '\'', '"': '"', 'a': 7, 'b': 8, 'f': 12, 'n': '\n', 'r': '\r', 't': '\t', 'v': 11}
	c := rest[0]
	if r, ok := simple[c]; ok {
		b.WriteRune(r)
		return 1, true
	}
	switch {
	case c == '\n':
		return 1, true
	case c >= '0' && c <= '7':
		return octal(b, rest)
	case c == 'x':
		return hexEscape(b, rest, 2)
	case c == 'u':
		return hexEscape(b, rest, 4)
	case c == 'U':
		return hexEscape(b, rest, 8)
	case c == 'N':
		return 0, false
	}
	b.WriteByte('\\')
	b.WriteRune(rune(c))
	return 1, true
}

func octal(b *strings.Builder, rest string) (int, bool) {
	n := 1
	for n < 3 && n < len(rest) && rest[n] >= '0' && rest[n] <= '7' {
		n++
	}
	v, err := strconv.ParseUint(rest[:n], 8, 16)
	if err != nil {
		return 0, false
	}
	b.WriteRune(rune(v))
	return n, true
}

func hexEscape(b *strings.Builder, rest string, digits int) (int, bool) {
	if len(rest) < 1+digits {
		return 0, false
	}
	v, err := strconv.ParseUint(rest[1:1+digits], 16, 32)
	if err != nil || strings.ContainsAny(rest[1:1+digits], "+-_") || v > utf8.MaxRune {
		return 0, false
	}
	b.WriteRune(rune(v))
	return 1 + digits, true
}
