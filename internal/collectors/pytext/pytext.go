// Package pytext reads and writes text the way the Python collectors do, so that the Go collectors produce the
// same documents from the same target output: subprocess output decoding (UTF-8, errors="replace", universal
// newlines), str.splitlines / str.strip, slicing by code point, shlex.quote, subprocess.list2cmdline and
// fnmatch.fnmatchcase for the `*`/`?` patterns the collectors use.
package pytext

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Decode is bytes.decode("utf-8", "replace") followed by universal newlines ("\r\n" and "\r" become "\n"), what
// Python's subprocess returns in text mode. Every maximal invalid subsequence becomes one U+FFFD, as in Python.
func Decode(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b))
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		if r != utf8.RuneError || size > 1 {
			sb.WriteRune(r)
			i += size
			continue
		}
		sb.WriteRune(utf8.RuneError)
		i += invalidLen(b[i:])
	}
	return strings.ReplaceAll(strings.ReplaceAll(sb.String(), "\r\n", "\n"), "\r", "\n")
}

// invalidLen is the length of the maximal subpart of an ill-formed UTF-8 sequence at the start of b (at least 1):
// a lead byte followed by the continuation bytes that are valid for it, until one is not (Unicode §3.9, U+FFFD
// substitution of maximal subparts, which Python's decoder follows).
func invalidLen(b []byte) int {
	lo, hi, n := secondByteRange(b[0])
	if n == 0 {
		return 1
	}
	k := 1
	for ; k <= n && k < len(b); k++ {
		c := b[k]
		if k == 1 && (c < lo || c > hi) || k > 1 && (c < 0x80 || c > 0xBF) {
			break
		}
	}
	return k
}

// secondByteRange: the valid range of the byte after lead byte c, and how many continuation bytes c needs
// (0: c cannot start a sequence).
func secondByteRange(c byte) (lo, hi byte, n int) {
	switch {
	case c >= 0xC2 && c <= 0xDF:
		return 0x80, 0xBF, 1
	case c == 0xE0:
		return 0xA0, 0xBF, 2
	case c == 0xED:
		return 0x80, 0x9F, 2
	case c >= 0xE1 && c <= 0xEF:
		return 0x80, 0xBF, 2
	case c == 0xF0:
		return 0x90, 0xBF, 3
	case c >= 0xF1 && c <= 0xF3:
		return 0x80, 0xBF, 3
	case c == 0xF4:
		return 0x80, 0x8F, 3
	}
	return 0, 0, 0
}

// IsSpace is Python's str.isspace for one character: Go's unicode.IsSpace plus the information separators
// U+001C..U+001F.
func IsSpace(r rune) bool {
	return unicode.IsSpace(r) || r >= 0x1C && r <= 0x1F
}

// Strip is str.strip(): whitespace (IsSpace) removed at both ends.
func Strip(s string) string { return strings.TrimFunc(s, IsSpace) }

// lineBreak reports whether r ends a line for str.splitlines.
func lineBreak(r rune) bool {
	switch r {
	case '\n', '\r', '\v', '\f', 0x1C, 0x1D, 0x1E, 0x85, 0x2028, 0x2029:
		return true
	}
	return false
}

// SplitLines is str.splitlines(): lines without their line breaks ("\r\n" is one break); no empty last element for
// a text that ends with a break; no element at all for "".
func SplitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if !lineBreak(r) {
			i += size
			continue
		}
		out = append(out, s[start:i])
		i += size
		if r == '\r' && i < len(s) && s[i] == '\n' {
			i++
		}
		start = i
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// Head is s[:n] counted in code points.
func Head(s string, n int) string {
	i := 0
	for j := range s {
		if i == n {
			return s[:j]
		}
		i++
	}
	return s
}

// Tail is s[-n:] counted in code points (all of s when it is shorter).
func Tail(s string, n int) string {
	if n <= 0 {
		return ""
	}
	end := len(s)
	for c := 0; end > 0; c++ {
		if c == n {
			return s[end:]
		}
		_, size := utf8.DecodeLastRuneInString(s[:end])
		end -= size
	}
	return s
}

// ShellQuote is shlex.quote: s unchanged when it only has characters a POSIX shell never interprets, otherwise
// in single quotes with every single quote written as '"'"'.
func ShellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if strings.IndexFunc(s, shellUnsafe) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

func shellUnsafe(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return false
	}
	return !strings.ContainsRune("_@%+=:,./-", r)
}

// CmdLine is subprocess.list2cmdline: the argument vector as one Windows command line (the rules of the Microsoft
// C runtime: arguments with a space or tab, or empty ones, in double quotes; a double quote escaped with a
// backslash, and the backslashes before it doubled; trailing backslashes of a quoted argument doubled).
func CmdLine(args []string) string {
	var b strings.Builder
	for i, arg := range args {
		if i > 0 {
			b.WriteByte(' ')
		}
		quote := arg == "" || strings.ContainsAny(arg, " \t")
		if quote {
			b.WriteByte('"')
		}
		backslashes := 0
		for _, r := range arg {
			switch r {
			case '\\':
				backslashes++
			case '"':
				b.WriteString(strings.Repeat(`\`, 2*backslashes) + `\"`)
				backslashes = 0
			default:
				b.WriteString(strings.Repeat(`\`, backslashes))
				backslashes = 0
				b.WriteRune(r)
			}
		}
		b.WriteString(strings.Repeat(`\`, backslashes))
		if quote {
			b.WriteString(strings.Repeat(`\`, backslashes) + `"`)
		}
	}
	return b.String()
}

// FnMatch is fnmatch.fnmatchcase(name, pattern) on valid UTF-8 text (what Decode returns) for patterns made of literal characters, `*` (any text, `/`
// included) and `?` (one character). The collectors' patterns use nothing else.
func FnMatch(name, pattern string) bool {
	n, p := []rune(name), []rune(pattern)
	ni, pi := 0, 0
	star, mark := -1, 0
	for ni < len(n) {
		switch {
		case pi < len(p) && (p[pi] == '?' || p[pi] == n[ni]) && p[pi] != '*':
			ni++
			pi++
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, ni
			pi++
		case star >= 0:
			pi = star + 1
			mark++
			ni = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}
