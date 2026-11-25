package pytext

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

// golden is testdata/golden.json: Python's answers (testdata/gen_golden.py).
type golden struct {
	Decode     [][2]string       `json:"decode"`
	SplitLines []json.RawMessage `json:"splitlines"`
	Strip      [][2]string       `json:"strip"`
	Quote      [][2]string       `json:"quote"`
	CmdLine    []json.RawMessage `json:"cmdline"`
	FnMatch    []json.RawMessage `json:"fnmatch"`
}

func loadGolden(t *testing.T) golden {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	var g golden
	if err := json.Unmarshal(data, &g); err != nil {
		t.Fatal(err)
	}
	return g
}

func TestMatchesPython(t *testing.T) {
	t.Parallel()
	g := loadGolden(t)
	for _, c := range g.Decode {
		raw, err := base64.StdEncoding.DecodeString(c[0])
		if err != nil {
			t.Fatal(err)
		}
		if got := Decode(raw); got != c[1] {
			t.Errorf("Decode(%q) = %q, Python %q", raw, got, c[1])
		}
	}
	for _, c := range g.Strip {
		if got := Strip(c[0]); got != c[1] {
			t.Errorf("Strip(%q) = %q, Python %q", c[0], got, c[1])
		}
	}
	for _, c := range g.Quote {
		if got := ShellQuote(c[0]); got != c[1] {
			t.Errorf("ShellQuote(%q) = %q, Python %q", c[0], got, c[1])
		}
	}
	matchStructured(t, g)
}

func matchStructured(t *testing.T, g golden) {
	t.Helper()
	for _, raw := range g.SplitLines {
		var in string
		var want []string
		unpack(t, raw, &in, &want)
		if got := SplitLines(in); !reflect.DeepEqual(nonNil(got), nonNil(want)) {
			t.Errorf("SplitLines(%q) = %q, Python %q", in, got, want)
		}
	}
	for _, raw := range g.CmdLine {
		var in []string
		var want string
		unpack(t, raw, &in, &want)
		if got := CmdLine(in); got != want {
			t.Errorf("CmdLine(%q) = %q, Python %q", in, got, want)
		}
	}
	for _, raw := range g.FnMatch {
		var name, pattern string
		var want bool
		unpack(t, raw, &name, &pattern, &want)
		if got := FnMatch(name, pattern); got != want {
			t.Errorf("FnMatch(%q, %q) = %v, Python %v", name, pattern, got, want)
		}
	}
}

func unpack(t *testing.T, raw json.RawMessage, into ...any) {
	t.Helper()
	var parts []json.RawMessage
	if err := json.Unmarshal(raw, &parts); err != nil || len(parts) != len(into) {
		t.Fatalf("golden entry %s: %v", raw, err)
	}
	for i, p := range parts {
		if err := json.Unmarshal(p, into[i]); err != nil {
			t.Fatal(err)
		}
	}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func TestHeadTail(t *testing.T) {
	t.Parallel()
	tests := []struct {
		s          string
		n          int
		head, tail string
	}{
		{"", 3, "", ""},
		{"abc", 0, "", ""},
		{"abc", 2, "ab", "bc"},
		{"abc", 5, "abc", "abc"},
		{"日本語テキスト", 3, "日本語", "キスト"},
	}
	for _, tt := range tests {
		if got := Head(tt.s, tt.n); got != tt.head {
			t.Errorf("Head(%q, %d) = %q, want %q", tt.s, tt.n, got, tt.head)
		}
		if got := Tail(tt.s, tt.n); got != tt.tail {
			t.Errorf("Tail(%q, %d) = %q, want %q", tt.s, tt.n, got, tt.tail)
		}
	}
}

// FuzzDecode: the text is valid UTF-8 without carriage returns, and valid UTF-8 input without "\r" is unchanged.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{"a=1\r\n", "\xe2\x82(", "\xff", "ok"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		got := Decode(b)
		if !utf8.ValidString(got) || strings.Contains(got, "\r") {
			t.Fatalf("Decode(%q) = %q", b, got)
		}
		if utf8.Valid(b) && !strings.Contains(string(b), "\r") && got != string(b) {
			t.Fatalf("Decode changed valid text %q to %q", b, got)
		}
	})
}

// FuzzSplitLines: no line holds a line break, and the lines joined with "\n" give the text back for "\n"-only text.
func FuzzSplitLines(f *testing.F) {
	for _, s := range []string{"a\nb", "a\r\nb\r", "\x1c\x85", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		lines := SplitLines(s)
		for _, l := range lines {
			if strings.IndexFunc(l, lineBreak) >= 0 {
				t.Fatalf("line %q of %q holds a break", l, s)
			}
		}
		if strings.IndexFunc(s, func(r rune) bool { return lineBreak(r) && r != '\n' }) < 0 {
			if j := strings.Join(lines, "\n"); j != strings.TrimSuffix(s, "\n") {
				t.Fatalf("joined %q != %q", j, s)
			}
		}
	})
}

// FuzzShellQuote: a POSIX shell reads the quoted text back as exactly one word, the original.
func FuzzShellQuote(f *testing.F) {
	for _, s := range []string{"", "a b", "it's", "$(x)", "-n"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if got := unquotePOSIX(ShellQuote(s)); got != s {
			t.Fatalf("ShellQuote(%q) reads back as %q", s, got)
		}
	})
}

// unquotePOSIX reads one shell word made of bare safe characters, '...' and the '"'"' sequence.
func unquotePOSIX(q string) string {
	var b strings.Builder
	for i := 0; i < len(q); i++ {
		switch q[i] {
		case '\'':
			j := strings.IndexByte(q[i+1:], '\'')
			if j < 0 {
				return "\x00unterminated"
			}
			b.WriteString(q[i+1 : i+1+j])
			i += j + 1
		case '"':
			j := strings.IndexByte(q[i+1:], '"')
			if j < 0 {
				return "\x00unterminated"
			}
			b.WriteString(q[i+1 : i+1+j])
			i += j + 1
		default:
			if !shellUnsafe(rune(q[i])) {
				b.WriteByte(q[i])
				continue
			}
			return "\x00unquoted " + string(q[i])
		}
	}
	return b.String()
}

// FuzzCmdLine: the Microsoft C runtime's parser reads the command line back as the same argument vector.
func FuzzCmdLine(f *testing.F) {
	f.Add("a", "b c", `x\"y\`)
	f.Add("", "\t", `\\`)
	f.Fuzz(func(t *testing.T, a, b, c string) {
		in := []string{a, b, c}
		for _, s := range in {
			if strings.ContainsAny(s, "\x00\n\r\v\f") || !utf8.ValidString(s) {
				return // not representable on a command line
			}
		}
		if got := parseMSVC(CmdLine(in)); !reflect.DeepEqual(got, in) {
			t.Fatalf("CmdLine(%q) = %q reads back as %q", in, CmdLine(in), got)
		}
	})
}

// parseMSVC splits a command line by the rules of the Microsoft C runtime (2008 and later): whitespace separates
// arguments outside quotes; 2n backslashes before a quote are n backslashes and the quote toggles quoting; 2n+1
// are n and a literal quote; backslashes not before a quote are literal.
func parseMSVC(s string) []string {
	p := &msvc{}
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\':
			i = p.backslashes(s, i)
		case c == '"':
			p.quoted, p.inArg = !p.quoted, true
		case (c == ' ' || c == '\t') && !p.quoted:
			p.end()
		default:
			p.cur.WriteByte(c)
			p.inArg = true
		}
	}
	p.end()
	return p.out
}

type msvc struct {
	out           []string
	cur           strings.Builder
	inArg, quoted bool
}

func (p *msvc) end() {
	if p.inArg {
		p.out = append(p.out, p.cur.String())
		p.cur.Reset()
		p.inArg = false
	}
}

// backslashes reads the run of backslashes at s[i:] and returns the index of its last byte (or of the quote after it).
func (p *msvc) backslashes(s string, i int) int {
	n := 0
	for i < len(s) && s[i] == '\\' {
		n++
		i++
	}
	p.inArg = true
	if i >= len(s) || s[i] != '"' {
		p.cur.WriteString(strings.Repeat(`\`, n))
		return i - 1
	}
	p.cur.WriteString(strings.Repeat(`\`, n/2))
	if n%2 == 1 {
		p.cur.WriteByte('"')
	} else {
		p.quoted = !p.quoted
	}
	return i
}

func FuzzFnMatch(f *testing.F) {
	f.Add("sshd.x", "sshd.*")
	f.Add("aXbXc", "a*b?c")
	f.Fuzz(func(t *testing.T, name, pattern string) {
		if strings.ContainsAny(pattern, "[") || !utf8.ValidString(name) || !utf8.ValidString(pattern) {
			return // character classes are not used by the collectors; text is always valid UTF-8 (Decode)
		}
		got := FnMatch(name, pattern)
		if !strings.ContainsAny(pattern, "*?") && got != (name == pattern) {
			t.Fatalf("FnMatch(%q, literal %q) = %v", name, pattern, got)
		}
		if pattern == "*" && !got {
			t.Fatalf("* does not match %q", name)
		}
	})
}
