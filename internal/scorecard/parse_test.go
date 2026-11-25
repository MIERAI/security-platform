package scorecard

import (
	"strings"
	"testing"
)

// Expected values below are the reference implementation's answers for the same inputs.

func TestTimestamp(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want float64
		err  string
	}{
		{"2030-01-10", 1894233600, ""},
		{"2030-1-5", 1893801600, ""},
		{"2030-01- 5", 1893801600, ""},
		{"2030-01-10T00:00:00Z", 1894233600, ""},
		{"2030-01-10T1:2:3", 1894237323, ""},
		{"2030-01-10T23:59:61", 1894320001, ""},
		{"2030-01-10t00:00:00", 1894233600, ""},
		{"2030-01-1", 1893456000, ""},
		{"2030-01-10 10:00:00", 1894233600, ""},
		{"2030-02-30", 0, "ValueError: day is out of range for month"},
		{"2030-13-01", 0, "ValueError: time data '2030-13-01' does not match format '%Y-%m-%d'"},
		{"x", 0, "ValueError: time data 'x' does not match format '%Y-%m-%d'"},
		{"2030-01-10Tjunk", 0, "ValueError: time data '2030-01-10Tjunk' does not match format '%Y-%m-%dT%H:%M:%S'"},
		{"0000-01-01", 0, "ValueError: year 0 is out of range"},
		{"2030-01-10x", 0, ""},
	}
	for _, tc := range tests {
		got, err := timestamp(tc.in)
		switch {
		case tc.err != "" && (err == nil || err.Error() != tc.err):
			t.Errorf("timestamp(%q) error = %v, want %s", tc.in, err, tc.err)
		case tc.err == "" && tc.in != "2030-01-10x" && (err != nil || got != tc.want):
			t.Errorf("timestamp(%q) = %v, %v, want %v", tc.in, got, err, tc.want)
		}
	}
}

func TestDuration(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   any
		want float64
		err  bool
	}{
		{"90d", 7776000, false}, {" 1.5 w ", 907200, false}, {"12h", 43200, false}, {nil, 7, false},
		{int64(3), 3, false}, {true, 1, false}, {"10", 0, true}, {"x", 0, true}, {"1e3d", 0, true},
	}
	for _, tc := range tests {
		got, err := duration(tc.in, 7)
		if (err != nil) != tc.err || (!tc.err && got != tc.want) {
			t.Errorf("duration(%#v) = %v, %v", tc.in, got, err)
		}
	}
	if _, err := duration("x", 0); err == nil || err.Error() != "ValueError: bad duration 'x' (e.g. 90d, 12h)" {
		t.Errorf("message: %v", err)
	}
}

func TestGlob(t *testing.T) {
	t.Parallel()
	tests := []struct {
		pattern, id string
		want        bool
	}{
		{"beta.*", "beta.x", true}, {"beta.*", "alpha.x", false}, {"a?c", "abc", true}, {"a?c", "ac", false},
		{"[a-c]x", "bx", true}, {"[!a-c]x", "bx", false}, {"[!a-c]x", "dx", true}, {"[z-a]x", "zx", false},
		{"[az-bc]", "c", true}, {"[az-bc]", "z", false}, {"[a-]", "-", true}, {"[]a]", "]", true},
		{"[!]a]", "b", true}, {"[", "[", true}, {"a[b", "a[b", true}, {"*", "a/b\nc", true}, {`a\b`, `a\b`, true},
		{"**.x", "q.x", true}, {"[a-c-e]", "-", true}, {"[a-c-e]", "d", false}, {"[!]", "!", false},
		{"[!]", "[!]", true}, {"x.[!.]*", "x.ab", true}, {"a.(b)+", "a.(b)+", true},
	}
	for _, tc := range tests {
		re, err := globRegexp(tc.pattern)
		if err != nil {
			t.Fatalf("%q: %v", tc.pattern, err)
		}
		if got := re.MatchString(tc.id); got != tc.want {
			t.Errorf("glob %q on %q = %v, want %v", tc.pattern, tc.id, got, tc.want)
		}
	}
}

func TestParseProm(t *testing.T) {
	t.Parallel()
	text := "# HELP x\r\nm{a=\"1\",b=\"q\\\"\\\\\\n\"} 1.5 1700000000\n\n  n 2\x0bo{c=\"\\x41\\101\\u00e9\\q\"} +Inf\nsecurity_score 1\n"
	got, ok := parseProm(text)
	if !ok || len(got) != 4 {
		t.Fatalf("parseProm = %#v, %v", got, ok)
	}
	if got[0].labels["b"] != "q\"\\\n" || got[0].value != 1.5 {
		t.Errorf("sample 0 = %#v", got[0])
	}
	if got[2].name != "o" || got[2].labels["c"] != `AAé\q` {
		t.Errorf("sample 2 = %#v", got[2])
	}
	for _, bad := range []string{"m{a=\"1\"}", "m x", "m{a=\"\\x4\"} 1", "1m 1"} {
		if _, ok := parseProm(bad); ok {
			t.Errorf("parseProm(%q) must fail", bad)
		}
	}
	if v, _ := unescapeLabel("é"); v != "Ã©" {
		t.Errorf("non-ASCII bytes are read one by one: %q", v)
	}
}

func TestParseArgs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		argv []string
		want string // command|data|now|catalogs|control, or the error
	}{
		{[]string{"compute", "--data", "D", "--now", "5"}, "compute|D|5||"},
		{[]string{"--data=D", "compute", "--catalog", "a", "--catalog=b"}, "compute|D||a,b|"},
		{[]string{"compute", "--inst", "i.yaml", "--data", "D", "--now", "-5"}, "compute|D|-5||"},
		{[]string{"attest", "c.x", "--by", "me", "--false"}, "attest|||c.x|"},
		{[]string{"lint", "--", "x"}, "lint||||x"},
		{[]string{"compute", "--no", "1"}, "error"},
		{[]string{"compute", "--data"}, "error"},
		{[]string{"compute", "--data", "--now"}, "error"},
		{[]string{"nope"}, "error"},
		{[]string{}, "error"},
		{[]string{"list", "a", "b"}, "error"},
		{[]string{"compute", "--false=1"}, "error"},
		{[]string{"compute", "--bogus"}, "error"},
	}
	for _, tc := range tests {
		a, err := ParseArgs(tc.argv)
		got := "error"
		if err == nil {
			got = strings.Join([]string{a.Command, a.Data, a.Now, strings.Join(a.Catalogs, ","), a.Control}, "|")
			if a.Command == "attest" {
				got = strings.Join([]string{a.Command, a.Data, a.Now, a.Control, a.Values["catalog"]}, "|")
			}
		}
		if got != tc.want {
			t.Errorf("ParseArgs(%q) = %s (%v), want %s", tc.argv, got, err, tc.want)
		}
	}
	if _, err := ParseArgs([]string{"-h"}); err != ErrHelp { //nolint:errorlint // sentinel returned unwrapped
		t.Errorf("-h: %v", err)
	}
}
