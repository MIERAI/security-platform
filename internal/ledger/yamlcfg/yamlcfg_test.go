package yamlcfg

import (
	"errors"
	"strings"
	"testing"

	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
)

func TestParse(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, in, want string // want: pyjson.Repr of the result
	}{
		{"empty", "", "None"},
		{"comment only", "# nothing\n", "None"},
		{"block", "exceptions:\n  4a8faf0efd8f:\n    approved_by: alice\n    expires: '2027-01-31'\n",
			"{'exceptions': {'4a8faf0efd8f': {'approved_by': 'alice', 'expires': '2027-01-31'}}}"},
		{"flow", "coverage_exceptions:\n  host|host:phone: {approved_by: alice, reason: a b, expires: 2027-03-01}\n",
			"{'coverage_exceptions': {'host|host:phone': {'approved_by': 'alice', 'reason': 'a b', 'expires': '2027-03-01'}}}"},
		{"json is yaml", `{"a": [1, 2.5, true, null], "b": "x"}`, "{'a': [1, 2.5, True, None], 'b': 'x'}"},
		{"yaml 1.2 core schema", "a: yes\nb: on\nc: True\nd: ~\ne: 0o17\nf: 0x1f\ng: .inf\nh: 2026-01-01T10:00:00Z\n",
			"{'a': 'yes', 'b': 'on', 'c': True, 'd': None, 'e': 15, 'f': 31, 'g': inf, 'h': '2026-01-01T10:00:00Z'}"},
		{"ids keep their text", "123456789012: {approved_by: x}\n000000000012: 1\n1e5: 2\n",
			"{'123456789012': {'approved_by': 'x'}, '000000000012': 1, '1e5': 2}"},
		{"block scalars", "a: |\n  line1\n  line2\nb: >\n  folded\n  text\n", "{'a': 'line1\\nline2\\n', 'b': 'folded text\\n'}"},
		{"anchors and merge", "base: &b {approved_by: alice, expires: '2027-01-01'}\nx:\n  <<: *b\n  reason: r\n  expires: '2028-01-01'\n",
			"{'base': {'approved_by': 'alice', 'expires': '2027-01-01'}, 'x': {'approved_by': 'alice', 'expires': '2028-01-01', 'reason': 'r'}}"},
		{"int beyond 64 bits is a float", "a: 123456789012345678901234567890\n", "{'a': 1.2345678901234568e+29}"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v, err := Parse([]byte(tc.in))
			if err != nil {
				t.Fatal(err)
			}
			if got := pyjson.Repr(v); got != tc.want {
				t.Errorf("Parse(%q)\n got  %s\n want %s", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseErrors(t *testing.T) {
	t.Parallel()
	bomb := "a: &a [x, x, x, x, x, x, x, x, x, x]\n"
	prev := "a"
	for _, n := range []string{"b", "c", "d", "e", "f", "g"} {
		bomb += n + ": &" + n + " [" + strings.TrimSuffix(strings.Repeat("*"+prev+", ", 10), ", ") + "]\n"
		prev = n
	}
	tests := []struct {
		name, in string
		want     error // nil: any error
	}{
		{"two documents", "a: 1\n---\nb: 2\n", ErrMultipleDocuments},
		{"alias bomb", bomb, ErrTooLarge},
		{"mapping key", "? [a, b]\n: 1\n", ErrUnsupportedKey},
		{"syntax", "a: [1, 2\n", nil},
		{"bad merge", "a: {<<: 5}\n", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := Parse([]byte(tc.in))
			if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("Parse error = %v, want %v", err, tc.want)
			}
		})
	}
}

// FuzzParse: no input crashes the parser or the conversion, and a successful result can be rendered as JSON.
func FuzzParse(f *testing.F) {
	for _, s := range []string{"a: 1\n", "x: {<<: [{a: 1}, {b: 2}]}\n", "- &a [1, *a]\n", "a: !!binary aGk=\n",
		"exceptions:\n  id: {approved_by: x, expires: 2027-01-01}\n", "? a\n: b\n", "'k': \"\\u00e9\"\n"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		v, err := Parse([]byte(s))
		if err != nil {
			return
		}
		if _, err := pyjson.Marshal(v, pyjson.Ledger()); err != nil {
			t.Fatalf("result cannot be written: %v", err)
		}
	})
}
