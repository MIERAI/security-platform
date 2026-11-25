package yamlcfg

import (
	"testing"

	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
)

// The expected values are what PyYAML's safe_load gives, then str() of dates as the reference records them.
func TestParse(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, in, want string // want: pyjson.Repr of the result
	}{
		{"empty", "", "None"},
		{"block", "exceptions:\n  4a8faf0efd8f:\n    approved_by: reviewer\n    expires: '2027-01-31'\n",
			"{'exceptions': {'4a8faf0efd8f': {'approved_by': 'reviewer', 'expires': '2027-01-31'}}}"},
		{"flow", "coverage_exceptions:\n  host|host:phone: {approved_by: reviewer, reason: a b, expires: 2027-03-01}\n",
			"{'coverage_exceptions': {'host|host:phone': {'approved_by': 'reviewer', 'reason': 'a b', 'expires': '2027-03-01'}}}"},
		{"json is yaml", `{"a": [1, 2.5, true, null], "b": "x"}`, "{'a': [1, 2.5, True, None], 'b': 'x'}"},
		{"yaml 1.1 typing", "a: yes\nb: 017\nc: 2027-01-31T10:00:00Z\nd: 7d\n",
			"{'a': True, 'b': 15, 'c': '2027-01-31 10:00:00+00:00', 'd': '7d'}"},
		{"merge keys", "base: &b {approved_by: x, expires: '2027-01-01'}\ny:\n  <<: *b\n  expires: '2028-01-01'\n",
			"{'base': {'approved_by': 'x', 'expires': '2027-01-01'}, 'y': {'approved_by': 'x', 'expires': '2028-01-01'}}"},
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
	if _, err := Parse([]byte("a: [1, 2\n")); err == nil {
		t.Error("a syntax error is an error")
	}
}

// FuzzParse: no input crashes the decoder or the conversion, and a result can be written as JSON.
func FuzzParse(f *testing.F) {
	for _, s := range []string{"a: 1\n", "x: {<<: [{a: 1}, {b: 2}]}\n", "- &a [1, *a]\n", "d: 2027-01-01\n",
		"exceptions:\n  id: {approved_by: x, expires: 2027-01-01}\n", "? a\n: b\n"} {
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
