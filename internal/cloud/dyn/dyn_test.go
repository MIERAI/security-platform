package dyn

import (
	"encoding/json"
	"testing"
	"unicode/utf8"
)

func TestPythonSemantics(t *testing.T) {
	t.Parallel()
	v, err := Decode([]byte(`{"n": 123456789012, "f": 1.5, "s": "x", "b": true, "z": 0, "e": "", "l": [], "m": {}, "nil": null}`))
	if err != nil {
		t.Fatal(err)
	}
	m := Map(v)
	tests := []struct {
		key      string
		str      string
		truthy   bool
		textOrEm string
	}{
		{"n", "123456789012", true, "123456789012"}, {"f", "1.5", true, "1.5"}, {"s", "x", true, "x"},
		{"b", "True", true, "True"}, {"z", "0", false, ""}, {"e", "", false, ""}, {"l", "", false, ""},
		{"m", "", false, ""}, {"nil", "", false, ""}, {"absent", "", false, ""},
	}
	for _, tc := range tests {
		if Str(m[tc.key]) != tc.str || Truthy(m[tc.key]) != tc.truthy || Text(m, tc.key) != tc.textOrEm {
			t.Errorf("%s: str %q truthy %v text %q", tc.key, Str(m[tc.key]), Truthy(m[tc.key]), Text(m, tc.key))
		}
	}
	if _, err := Decode([]byte(`{} x`)); err == nil {
		t.Fatal("trailing data accepted")
	}
	if got := Strings([]any{"a", json.Number("1"), map[string]any{}, true}); len(got) != 3 || got[2] != "True" {
		t.Fatalf("Strings: %q", got)
	}
}

func TestCut(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		n    int
		want string
	}{{"héllo", 2, "hé"}, {"abc", 5, "abc"}, {"abc", 0, ""}, {"日本語", 3, "日本語"}, {"日本語", 1, "日"}}
	for _, tc := range tests {
		if got := Cut(tc.in, tc.n); got != tc.want {
			t.Errorf("Cut(%q, %d) = %q, want %q", tc.in, tc.n, got, tc.want)
		}
	}
}

func FuzzDecode(f *testing.F) {
	f.Add([]byte(`{"a": [1, 2.5, "x", null, {"b": true}]}`))
	f.Add([]byte(`[`))
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := Decode(data)
		if err != nil {
			return
		}
		for k, x := range Map(v) {
			_ = Str(x) + Text(Map(v), k) // must not panic, whatever the shape
			if s := Cut(Str(x), 5); utf8.ValidString(Str(x)) && utf8.RuneCountInString(s) > 5 {
				t.Fatalf("Cut kept %d characters", utf8.RuneCountInString(s))
			}
		}
	})
}
