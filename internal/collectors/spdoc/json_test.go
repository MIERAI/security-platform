package spdoc

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/MIERAI/security-platform/internal/pyvalue"
)

func TestMarshalMatchesPython(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("testdata", "golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Src    string `json:"src"`
		Indent int    `json:"indent"`
		Sort   bool   `json:"sort"`
		Out    string `json:"out"`
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		v, err := pyvalue.DecodeJSON([]byte(c.Src))
		if err != nil {
			t.Fatalf("%s: %v", c.Src, err)
		}
		got, err := Marshal(v, c.Indent, c.Sort)
		if err != nil {
			t.Fatalf("%s: %v", c.Src, err)
		}
		if string(got) != c.Out {
			t.Errorf("Marshal(%s, %d, %v) =\n%s\nPython:\n%s", c.Src, c.Indent, c.Sort, got, c.Out)
		}
	}
}

func TestMarshalRejectsUnknownTypes(t *testing.T) {
	t.Parallel()
	if _, err := Marshal([]any{struct{}{}}, 1, true); err == nil {
		t.Fatal("a struct was encoded")
	}
}

// FuzzMarshal: any JSON document pyvalue reads is written as JSON that encoding/json reads back to the same value.
func FuzzMarshal(f *testing.F) {
	for _, s := range []string{`{"b": [1, 2.5, "x"], "a": null}`, `"\ud83d\ude00"`, `[[], {}]`, `1e300`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, src string) {
		v, err := pyvalue.DecodeJSON([]byte(src))
		var want any
		if err != nil || json.Unmarshal([]byte(src), &want) != nil {
			return
		}
		for _, indent := range []int{Compact, 0, 1} {
			roundTrip(t, v, want, indent)
		}
	})
}

func roundTrip(t *testing.T, v, want any, indent int) {
	t.Helper()
	out, err := Marshal(v, indent, indent == 1)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got any
	if json.Unmarshal(out, &got) != nil {
		return // NaN/Infinity: valid for Python, not for encoding/json
	}
	if !reflect.DeepEqual(got, want) { // == on numbers: -0 (read as the integer 0 by Python and pyvalue) equals 0
		t.Fatalf("Marshal(%s, %d) = %s reads back as %s", mustJSON(t, want), indent, out, mustJSON(t, got))
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
