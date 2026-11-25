package pyvalue

import (
	"math"
	"testing"
)

// FuzzDecodeYAML: any input either fails cleanly or gives a value that can be printed and written as JSON
// (when it holds no timestamp) without panicking.
func FuzzDecodeYAML(f *testing.F) {
	for _, s := range []string{"", "a: 1\n", "schema: x\ndimension: {id: a, order: 1}\ncontrols:\n  - {id: a.b, weight: 2.5}\n",
		"x: &a [1]\ny: [*a, *a]\n", "m: {<<: {a: 1}, b: [yes, no, ~, 0x1f, 1:30, 2030-01-01]}\n", "? [a]\n: b\n",
		"t: 2030-01-31 10:00:00.5 +09:00\n", "'k': !!float '1'\n"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(_ *testing.T, data []byte) {
		v, err := DecodeYAML(data)
		if err != nil {
			return
		}
		_ = Repr(v)
		_ = Str(v)
		_ = Truthy(v)
		_, _ = EncodeJSON(v, false) // fails (cleanly) only for timestamps
	})
}

// FuzzDecodeJSON: a decoded document written back and decoded again is the same document.
func FuzzDecodeJSON(f *testing.F) {
	for _, s := range []string{`{}`, `{"a": [1, 2.5, "x", null, true, {"b": -0.0}]}`, `[1e308, 5e-324]`, `"é"`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := DecodeJSON(data)
		if err != nil {
			return
		}
		for _, ascii := range []bool{false, true} {
			roundTrip(t, v, ascii)
		}
	})
}

func roundTrip(t *testing.T, v any, ascii bool) {
	t.Helper()
	text, err := EncodeJSON(v, ascii)
	if err != nil {
		t.Fatalf("encode %#v: %v", v, err)
	}
	if hasNonFinite(v) {
		return // NaN and Infinity are written as the reference writes them, which JSON cannot read
	}
	back, err := DecodeJSON(text)
	if err != nil {
		t.Fatalf("decode %s: %v", text, err)
	}
	if !Equal(v, back) {
		t.Fatalf("round trip changed %s", text)
	}
}

func hasNonFinite(v any) bool {
	switch x := v.(type) {
	case float64:
		return math.IsInf(x, 0) || math.IsNaN(x)
	case []any:
		for _, e := range x {
			if hasNonFinite(e) {
				return true
			}
		}
	case *Map:
		for _, k := range x.Keys() {
			if hasNonFinite(x.Value(k)) {
				return true
			}
		}
	}
	return false
}

// FuzzNumbers: formatting and conversions never panic, and a repr reads back as the same float.
func FuzzNumbers(f *testing.F) {
	f.Add(1.5, " 1_0 ")
	f.Add(6.25, "inf")
	f.Fuzz(func(t *testing.T, x float64, s string) {
		if r := FloatRepr(x); !math.IsNaN(x) && !math.IsInf(x, 0) {
			back, err := ToFloat(r)
			if err != nil || back != x {
				t.Fatalf("FloatRepr(%v) = %q reads back as %v, %v", x, r, back, err)
			}
		}
		_ = FormatG(x)
		_ = Round(x, 1)
		_, _ = ToFloat(s)
		_, _ = ToInt(s)
		_, _ = ParseInt(s, 8)
		_, _ = Sum([]any{x, int64(len(s)), x})
	})
}
