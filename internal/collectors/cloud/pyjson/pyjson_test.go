package pyjson

import (
	"encoding/json"
	"math"
	"reflect"
	"testing"
)

func TestFloatRepr(t *testing.T) {
	t.Parallel()
	// repr() of each value in CPython 3.12
	tests := []struct {
		in   float64
		want string
	}{
		{0, "0.0"}, {math.Copysign(0, -1), "-0.0"}, {1, "1.0"}, {3, "3.0"}, {0.1, "0.1"}, {12.3, "12.3"},
		{1e16, "1e+16"}, {1.5e-05, "1.5e-05"}, {0.0001, "0.0001"}, {123456789.5, "123456789.5"}, {2.5e+20, "2.5e+20"},
		{1234567, "1234567.0"}, {100, "100.0"}, {1.0 / 3, "0.3333333333333333"}, {-2.5, "-2.5"}, {9999999999999998, "9999999999999998.0"},
	}
	for _, tc := range tests {
		if got := FloatRepr(tc.in); got != tc.want {
			t.Errorf("FloatRepr(%v) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

func TestMarshalMatchesPython(t *testing.T) {
	t.Parallel()
	v := map[string]any{"b": []any{1, map[string]any{"x": "é \x7f\x01\"\\ \U0001F600"}}, "a": map[string]any{},
		"c": []any{}, "d": nil, "e": true, "f": 2.0}
	// json.dumps(v, indent=1, sort_keys=True) in CPython 3.12
	want := "{\n \"a\": {},\n \"b\": [\n  1,\n  {\n   \"x\": \"\\u00e9\\u2028\\u007f\\u0001\\\"\\\\ \\ud83d\\ude00\"\n  }\n ],\n" +
		" \"c\": [],\n \"d\": null,\n \"e\": true,\n \"f\": 2.0\n}"
	got, err := Marshal(v, 1)
	if err != nil || string(got) != want {
		t.Fatalf("got\n%s\nwant\n%s (%v)", got, want, err)
	}
	if _, err := Marshal(struct{}{}, 1); err == nil {
		t.Fatal("an unsupported type was encoded")
	}
}

func FuzzMarshalRoundTrip(f *testing.F) {
	f.Add("plain", 1.5, int64(3))
	f.Add("\x00 \U0001F600\"\\", math.Copysign(0, -1), int64(-1))
	f.Add("\xff", 1e300, int64(math.MaxInt64))
	f.Fuzz(func(t *testing.T, s string, x float64, n int64) {
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return
		}
		v := map[string]any{s: []any{s, x, n, map[string]string{s: s}, nil, true}}
		data := asciiJSON(t, v)
		var back map[string]any
		if err := json.Unmarshal(data, &back); err != nil {
			t.Fatalf("not JSON: %v\n%s", err, data)
		}
		want := map[string]any{}
		if err := json.Unmarshal(mustStd(t, v), &want); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(back, want) {
			t.Fatalf("round trip differs:\n%v\n%v", back, want)
		}
	})
}

func mustStd(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// asciiJSON is Marshal's output, which must be ASCII only (as Python's ensure_ascii).
func asciiJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := Marshal(v, 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range data {
		if c >= 0x80 {
			t.Fatalf("non-ASCII byte in %q", data)
		}
	}
	return data
}
