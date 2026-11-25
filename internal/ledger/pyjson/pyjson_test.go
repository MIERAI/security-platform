package pyjson

import (
	"bytes"
	"errors"
	"math"
	"strings"
	"testing"
)

// Expected strings below were produced by CPython 3.12 (repr, f"{x:g}", round, json.dumps).

func TestFloatFormats(t *testing.T) {
	t.Parallel()
	tests := []struct {
		f       float64
		repr, g string
	}{
		{0.0, "0.0", "0"}, {math.Copysign(0, -1), "-0.0", "-0"}, {1.0, "1.0", "1"}, {14.0, "14.0", "14"},
		{13.96, "13.96", "13.96"}, {0.1, "0.1", "0.1"}, {0.0001, "0.0001", "0.0001"}, {1e-05, "1e-05", "1e-05"},
		{1.5e-05, "1.5e-05", "1.5e-05"}, {123456789012345.6, "123456789012345.6", "1.23457e+14"},
		{1e15, "1000000000000000.0", "1e+15"}, {1e16, "1e+16", "1e+16"}, {1.5e16, "1.5e+16", "1.5e+16"},
		{2.5, "2.5", "2.5"}, {1.0 / 3, "0.3333333333333333", "0.333333"}, {-2.75, "-2.75", "-2.75"},
		{1e300, "1e+300", "1e+300"}, {5e-324, "5e-324", "4.94066e-324"}, {100000.0, "100000.0", "100000"},
		{1e6, "1000000.0", "1e+06"}, {1234567.0, "1234567.0", "1.23457e+06"},
		{0.000123456789, "0.000123456789", "0.000123457"}, {math.Inf(1), "inf", "inf"}, {math.NaN(), "nan", "nan"},
	}
	for _, tc := range tests {
		t.Run(tc.repr, func(t *testing.T) {
			t.Parallel()
			if got := FloatRepr(tc.f); got != tc.repr {
				t.Errorf("FloatRepr(%v) = %q, want %q", tc.f, got, tc.repr)
			}
			if got := FormatG(tc.f); got != tc.g {
				t.Errorf("FormatG(%v) = %q, want %q", tc.f, got, tc.g)
			}
		})
	}
}

func TestRound(t *testing.T) {
	t.Parallel()
	tests := []struct {
		x    float64
		n    int
		want string
	}{
		{2.675, 2, "2.67"}, {0.125, 2, "0.12"}, {13.995, 2, "13.99"}, {0.05, 1, "0.1"}, {-0.001, 2, "-0.0"},
		{1.25, 1, "1.2"}, {14.000000001, 2, "14.0"},
	}
	for _, tc := range tests {
		if got := FloatRepr(Round(tc.x, tc.n)); got != tc.want {
			t.Errorf("round(%v, %d) = %s, want %s", tc.x, tc.n, got, tc.want)
		}
	}
}

const sample = "{\"b\": [1, 2.0, {}], \"a\": \"\\u00e9\\u2028\\u007f\\n\\\"\\\\\\u0001\\ud83d\\ude00\", \"c\": [], \"d\": null, \"e\": true}"

func TestMarshalLikeJSONDumps(t *testing.T) {
	t.Parallel()
	v, err := Decode([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		opt  Options
		want string
	}{
		{"ledger", Ledger(), "{\n \"a\": \"\u00e9\u2028\u007f\\n\\\"\\\\\\u0001\U0001f600\",\n \"b\": [\n  1,\n  2.0,\n  {}\n ],\n" +
			" \"c\": [],\n \"d\": null,\n \"e\": true\n}"},
		{"compact", Compact(), sample},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := Marshal(v, tc.opt)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Errorf("got\n%s\nwant\n%s", got, tc.want)
			}
		})
	}
}

func TestDecode(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in      string
		want    string // Repr of the result
		wantErr error
	}{
		{`{"a": 1, "b": 1.0, "a": 2}`, "{'a': 2, 'b': 1.0}", nil},
		{`[-0, 1e2, 99999999999999999999, 1E999]`, "[0, 100.0, 99999999999999999999, inf]", nil},
		{`"x" "y"`, "", ErrTrailingData},
		{strings.Repeat("[", MaxDepth+1) + strings.Repeat("]", MaxDepth+1), "", ErrTooDeep},
		{`{"a": }`, "", nil},
	}
	for _, tc := range tests {
		t.Run(tc.in[:min(len(tc.in), 20)], func(t *testing.T) {
			t.Parallel()
			v, err := Decode([]byte(tc.in))
			switch {
			case tc.want == "" && tc.wantErr == nil:
				if err == nil {
					t.Fatalf("Decode(%q) succeeded", tc.in)
				}
			case tc.wantErr != nil:
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Decode(%q) error %v, want %v", tc.in, err, tc.wantErr)
				}
			case err != nil:
				t.Fatal(err)
			case Repr(v) != tc.want:
				t.Errorf("Decode(%q) = %s, want %s", tc.in, Repr(v), tc.want)
			}
		})
	}
}

func TestRepr(t *testing.T) {
	t.Parallel()
	tests := []struct {
		v    Value
		want string
	}{
		{"it's", `"it's"`}, {`a"b'c`, `'a"b\'c'`}, {"\x00\x7f\u0085\u00e9\u2028\U0001f600\t", "'\\x00\\x7f\\x85\u00e9\\u2028\U0001f600\\t'"},
		{[]Value{"x", int64(1), nil, ObjectOf("k", 2.5)}, `['x', 1, None, {'k': 2.5}]`}, {true, "True"},
	}
	for _, tc := range tests {
		if got := Repr(tc.v); got != tc.want {
			t.Errorf("Repr(%#v) = %s, want %s", tc.v, got, tc.want)
		}
	}
}

func TestPythonNumbers(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		got  Value
		want string
	}{
		{"sum ints", Sum([]Value{int64(1), int64(2)}), "3"},
		{"sum mixed", Sum([]Value{int64(1), 2.0}), "3.0"},
		{"sum empty", Sum(nil), "0"},
		{"max keeps type", Max([]Value{int64(2), 2.0, int64(1)}), "2"},
		{"median odd", Median([]Value{int64(3), int64(1), int64(2)}), "2"},
		{"median even", Median([]Value{int64(1), int64(2)}), "1.5"},
		{"round int", RoundValue(int64(3), 1), "3"},
		{"round float", RoundValue(2.25, 1), "2.2"},
	}
	for _, tc := range tests {
		if Repr(tc.got) != tc.want {
			t.Errorf("%s = %s, want %s", tc.name, Repr(tc.got), tc.want)
		}
	}
}

func TestTruthyAndContains(t *testing.T) {
	t.Parallel()
	falsy := []Value{nil, false, "", int64(0), 0.0, []Value{}, NewObject()}
	for _, v := range falsy {
		if Truthy(v) {
			t.Errorf("Truthy(%s) = true", Repr(v))
		}
	}
	if !Contains("host", "os") || !Contains([]Value{"a", "b"}, "b") || Contains([]Value{int64(1)}, "1") ||
		!Contains(ObjectOf("k", nil), "k") || Contains(int64(5), "5") {
		t.Error("Contains does not follow Python's `in`")
	}
}

// FuzzDecode: any input either fails to parse or round-trips: Marshal(Decode(x)) decodes to the same text.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{sample, `{"a":[1,2.5e-7,{"b":null}]}`, `"\ud800"`, `1E400`, `[]`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		v, err := Decode([]byte(s))
		if err != nil || hasNonFinite(v) { // Python writes Infinity/NaN, which only Python reads back
			return
		}
		for _, opt := range []Options{Ledger(), Compact()} {
			roundTrip(t, v, opt)
		}
	})
}

// roundTrip: the output of Marshal parses, and marshals again to the same bytes.
func roundTrip(t *testing.T, v Value, opt Options) {
	t.Helper()
	out, err := Marshal(v, opt)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	w, err := Decode(out)
	if err != nil {
		t.Fatalf("output does not parse: %v\n%s", err, out)
	}
	again, err := Marshal(w, opt)
	if err != nil || !bytes.Equal(again, out) {
		t.Fatalf("not stable:\n%s\n%s", out, again)
	}
}

func hasNonFinite(v Value) bool {
	switch t := v.(type) {
	case float64:
		return !IsFinite(t)
	case []Value:
		for _, x := range t {
			if hasNonFinite(x) {
				return true
			}
		}
	case *Object:
		for _, k := range t.Keys() {
			if x, _ := t.Get(k); hasNonFinite(x) {
				return true
			}
		}
	}
	return false
}
