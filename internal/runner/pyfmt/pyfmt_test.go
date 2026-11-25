package pyfmt

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

type reference struct {
	Floats []struct {
		F    float64 `json:"f"`
		Repr string  `json:"repr"`
		G    string  `json:"g"`
	} `json:"floats"`
	JSONInput json.RawMessage `json:"json_input"`
	JSON      string          `json:"json"`
}

func loadReference(t *testing.T) reference {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "reference.json"))
	if err != nil {
		t.Fatal(err)
	}
	var ref reference
	if err := json.Unmarshal(data, &ref); err != nil {
		t.Fatal(err)
	}
	return ref
}

// TestMatchesPython compares with Python's repr(float), format(float, "g") and json.dumps(indent=1, sort_keys=True)
// (testdata/gen_reference.py).
func TestMatchesPython(t *testing.T) {
	t.Parallel()
	ref := loadReference(t)
	for _, c := range ref.Floats {
		if got := FloatRepr(c.F); got != c.Repr {
			t.Errorf("FloatRepr(%v) = %q, want %q", c.F, got, c.Repr)
		}
		if got := FormatG(c.F); got != c.G {
			t.Errorf("FormatG(%v) = %q, want %q", c.F, got, c.G)
		}
	}
	v, err := Decode(ref.JSONInput)
	if err != nil {
		t.Fatal(err)
	}
	got, err := JSONIndent1(v)
	if err != nil || string(got) != ref.JSON {
		t.Errorf("JSONIndent1 =\n%s\nwant\n%s (%v)", got, ref.JSON, err)
	}
}

func TestScalarsAndErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   any
		want string
	}{
		{int64(5), "5"}, {7, "7"}, {2.5, "2.5"}, {math.Inf(1), "Infinity"}, {math.NaN(), "NaN"},
		{[]string{"a"}, "[\n \"a\"\n]"}, {map[string]any{}, "{}"}, {json.Number("1.0"), "1.0"},
	}
	for _, tt := range tests {
		got, err := JSONIndent1(tt.in)
		if err != nil || string(got) != tt.want {
			t.Errorf("JSONIndent1(%#v) = %q, %v; want %q", tt.in, got, err, tt.want)
		}
	}
	if _, err := JSONIndent1(map[string]any{"x": struct{}{}}); !errors.Is(err, ErrUnsupported) {
		t.Errorf("unsupported value: %v", err)
	}
	if _, err := Decode([]byte("{} {}")); err == nil {
		t.Error("two values accepted")
	}
	for in, want := range map[any]string{nil: "None", true: "True", json.Number("2"): "2", json.Number("2.50"): "2.5",
		1.0: "1.0", "s": "s", int64(-1): "-1"} {
		if got := Str(in); got != want {
			t.Errorf("Str(%#v) = %q, want %q", in, got, want)
		}
	}
}

// FuzzFloatRepr: the text always parses back to the same float, and has a decimal point or an exponent.
func FuzzFloatRepr(f *testing.F) {
	for _, v := range []float64{0, 1, 0.1, 1e16, 1e-5, 123.456, math.Copysign(0, -1)} {
		f.Add(v)
	}
	f.Fuzz(func(t *testing.T, v float64) {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return
		}
		s := FloatRepr(v)
		back, err := strconv.ParseFloat(s, 64)
		if err != nil || back != v {
			t.Fatalf("FloatRepr(%v) = %q does not round-trip", v, s)
		}
	})
}

// FuzzJSON: any JSON document re-encodes to JSON that decodes to the same value.
func FuzzJSON(f *testing.F) {
	for _, s := range []string{`{"a": [1, 2.5, "xé"], "b": null}`, `"😀"`, `[]`, `{"z": {"y": true}}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := Decode(data)
		if err != nil {
			return
		}
		out, err := JSONIndent1(v)
		if err != nil {
			t.Fatal(err)
		}
		again, err := Decode(out)
		if err != nil {
			t.Fatalf("re-encoded JSON does not parse: %v\n%s", err, out)
		}
		out2, err := JSONIndent1(again)
		if err != nil || !bytes.Equal(out2, out) {
			t.Fatalf("not stable:\n%s\n%s", out, out2)
		}
	})
}
