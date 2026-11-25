package pyvalue

import (
	"encoding/json"
	"math"
	"os"
	"strconv"
	"testing"
)

// golden.json is written by testdata/gen_golden.py from the reference implementation: number formatting,
// rounding, sums and YAML scalar types, so that the two implementations agree bit for bit.
type golden struct {
	Floats []struct {
		Bits, Repr, G, F1, Round1 string
	}
	Sums []struct {
		Values []struct {
			Int   *int64
			Float *string
		}
		Int    bool
		Result string
	}
	YAML []struct {
		Text  string
		Error bool
		Want  struct{ Type, Str string }
	}
}

func loadGolden(t *testing.T) golden {
	t.Helper()
	data, err := os.ReadFile("testdata/golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var g golden
	if err := json.Unmarshal(data, &g); err != nil {
		t.Fatal(err)
	}
	return g
}

func fromBits(t *testing.T, s string) float64 {
	t.Helper()
	b, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return math.Float64frombits(b)
}

func TestGoldenFloats(t *testing.T) {
	t.Parallel()
	for _, c := range loadGolden(t).Floats {
		f := fromBits(t, c.Bits)
		if got := FloatRepr(f); got != c.Repr {
			t.Errorf("FloatRepr(%v) = %q, want %q", f, got, c.Repr)
		}
		if got := FormatG(f); got != c.G {
			t.Errorf("FormatG(%v) = %q, want %q", f, got, c.G)
		}
		if got := FormatFixed(f, 1); got != c.F1 {
			t.Errorf("FormatFixed(%v, 1) = %q, want %q", f, got, c.F1)
		}
		want := fromBits(t, c.Round1)
		if got := Round(f, 1); math.Float64bits(got) != math.Float64bits(want) && !(math.IsNaN(got) && math.IsNaN(want)) {
			t.Errorf("Round(%v, 1) = %v, want %v", f, got, want)
		}
	}
}

func TestGoldenSums(t *testing.T) {
	t.Parallel()
	for i, c := range loadGolden(t).Sums {
		vals := make([]any, len(c.Values))
		for j, v := range c.Values {
			vals[j] = goldenNumber(t, v.Int, v.Float)
		}
		got, err := Sum(vals)
		if err != nil {
			t.Fatal(err)
		}
		switch g := got.(type) {
		case int64:
			if !c.Int || strconv.FormatInt(g, 10) != c.Result {
				t.Errorf("sum %d: got int %d, want %s (int=%v)", i, g, c.Result, c.Int)
			}
		case float64:
			if c.Int || math.Float64bits(g) != math.Float64bits(fromBits(t, c.Result)) {
				t.Errorf("sum %d of %v: got %v, want bits %s", i, vals, g, c.Result)
			}
		}
	}
}

func goldenNumber(t *testing.T, i *int64, f *string) any {
	t.Helper()
	if i != nil {
		return *i
	}
	return fromBits(t, *f)
}

func TestGoldenYAMLScalars(t *testing.T) {
	t.Parallel()
	for _, c := range loadGolden(t).YAML {
		v, err := DecodeYAML([]byte("k: " + c.Text + "\n"))
		if c.Error {
			if err == nil {
				t.Errorf("%q: want an error", c.Text)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", c.Text, err)
			continue
		}
		got := mustMap(t, v).Value("k")
		if TypeName(got) != c.Want.Type {
			t.Errorf("%q: type %s, want %s", c.Text, TypeName(got), c.Want.Type)
		}
		if s := Str(got); s != c.Want.Str {
			t.Errorf("%q: %q, want %q", c.Text, s, c.Want.Str)
		}
	}
}
