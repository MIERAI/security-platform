package pyvalue

import (
	"errors"
	"math"
	"strings"
	"testing"
)

func TestDecodeJSONKeepsOrderAndTypes(t *testing.T) {
	t.Parallel()
	v, err := DecodeJSON([]byte(`{"b": 1, "a": [1.0, 2, "x", null, true], "b": 3, "c": 1e400}`))
	if err != nil {
		t.Fatal(err)
	}
	m := mustMap(t, v)
	if got := strings.Join(m.Keys(), ","); got != "b,a,c" {
		t.Errorf("keys %s, want b,a,c (last duplicate wins at the first position)", got)
	}
	if m.Value("b") != int64(3) {
		t.Errorf("b = %#v", m.Value("b"))
	}
	if l, ok := m.Value("a").([]any); !ok || l[0] != 1.0 || l[1] != int64(2) {
		t.Errorf("a = %#v", m.Value("a"))
	}
	if c, ok := m.Value("c").(float64); !ok || !math.IsInf(c, 1) {
		t.Errorf("c = %#v, want +Inf", m.Value("c"))
	}
}

func mustMap(t *testing.T, v any) *Map {
	t.Helper()
	m, ok := v.(*Map)
	if !ok {
		t.Fatalf("not a mapping: %#v", v)
	}
	return m
}

func TestDecodeJSONRejects(t *testing.T) {
	t.Parallel()
	tests := []struct{ name, in string }{
		{"trailing data", `{} {}`},
		{"not utf-8", "{\"a\": \"\xff\"}"},
		{"huge integer", `{"a": 99999999999999999999}`},
		{"truncated", `{"a": [1, 2`},
		{"nested too deeply", strings.Repeat("[", 600) + strings.Repeat("]", 600)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := DecodeJSON([]byte(tc.in)); !errors.Is(err, ErrDocument) {
				t.Errorf("err = %v, want ErrDocument", err)
			}
		})
	}
}

func TestEncodeJSON(t *testing.T) {
	t.Parallel()
	m := NewMap()
	m.Set("z", []any{})
	m.Set("a", []any{int64(1), 2.5, 100.0, "é\"\n\x01", nil, true})
	m.Set("m", NewMap())
	tests := []struct {
		ascii bool
		want  string
	}{
		{false, "{\n \"a\": [\n  1,\n  2.5,\n  100.0,\n  \"é\\\"\\n\\u0001\",\n  null,\n  true\n ],\n \"m\": {},\n \"z\": []\n}"},
		{true, "{\n \"a\": [\n  1,\n  2.5,\n  100.0,\n  \"\\u00e9\\\"\\n\\u0001\",\n  null,\n  true\n ],\n \"m\": {},\n \"z\": []\n}"},
	}
	for _, tc := range tests {
		got, err := EncodeJSON(m, tc.ascii)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != tc.want {
			t.Errorf("ascii=%v:\n%s\nwant\n%s", tc.ascii, got, tc.want)
		}
	}
	if _, err := EncodeJSON(Date{2030, 1, 1}, false); !errors.Is(err, ErrDocument) {
		t.Errorf("a date must not be written as JSON: %v", err)
	}
}

func TestEncodeJSONAstral(t *testing.T) {
	t.Parallel()
	got, err := EncodeJSON("\U0001F600", true)
	if err != nil || string(got) != `"\ud83d\ude00"` {
		t.Errorf("got %s %v", got, err)
	}
}

func TestDecodeYAML(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, in, want string
	}{
		{"empty", "", "None"},
		{"comment only", "# nothing\n", "None"},
		{"order kept", "b: 1\na: 2\n", "{'b': 1, 'a': 2}"},
		{"duplicate key", "a: 1\nb: 2\na: 3\n", "{'a': 3, 'b': 2}"},
		{"quoted stays text", "a: 'yes'\nb: \"1.5\"\n", "{'a': 'yes', 'b': '1.5'}"},
		{"explicit tag", "a: !!str 12\nb: !!int '7'\n", "{'a': '12', 'b': 7}"},
		{"alias", "x: &v [1, 2]\ny: *v\n", "{'x': [1, 2], 'y': [1, 2]}"},
		{"merge", "base: &b {a: 1, b: 2}\nm:\n  <<: *b\n  b: 3\n", "{'base': {'a': 1, 'b': 2}, 'm': {'a': 1, 'b': 3}}"},
		{"merge list", "x: &x {a: 1}\ny: &y {a: 2, c: 3}\nm: {<<: [*x, *y]}\n", "{'x': {'a': 1}, 'y': {'a': 2, 'c': 3}, 'm': {'a': 1, 'c': 3}}"},
		{"bool key", "on: 1\n", "{'True': 1}"},
		{"dates", "d: 2030-01-31\nt: 2030-01-31T10:00:00Z\n", "{'d': datetime.date(2030, 1, 31), 't': datetime.datetime('2030-01-31 10:00:00+00:00')}"},
		{"bom", "\ufeffa: 1\n", "{'a': 1}"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v, err := DecodeYAML([]byte(tc.in))
			if err != nil {
				t.Fatal(err)
			}
			if got := Repr(v); got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestDecodeYAMLRejects(t *testing.T) {
	t.Parallel()
	laughs := "a: &a [x, x, x, x, x, x, x, x, x, x]\n"
	prev := "a"
	for i := range 8 {
		n := string(rune('b' + i))
		laughs += n + ": &" + n + " [*" + prev + ", *" + prev + ", *" + prev + ", *" + prev + ", *" + prev + ", *" + prev + ", *" + prev + ", *" + prev + "]\n"
		prev = n
	}
	tests := []struct{ name, in string }{
		{"two documents", "a: 1\n---\nb: 2\n"},
		{"unknown tag", "a: !!python/object:os.system x\n"},
		{"bad date", "a: 2030-02-30\n"},
		{"billion laughs", laughs},
		{"unhashable key", "? [1, 2]\n: x\n"},
		{"value tag", "a: =\n"},
		{"syntax", "a: [1, 2\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := DecodeYAML([]byte(tc.in)); !errors.Is(err, ErrDocument) {
				t.Errorf("err = %v, want ErrDocument", err)
			}
		})
	}
}

func TestOps(t *testing.T) {
	t.Parallel()
	l := []any{"a", int64(1)}
	tests := []struct {
		name string
		got  any
		want any
	}{
		{"truthy empty", Truthy(""), false},
		{"truthy nan", Truthy(math.NaN()), true},
		{"equal int float", Equal(int64(1), 1.0), true},
		{"equal bool int", Equal(true, int64(1)), true},
		{"equal str int", Equal("1", int64(1)), false},
		{"equal lists", Equal(l, []any{"a", 1.0}), true},
		{"str none", Str(nil), "None"},
		{"repr quote", Repr("it's"), `"it's"`},
		{"repr both quotes", Repr(`'"`), `'\'"'`},
		{"repr control", Repr("a\tb\x01é"), `'a\tb\x01é'`},
		{"repr list", Repr([]any{"a", 1.5, nil}), "['a', 1.5, None]"},
	}
	for _, tc := range tests {
		if tc.got != tc.want {
			t.Errorf("%s: got %#v, want %#v", tc.name, tc.got, tc.want)
		}
	}
}

func TestInAndIter(t *testing.T) {
	t.Parallel()
	m := NewMap()
	m.Set("k", 1)
	tests := []struct {
		name      string
		x, c      any
		want, err bool
	}{
		{"substring", "pen", "open", true, false},
		{"list element", int64(1), []any{1.0}, true, false},
		{"map key", "k", m, true, false},
		{"int in string", int64(1), "1", false, true},
		{"in none", "a", nil, false, true},
		{"unhashable in map", []any{}, m, false, true},
	}
	for _, tc := range tests {
		got, err := In(tc.x, tc.c)
		if got != tc.want || (err != nil) != tc.err {
			t.Errorf("%s: got %v %v", tc.name, got, err)
		}
	}
	if items, err := Iter("ab"); err != nil || len(items) != 2 {
		t.Errorf("Iter(string) = %v %v", items, err)
	}
	if _, err := Iter(int64(1)); err == nil {
		t.Error("Iter(int) must fail")
	}
}

func TestConversions(t *testing.T) {
	t.Parallel()
	floats := []struct {
		in   any
		want float64
		err  bool
	}{
		{" 1.5 ", 1.5, false}, {"1_000", 1000, false}, {"inf", math.Inf(1), false}, {"-Infinity", math.Inf(-1), false},
		{"1e3", 1000, false}, {"0x10", 0, true}, {"_1", 0, true}, {"", 0, true}, {nil, 0, true}, {true, 1, false},
	}
	for _, tc := range floats {
		got, err := ToFloat(tc.in)
		if (err != nil) != tc.err || (!tc.err && got != tc.want) {
			t.Errorf("ToFloat(%#v) = %v, %v", tc.in, got, err)
		}
	}
	ints := []struct {
		in   any
		want int64
		err  bool
	}{
		{" -12 ", -12, false}, {"1_0", 10, false}, {2.9, 2, false}, {-2.9, -2, false}, {"2.5", 0, true},
		{math.NaN(), 0, true}, {math.Inf(1), 0, true}, {"--1", 0, true}, {nil, 0, true},
	}
	for _, tc := range ints {
		got, err := ToInt(tc.in)
		if (err != nil) != tc.err || (!tc.err && got != tc.want) {
			t.Errorf("ToInt(%#v) = %v, %v", tc.in, got, err)
		}
	}
	if n, err := ParseInt("0o700", 8); err != nil || n != 0o700 {
		t.Errorf("ParseInt(0o700, 8) = %v %v", n, err)
	}
}
