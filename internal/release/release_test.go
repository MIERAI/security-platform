package release

import (
	"errors"
	"strings"
	"testing"
)

func TestIsProductTag(t *testing.T) {
	t.Parallel()
	tests := []struct {
		tag  string
		want bool
	}{
		{"v0.3.0", true},
		{"v10.20.30", true},
		{"v0.3.0-rc.1", true},
		{"v1.0.0-alpha-1.x.7", true},
		{"v99999999999999999999999.0.0", true},
		{"0.3.0", false},
		{"v0.3", false},
		{"v01.0.0", false},
		{"v0.3.0-", false},
		{"v0.3.0-rc..1", false},
		{"v0.3.0+build", false},
		{"collectors/host/v0.2.0", false},
		{"core/v0.8.0", false},
		{"v0.3.0\n", false},
		{"v١.0.0", false}, // ARABIC-INDIC DIGIT ONE: ASCII digits only
		{"", false},
	}
	for _, tc := range tests {
		t.Run(tc.tag, func(t *testing.T) {
			t.Parallel()
			if got := IsProductTag(tc.tag); got != tc.want {
				t.Errorf("IsProductTag(%q) = %v, want %v", tc.tag, got, tc.want)
			}
		})
	}
}

func TestCompare(t *testing.T) {
	t.Parallel()
	// ascending, per semantic version precedence (cli/release.py semver_key)
	order := []string{
		"v0.2.0", "v0.3.0-1", "v0.3.0-2", "v0.3.0-10", "v0.3.0-alpha", "v0.3.0-alpha.1", "v0.3.0-beta",
		"v0.3.0-rc.1", "v0.3.0-rc.2", "v0.3.0-rc.10", "v0.3.0", "v0.3.1", "v0.10.0", "v1.0.0",
		"v99999999999999999999999.0.0",
	}
	for i := range order {
		for j := range order {
			a, _ := Parse(order[i])
			b, _ := Parse(order[j])
			if got, want := Compare(a, b), compareInt(i, j); got != want {
				t.Errorf("Compare(%s, %s) = %d, want %d", order[i], order[j], got, want)
			}
		}
	}
}

func TestHighest(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		in     []string
		want   string
		wantOK bool
	}{
		{"product among components", []string{"core/v0.8.0", "v0.3.0", "runner/v0.9.0"}, "v0.3.0", true},
		{"release above its rc", []string{"v0.3.0-rc.1", "v0.3.0", "v0.3.0-rc.2"}, "v0.3.0", true},
		{"numeric not lexical", []string{"v0.9.0", "v0.10.0"}, "v0.10.0", true},
		{"components only", []string{"core/v0.8.0", "collectors/host/v0.2.0"}, "", false},
		{"none", nil, "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := Highest(tc.in)
			if got != tc.want || ok != tc.wantOK {
				t.Errorf("Highest(%q) = %q, %v; want %q, %v", tc.in, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestParseFile(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		in     string
		want   Installed
		wantOK bool
	}{
		{"installer output", "version=v0.3.0\ncommit=65cd3b0\n", Installed{"v0.3.0", "65cd3b0"}, true},
		{"crlf and spaces", "  version=v0.3.0  \r\ncommit=abc\r\n", Installed{"v0.3.0", "abc"}, true},
		{"lone carriage returns", "version=v1.0.0\rcommit=abc", Installed{"v1.0.0", "abc"}, true},
		{"last wins", "version=v0.1.0\nversion=v0.2.0\n", Installed{Version: "v0.2.0"}, true},
		{"value keeps =", "version=a=b\n", Installed{Version: "a=b"}, true},
		{"unknown keys ignored", "x=y\nversion=dev-v0.3.0-2-gabc\n", Installed{Version: "dev-v0.3.0-2-gabc"}, true},
		{"no version", "commit=abc\n", Installed{Commit: "abc"}, false},
		{"empty version", "version=\n", Installed{}, false},
		{"spaced key is another key", "version = v1\n", Installed{}, false},
		{"empty", "", Installed{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok, err := ParseFile(strings.NewReader(tc.in))
			if err != nil || got != tc.want || ok != tc.wantOK {
				t.Errorf("ParseFile(%q) = %+v, %v, %v; want %+v, %v, nil", tc.in, got, ok, err, tc.want, tc.wantOK)
			}
		})
	}
}

func TestParseFileTooLarge(t *testing.T) {
	t.Parallel()
	_, ok, err := ParseFile(strings.NewReader("version=v1.0.0\n" + strings.Repeat("x", MaxReleaseFile)))
	if ok || !errors.Is(err, ErrTooLarge) {
		t.Fatalf("ParseFile(oversized) = ok %v, err %v; want ErrTooLarge", ok, err)
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{"v0.3.0", "v0.3.0-rc.1", "core/v0.8.0", "v01.0.0", "v1.0.0-0.a.00"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		v, ok := Parse(s)
		if !ok {
			return
		}
		if v.Tag != s || Compare(v, v) != 0 {
			t.Fatalf("Parse(%q) = %+v: not reflexive", s, v)
		}
		if !strings.HasPrefix(s, "v") || strings.ContainsAny(s, "/+\n ") {
			t.Fatalf("Parse accepted %q", s)
		}
	})
}

func FuzzCompare(f *testing.F) {
	f.Add("v0.3.0", "v0.3.0-rc.1")
	f.Add("v1.0.0-1", "v1.0.0-a")
	f.Fuzz(func(t *testing.T, x, y string) {
		a, okA := Parse(x)
		b, okB := Parse(y)
		if !okA || !okB {
			return
		}
		if Compare(a, b) != -Compare(b, a) {
			t.Fatalf("Compare(%q, %q) is not antisymmetric", x, y)
		}
	})
}

func FuzzParseFile(f *testing.F) {
	for _, s := range []string{"version=v0.3.0\ncommit=abc\n", "version=\r\n", "\x00=\n", "=\n="} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		inst, ok, err := ParseFile(strings.NewReader(string(data)))
		if len(data) > MaxReleaseFile {
			if !errors.Is(err, ErrTooLarge) {
				t.Fatalf("oversized input: err %v", err)
			}
			return
		}
		if err != nil {
			t.Fatalf("ParseFile: %v", err)
		}
		if ok != (inst.Version != "") {
			t.Fatalf("ok %v with version %q", ok, inst.Version)
		}
		if strings.ContainsAny(inst.Version+inst.Commit, "\r\n") {
			t.Fatalf("a value spans lines: %+v", inst)
		}
	})
}
