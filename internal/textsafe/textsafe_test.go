package textsafe

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestLine(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, in, want string
	}{
		{"plain", "v0.3.0", "v0.3.0"},
		{"spaces", "a b", "a b"},
		{"empty", "", ""},
		{"unicode", "réseau", "réseau"},
		{"escape sequence", "v1\x1b[2J", `"v1\x1b[2J"`},
		{"newline", "v1\nforged", `"v1\nforged"`},
		{"carriage return", "v1\rX", `"v1\rX"`},
		{"invalid utf8", "v\xff", `"v\xff"`},
		{"tab", "a\tb", `"a\tb"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := Line(tc.in); got != tc.want {
				t.Errorf("Line(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func FuzzLine(f *testing.F) {
	for _, s := range []string{"v0.3.0", "\x1b[31m", "a\nb", "\xff", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := Line(s)
		if !utf8.ValidString(out) {
			t.Fatalf("Line(%q) is not valid UTF-8", s)
		}
		if strings.ContainsAny(out, "\x1b\r\n\x00\x7f") {
			t.Fatalf("Line(%q) = %q still carries a control character", s, out)
		}
	})
}
