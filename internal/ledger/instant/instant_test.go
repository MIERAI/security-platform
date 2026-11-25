package instant

import (
	"errors"
	"testing"
)

func TestParse(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want float64
		err  bool
	}{
		{"2026-11-01T08:00:00Z", 1793520000, false},
		{"2026-11-01T08:00:00", 1793520000, false},
		{"2026-11-01T08:00:00.987654Z", 1793520000, false},
		{"2026-11-01T09:00:00+01:00", 1793520000, false},
		{"2026-11-01T03:00:00-0500", 1793520000, false},
		{"2026-11-01T08:00:00+bogus", 1793520000, false},
		{"2026-11-01", 1793491200, false},
		{"2026-11-01 08:00:00+00:00", 1793491200, false}, // no "T": the date (as the reference)
		{"2026-03-29T00:30:00Z", 1774744200, false},      // a DST night in Europe: no effect, UTC only
		{"2026-13-01", 0, true},
		{"2026-11-01T25:00:00Z", 0, true},
		{"yesterday", 0, true},
		{"T", 0, true},
		{"", 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			got, err := Parse(tc.in)
			if tc.err {
				if !errors.Is(err, ErrInvalid) {
					t.Fatalf("Parse(%q) error = %v, want ErrInvalid", tc.in, err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("Parse(%q) = %v, %v; want %v", tc.in, got, err, tc.want)
			}
		})
	}
}

func TestISO(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   float64
		want string
	}{
		{1793520000, "2026-11-01T08:00:00Z"}, {1793520000.9, "2026-11-01T08:00:00Z"}, {-1.5, "1969-12-31T23:59:58Z"},
	}
	for _, tc := range tests {
		if got := ISO(tc.in); got != tc.want {
			t.Errorf("ISO(%v) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

// FuzzParse: Parse never panics, and what it accepts as a full RFC 3339 UTC timestamp round-trips through ISO.
func FuzzParse(f *testing.F) {
	for _, s := range []string{"2026-11-01T08:00:00Z", "2026-11-01", "2026-11-01T08:00:00.5+05:30", "0000-01-01T00:00:00-23:59"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		v, err := Parse(s)
		if err != nil {
			return
		}
		if len(s) == 20 && s[10] == 'T' && s[19] == 'Z' && ISO(v) != s {
			t.Fatalf("ISO(Parse(%q)) = %q", s, ISO(v))
		}
	})
}
