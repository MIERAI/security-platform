package cron

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
	_ "time/tzdata" // the zones below on every system, Windows included
)

func utc(t *testing.T, s string) int64 {
	t.Helper()
	v, err := time.Parse("2006-01-02 15:04", s)
	if err != nil {
		t.Fatal(err)
	}
	return v.Unix()
}

func zone(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

func TestParse(t *testing.T) {
	t.Parallel()
	tests := []struct {
		expr string
		ok   bool
	}{
		{"30 3 * * *", true}, {"*/15 * * * *", true}, {"1-10/3 * * * *", true}, {"5/20 * * * *", true},
		{"0 0 * * 7", true}, {"0 0 1,15 * 1-5", true}, {"  0   0  *  *  *  ", true}, {"07 03 * * *", true},
		{"* * *", false}, {"61 * * * *", false}, {"*/0 * * * *", false}, {"* * * * * *", false}, {"", false},
		{"1,,2 * * * *", false}, {"/5 * * * *", false}, {"*-5 * * * *", false}, {"5-1 * * * *", false},
		{"0 24 * * *", false}, {"0 0 0 * *", false}, {"0 0 * 13 *", false}, {"0 0 * * 8", false},
		{"-1 * * * *", false}, {"+1 * * * *", false}, {"1/-2 * * * *", false}, {"99999 * * * *", false},
	}
	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			t.Parallel()
			s, err := Parse(tt.expr)
			if (err == nil) != tt.ok {
				t.Fatalf("Parse(%q) error = %v, want ok=%v", tt.expr, err, tt.ok)
			}
			if err != nil && !errors.Is(err, ErrSyntax) {
				t.Errorf("error %v is not ErrSyntax", err)
			}
			if err == nil && s.String() != tt.expr {
				t.Errorf("String() = %q", s.String())
			}
		})
	}
}

func TestFieldSemantics(t *testing.T) {
	t.Parallel()
	got, err := parseField("1-10/3", 0, 59)
	if err != nil || got != 1<<1|1<<4|1<<7|1<<10 {
		t.Fatalf("1-10/3 = %b, %v", got, err)
	}
	if got, _ := parseField("50/5", 0, 59); got != 1<<50|1<<55 {
		t.Errorf("50/5 = %b (a/n runs to the maximum)", got)
	}
	s, err := Parse("0 0 1 * 1") // day-of-month OR day-of-week when both are restricted
	if err != nil {
		t.Fatal(err)
	}
	for _, ts := range []string{"2026-01-05 00:00", "2026-02-01 00:00"} {
		if !s.Matches(time.Unix(utc(t, ts), 0).UTC()) {
			t.Errorf("%s should match %q", ts, s)
		}
	}
	if s.Matches(time.Unix(utc(t, "2026-01-06 00:00"), 0).UTC()) {
		t.Error("a Tuesday that is not the 1st must not match")
	}
}

// TestUnitCasesOfTheReference repeats tests/test_runner.py's cron cases.
func TestUnitCasesOfTheReference(t *testing.T) {
	t.Parallel()
	tests := []struct {
		expr, now, want string
		next            bool
	}{
		{"30 3 * * *", "2026-01-05 03:29", "2026-01-04 03:30", false},
		{"30 3 * * *", "2026-01-05 03:30", "2026-01-05 03:30", false},
		{"30 3 * * *", "2026-01-05 03:30", "2026-01-06 03:30", true},
		{"0 9 * * 1", "2026-01-11 12:00", "2026-01-05 09:00", false},
		{"0 9 * * 7", "2026-01-11 12:00", "2026-01-11 09:00", false},
	}
	for _, tt := range tests {
		t.Run(tt.expr+"@"+tt.now, func(t *testing.T) {
			t.Parallel()
			s, err := Parse(tt.expr)
			if err != nil {
				t.Fatal(err)
			}
			f := s.Prev
			if tt.next {
				f = s.Next
			}
			if got, ok := f(utc(t, tt.now), time.UTC); !ok || got != utc(t, tt.want) {
				t.Errorf("got %v (%v), want %s", time.Unix(got, 0).UTC(), ok, tt.want)
			}
		})
	}
	for expr, want := range map[string]int64{"30 3 * * *": 86400, "*/15 * * * *": 900} {
		s, _ := Parse(expr)
		if got := s.Interval(utc(t, "2026-01-05 00:00"), time.UTC); got != want {
			t.Errorf("Interval(%q) = %d, want %d", expr, got, want)
		}
	}
}

type reference struct {
	Cron []struct {
		Expr     string `json:"expr"`
		Now      int64  `json:"now"`
		Prev     *int64 `json:"prev"`
		Next     *int64 `json:"next"`
		Interval int64  `json:"interval"`
	} `json:"cron"`
}

// TestMatchesReferenceOutsideDST compares with what runner/cron.py computes (testdata/gen_reference.py) for 216
// random (expression, time) pairs in UTC.
func TestMatchesReferenceOutsideDST(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "reference.json"))
	if err != nil {
		t.Fatal(err)
	}
	var ref reference
	if err := json.Unmarshal(data, &ref); err != nil {
		t.Fatal(err)
	}
	for _, c := range ref.Cron {
		s, err := Parse(c.Expr)
		if err != nil {
			t.Fatalf("%q: %v", c.Expr, err)
		}
		prev, okP := s.Prev(c.Now, time.UTC)
		next, okN := s.Next(c.Now, time.UTC)
		if !same(prev, okP, c.Prev) || !same(next, okN, c.Next) || s.Interval(c.Now, time.UTC) != c.Interval {
			t.Errorf("%q at %d: prev %d/%v next %d/%v interval %d; reference %v %v %d", c.Expr, c.Now, prev, okP,
				next, okN, s.Interval(c.Now, time.UTC), deref(c.Prev), deref(c.Next), c.Interval)
		}
	}
}

func same(got int64, ok bool, want *int64) bool {
	if want == nil {
		return !ok
	}
	return ok && got == *want
}

func deref(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}
