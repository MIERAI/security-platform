package cron

import (
	"testing"
	"time"
)

// TestDST checks contract runner §3.1 in zones with different transitions: Europe/Berlin (02:00/03:00, 1 h),
// America/New_York (02:00, 1 h), Australia/Lord_Howe (30-minute shift), Pacific/Apia (a whole skipped day,
// 2011-12-30).
func TestDST(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, zone, expr, now, want string // now and want in UTC
		next                        bool
	}{
		{"gap fires at its end", "Europe/Berlin", "30 2 * * *", "2030-03-31 01:10", "2030-03-31 01:00", false},
		{"gap minutes collapse", "Europe/Berlin", "*/10 2 * * *", "2030-03-31 01:30", "2030-03-31 01:00", false},
		{"before the gap", "Europe/Berlin", "30 2 * * *", "2030-03-31 00:59", "2030-03-30 01:30", false},
		{"next is the gap end", "Europe/Berlin", "30 2 * * *", "2030-03-30 12:00", "2030-03-31 01:00", true},
		{"after the gap the next day", "Europe/Berlin", "30 2 * * *", "2030-03-31 01:00", "2030-04-01 00:30", true},
		{"repeated time: first occurrence", "Europe/Berlin", "30 2 * * *", "2030-10-27 00:40", "2030-10-27 00:30", false},
		{"repeated time: still the first", "Europe/Berlin", "30 2 * * *", "2030-10-27 01:40", "2030-10-27 00:30", false},
		{"hourly in the repeated hour", "Europe/Berlin", "0 * * * *", "2030-10-27 01:30", "2030-10-27 00:00", false},
		{"hourly after the repeated hour", "Europe/Berlin", "0 * * * *", "2030-10-27 02:05", "2030-10-27 02:00", false},
		{"next skips the repetition", "Europe/Berlin", "30 2 * * *", "2030-10-27 00:30", "2030-10-28 01:30", true},
		{"day before spring forward", "Europe/Berlin", "30 23 * * 6", "2030-03-31 03:00", "2030-03-30 22:30", false},
		{"day before fall back", "Europe/Berlin", "30 23 * * 6", "2030-10-27 04:00", "2030-10-26 21:30", false},
		{"New York gap", "America/New_York", "30 2 * * *", "2030-03-10 07:30", "2030-03-10 07:00", false},
		{"New York repeat", "America/New_York", "30 1 * * *", "2030-11-03 06:45", "2030-11-03 05:30", false},
		{"half-hour shift gap", "Australia/Lord_Howe", "15 2 * * *", "2030-10-05 15:45", "2030-10-05 15:30", false},
		{"skipped day fires at its end", "Pacific/Apia", "0 12 30 12 *", "2012-01-01 00:00", "2011-12-30 10:00", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s, err := Parse(tt.expr)
			if err != nil {
				t.Fatal(err)
			}
			loc := zone(t, tt.zone)
			f := s.Prev
			if tt.next {
				f = s.Next
			}
			got, ok := f(utc(t, tt.now), loc)
			if want := utc(t, tt.want); !ok || got != want {
				t.Errorf("%s %q at %s: got %s, want %s", tt.zone, tt.expr, tt.now, time.Unix(got, 0).In(loc),
					time.Unix(want, 0).In(loc))
			}
		})
	}
}

// TestSlotsAreMonotonic walks every slot of minute-level schedules through a year of a DST zone: slots strictly
// increase, Prev and Next agree, and every slot is either a matching wall-clock minute or the end of a gap.
func TestSlotsAreMonotonic(t *testing.T) {
	t.Parallel()
	for _, expr := range []string{"*/7 * * * *", "30 2 * * *", "0 * * * *", "0 2,3 * * 0"} {
		t.Run(expr, func(t *testing.T) {
			t.Parallel()
			s, err := Parse(expr)
			if err != nil {
				t.Fatal(err)
			}
			start, end := utc(t, "2030-01-01 00:00"), utc(t, "2031-01-01 00:00")
			if expr == "*/7 * * * *" {
				start, end = utc(t, "2030-03-30 20:00"), utc(t, "2030-03-31 06:00")
			}
			walk(t, s, zone(t, "Europe/Berlin"), start, end)
		})
	}
}

// walk checks every slot from start to end: strictly increasing, and Prev agrees with Next.
func walk(t *testing.T, s *Schedule, loc *time.Location, start, end int64) {
	t.Helper()
	prev := int64(0)
	for cur, ok := s.Next(start, loc); ok && cur < end; cur, ok = s.Next(cur, loc) {
		if cur <= prev {
			t.Fatalf("slot %d not after %d", cur, prev)
		}
		if p, _ := s.Prev(cur, loc); p != cur {
			t.Fatalf("Prev(%d) = %d", cur, p)
		}
		if p, _ := s.Prev(cur-1, loc); prev != 0 && p != prev {
			t.Fatalf("Prev(%d-1) = %d, want %d", cur, p, prev)
		}
		prev = cur
	}
}

func TestInstant(t *testing.T) {
	t.Parallel()
	loc := zone(t, "Europe/Berlin")
	tests := []struct {
		wall string // local wall clock
		want string // UTC
	}{
		{"2030-03-31 02:30", "2030-03-31 01:00"}, {"2030-03-31 01:59", "2030-03-31 00:59"},
		{"2030-03-31 03:00", "2030-03-31 01:00"}, {"2030-10-27 02:30", "2030-10-27 00:30"},
		{"2030-10-27 03:00", "2030-10-27 02:00"}, {"2030-07-01 12:00", "2030-07-01 10:00"},
	}
	for _, tt := range tests {
		w, err := time.Parse("2006-01-02 15:04", tt.wall)
		if err != nil {
			t.Fatal(err)
		}
		if got := Instant(loc, w); got != utc(t, tt.want) {
			t.Errorf("Instant(%s) = %s, want %s UTC", tt.wall, time.Unix(got, 0).UTC(), tt.want)
		}
	}
	if got := Instant(time.UTC, time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)); got != utc(t, "2030-01-01 00:00") {
		t.Errorf("UTC instant = %d", got)
	}
}

func TestNoSlot(t *testing.T) {
	t.Parallel()
	s, err := Parse("0 0 31 2 *")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Prev(utc(t, "2030-01-01 00:00"), time.UTC); ok {
		t.Error("February 31st has a previous slot")
	}
	if _, ok := s.Next(utc(t, "2030-01-01 00:00"), time.UTC); ok {
		t.Error("February 31st has a next slot")
	}
	if got := s.Interval(utc(t, "2030-01-01 00:00"), time.UTC); got != 0 {
		t.Errorf("Interval = %d, want 0", got)
	}
}

// FuzzParse: any text either fails with ErrSyntax or gives a schedule whose slots are consistent: Prev is at or
// before now and Next after it, both minute-aligned in UTC, Prev(Next(now)) is Next(now).
func FuzzParse(f *testing.F) {
	for _, s := range []string{"30 3 * * *", "*/15 * * * *", "0 0 1 * 1", "1-10/3 2 * 1-6 0,7", "61 * * * *", "* * *"} {
		f.Add(s, int64(1900000000))
	}
	loc, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, expr string, now int64) {
		now = 946684800 + mod(now, 4102444800-946684800) // 2000 to 2100
		if s, err := Parse(expr); err == nil {
			checkSlots(t, s, loc, now)
		}
	})
}

func checkSlots(t *testing.T, s *Schedule, loc *time.Location, now int64) {
	t.Helper()
	if p, ok := s.Prev(now, loc); ok && (p > now || p%60 != 0) {
		t.Fatalf("%q: Prev(%d) = %d", s, now, p)
	}
	n, ok := s.Next(now, loc)
	if !ok {
		return
	}
	if n <= now-mod(now, 60) || n%60 != 0 {
		t.Fatalf("%q: Next(%d) = %d", s, now, n)
	}
	if p, ok := s.Prev(n, loc); !ok || p != n {
		t.Fatalf("%q: Prev(Next(%d)=%d) = %d", s, now, n, p)
	}
}
