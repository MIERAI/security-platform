package cron

import "time"

// wall is a wall-clock minute in a location.
type wall struct {
	y      int
	m      time.Month
	d      int
	hh, mm int
}

func wallOf(t time.Time) wall {
	y, m, d := t.Date()
	return wall{y: y, m: m, d: d, hh: t.Hour(), mm: t.Minute()}
}

// Instant maps a wall-clock minute to its slot instant (epoch seconds) under the package's DST rules: the only
// occurrence; the first of two (fall back); the end of the gap when it does not exist (spring forward).
func Instant(loc *time.Location, wallClock time.Time) int64 {
	y, m, d := wallClock.Date()
	return instant(loc, wall{y: y, m: m, d: d, hh: wallClock.Hour(), mm: wallClock.Minute()})
}

func instant(loc *time.Location, wc wall) int64 {
	w := time.Date(wc.y, wc.m, wc.d, wc.hh, wc.mm, 0, 0, time.UTC).Unix() // the wall clock read as if it were UTC
	before := offsetAt(loc, w-86400)
	after := offsetAt(loc, w+86400)
	best, found := int64(0), false
	for _, off := range []int64{before, after} {
		i := w - off
		if offsetAt(loc, i) == off && (!found || i < best) {
			best, found = i, true
		}
	}
	if found {
		return best
	}
	// No offset gives this wall time: it lies in a gap. Read with the offset before the gap, it is an instant
	// after the transition; the zone period that contains it starts where the gap ends.
	start, _ := time.Unix(w-before, 0).In(loc).ZoneBounds()
	if start.IsZero() {
		return w - before
	}
	return start.Unix()
}

func offsetAt(loc *time.Location, epoch int64) int64 {
	_, off := time.Unix(epoch, 0).In(loc).Zone()
	return int64(off)
}

// Prev returns the latest slot at or before now (epoch seconds) in loc, or false when there is none within the
// horizon.
func (s *Schedule) Prev(now int64, loc *time.Location) (int64, bool) {
	start := wallOf(time.Unix(now, 0).Add(lookaround).In(loc))
	day := time.Date(start.y, start.m, start.d, 12, 0, 0, 0, time.UTC)
	for i := 0; i <= horizonDays+1; i++ {
		y, m, d := day.Date()
		if s.dayMatches(y, m, d) {
			maxH, maxM := 23, 59
			if i == 0 {
				maxH, maxM = start.hh, start.mm
			}
			if t, ok := s.prevInDay(loc, wall{y: y, m: m, d: d, hh: maxH, mm: maxM}, now); ok {
				return t, true
			}
		}
		day = day.AddDate(0, 0, -1)
	}
	return 0, false
}

// prevInDay scans one day's matching minutes downwards from limit and returns the first slot at or before now.
func (s *Schedule) prevInDay(loc *time.Location, limit wall, now int64) (int64, bool) {
	for h := limit.hh; h >= 0; h-- {
		if s.hour&(1<<uint(h)) == 0 {
			continue
		}
		top := 59
		if h == limit.hh {
			top = limit.mm
		}
		for mi := top; mi >= 0; mi-- {
			if s.minute&(1<<uint(mi)) == 0 {
				continue
			}
			if t := instant(loc, wall{y: limit.y, m: limit.m, d: limit.d, hh: h, mm: mi}); t <= now {
				return t, true
			}
		}
	}
	return 0, false
}

// Next returns the earliest slot after the minute that contains now, or false when there is none within the
// horizon.
func (s *Schedule) Next(now int64, loc *time.Location) (int64, bool) {
	ref := now - mod(now, 60)
	start := wallOf(time.Unix(ref, 0).Add(-lookaround).In(loc))
	day := time.Date(start.y, start.m, start.d, 12, 0, 0, 0, time.UTC)
	for i := 0; i <= horizonDays+1; i++ {
		y, m, d := day.Date()
		if s.dayMatches(y, m, d) {
			minH, minM := 0, 0
			if i == 0 {
				minH, minM = start.hh, start.mm
			}
			if t, ok := s.nextInDay(loc, wall{y: y, m: m, d: d, hh: minH, mm: minM}, ref); ok {
				return t, true
			}
		}
		day = day.AddDate(0, 0, 1)
	}
	return 0, false
}

// nextInDay scans one day's matching minutes upwards from limit and returns the first slot after ref.
func (s *Schedule) nextInDay(loc *time.Location, limit wall, ref int64) (int64, bool) {
	for h := limit.hh; h < 24; h++ {
		if s.hour&(1<<uint(h)) == 0 {
			continue
		}
		low := 0
		if h == limit.hh {
			low = limit.mm
		}
		for mi := low; mi < 60; mi++ {
			if s.minute&(1<<uint(mi)) == 0 {
				continue
			}
			if t := instant(loc, wall{y: limit.y, m: limit.m, d: limit.d, hh: h, mm: mi}); t > ref {
				return t, true
			}
		}
	}
	return 0, false
}

// Interval is the typical number of seconds between fires: the smallest gap among the next few (0 when the
// schedule fires fewer than twice within the horizon), as the reference computes it for staleness thresholds.
func (s *Schedule) Interval(now int64, loc *time.Location) int64 {
	t, ok := s.Next(now, loc)
	if !ok {
		return 0
	}
	best := int64(0)
	for range 6 {
		n, ok := s.Next(t, loc)
		if !ok {
			break
		}
		if gap := n - t; best == 0 || gap < best {
			best = gap
		}
		t = n
	}
	return best
}

func mod(a, b int64) int64 {
	r := a % b
	if r < 0 {
		r += b
	}
	return r
}
