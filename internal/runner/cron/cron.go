// Package cron parses 5-field cron expressions (minute hour day-of-month month day-of-week) and finds their fire
// times in a time zone, as the runner contract specifies (contracts/runner/SPEC.md §3).
//
// Syntax (as the reference runner/cron.py): `*`, lists `a,b`, ranges `a-b`, steps `*/n`, `a-b/n` and `a/n` (= a to
// the field's maximum), day-of-week 0-7 (0 and 7 = Sunday). When both day-of-month and day-of-week are restricted
// (neither is `*`), either one matching is enough (Vixie cron).
//
// Fire times are local wall-clock times. Daylight saving time (contract §3.1):
//   - a wall-clock time that does not exist (spring forward) fires once, at the instant the gap ends;
//   - a wall-clock time that exists twice (fall back) fires once, at its first occurrence.
//
// So every matching wall-clock minute is exactly one slot, and slots never go backwards in time.
package cron

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// horizonDays bounds the search for a fire time, as the reference (a schedule that never fires has no slot).
const horizonDays = 400

// lookaround is how far beyond a reference instant the wall-clock search starts, so that a wall-clock time whose
// first occurrence precedes the instant (a repeated hour) is found. Larger than any daylight saving shift.
const lookaround = 3 * time.Hour

// ErrSyntax is the error class of every malformed expression.
var ErrSyntax = errors.New("bad cron expression")

type field struct {
	name   string
	lo, hi int
}

// fields returns the five fields in order. A fresh slice on every call: nothing can change it.
func fields() []field {
	return []field{{"minute", 0, 59}, {"hour", 0, 23}, {"day of month", 1, 31}, {"month", 1, 12}, {"day of week", 0, 7}}
}

// Schedule is a parsed expression. The zero value never fires.
type Schedule struct {
	expr   string
	minute uint64 // bit n = minute n
	hour   uint64
	dom    uint64 // bits 1-31
	month  uint64 // bits 1-12
	dow    uint64 // bits 0-6, Sunday = 0
	domAny bool
	dowAny bool
}

// String returns the expression as given.
func (s *Schedule) String() string { return s.expr }

// Parse parses a 5-field expression.
func Parse(expr string) (*Schedule, error) {
	parts := strings.Fields(expr)
	if len(parts) != len(fields()) {
		return nil, fmt.Errorf("%w: cron needs 5 fields: %q", ErrSyntax, expr)
	}
	sets := make([]uint64, len(parts))
	for i, f := range fields() {
		set, err := parseField(parts[i], f.lo, f.hi)
		if err != nil {
			return nil, fmt.Errorf("%w (%s field of %q)", err, f.name, expr)
		}
		sets[i] = set
	}
	dow := sets[4]
	if dow&(1<<7) != 0 {
		dow = dow&^(1<<7) | 1 // 7 = Sunday
	}
	return &Schedule{expr: expr, minute: sets[0], hour: sets[1], dom: sets[2], month: sets[3], dow: dow,
		domAny: parts[2] == "*", dowAny: parts[4] == "*"}, nil
}

// span is one part of a field: from a to b in steps.
type span struct{ a, b, step int }

// parseField parses one comma-separated field into a bit set.
func parseField(spec string, lo, hi int) (uint64, error) {
	var set uint64
	for _, part := range strings.Split(spec, ",") {
		sp, err := parsePart(part, lo, hi)
		if err != nil {
			return 0, err
		}
		for v := sp.a; v <= sp.b; v += sp.step {
			set |= 1 << uint(v)
		}
	}
	return set, nil
}

// parsePart parses `*`, `a`, `a-b`, each optionally followed by `/step`.
func parsePart(part string, lo, hi int) (span, error) {
	sp := span{step: 1}
	base, stepText, hasStep := strings.Cut(part, "/")
	if hasStep {
		n, err := number(stepText)
		if err != nil || n < 1 {
			return sp, fmt.Errorf("%w: bad step in %q", ErrSyntax, part)
		}
		sp.step = n
	}
	var err error
	sp.a, sp.b, err = bounds(base, lo, hi, hasStep)
	if err != nil {
		return sp, err
	}
	if sp.a < lo || sp.a > hi || sp.b < lo || sp.b > hi || sp.a > sp.b {
		return sp, fmt.Errorf("%w: %q out of range %d-%d", ErrSyntax, part, lo, hi)
	}
	return sp, nil
}

// bounds reads `*`, `a-b` or `a` (with a step, `a` alone runs to the field's maximum).
func bounds(base string, lo, hi int, hasStep bool) (from, to int, err error) {
	if base == "*" {
		return lo, hi, nil
	}
	if first, last, isRange := strings.Cut(base, "-"); isRange {
		if from, err = number(first); err != nil {
			return 0, 0, err
		}
		to, err = number(last)
		return from, to, err
	}
	from, err = number(base)
	if hasStep {
		return from, hi, err
	}
	return from, from, err
}

// number parses a plain decimal number (ASCII digits only: stricter than the reference's int()).
func number(s string) (int, error) {
	if s == "" || len(s) > 4 || strings.TrimLeft(s, "0123456789") != "" {
		return 0, fmt.Errorf("%w: not a number: %q", ErrSyntax, s)
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("%w: not a number: %q", ErrSyntax, s)
	}
	return n, nil
}

// dayMatches reports whether a calendar day matches the month, day-of-month and day-of-week fields.
func (s *Schedule) dayMatches(y int, m time.Month, d int) bool {
	if s.month&(1<<uint(m)) == 0 {
		return false
	}
	domOK := s.dom&(1<<uint(d)) != 0
	dowOK := s.dow&(1<<uint(time.Date(y, m, d, 12, 0, 0, 0, time.UTC).Weekday())) != 0
	if s.domAny || s.dowAny {
		return domOK && dowOK
	}
	return domOK || dowOK
}

// Matches reports whether the wall-clock minute of t (in t's location) matches the expression.
func (s *Schedule) Matches(t time.Time) bool {
	y, m, d := t.Date()
	return s.dayMatches(y, m, d) && s.hour&(1<<uint(t.Hour())) != 0 && s.minute&(1<<uint(t.Minute())) != 0
}
