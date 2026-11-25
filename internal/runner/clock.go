//go:build unix

package runner

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/textsafe"
)

// Clock is the runner's one clock (contract §1, RUNNER-D1): with --now every time the runner records or
// compares starts at that instant and advances with the real elapsed time; without it, the wall clock.
type Clock struct {
	fake  bool
	base  float64   // --now
	start time.Time // when the process started (monotonic)
	wall  func() time.Time
}

// NewClock returns a clock; now <= 0 means the wall clock.
func NewClock(now float64, wall func() time.Time) *Clock {
	return &Clock{fake: now > 0, base: now, start: wall(), wall: wall}
}

// Now is the current time in epoch seconds.
func (c *Clock) Now() float64 {
	if c.fake {
		return c.base + c.wall().Sub(c.start).Seconds()
	}
	return float64(c.wall().UnixNano()) / 1e9
}

// Decision is the time schedule decisions use: --now itself when given (every job of a tick is judged at the
// same instant, as the reference does), else the wall clock at the moment of the decision.
func (c *Clock) Decision() float64 {
	if c.fake {
		return c.base
	}
	return c.Now()
}

// Fake reports whether --now was given.
func (c *Clock) Fake() bool { return c.fake }

// Time is Now as a time.Time in loc.
func (c *Clock) Time(loc *time.Location) time.Time {
	n := c.Now()
	sec := int64(n)
	return time.Unix(sec, int64((n-float64(sec))*1e9)).In(loc)
}

// Logger writes `<local ISO 8601 time with offset> runner: <message>` lines (contract §1). Messages are made
// safe for a terminal: text from jobs can never forge log lines.
type Logger struct {
	w     io.Writer
	clock *Clock
	loc   *time.Location
}

// Printf logs one line. A failed write to the log cannot be reported anywhere else.
func (l *Logger) Printf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	ts := l.clock.Time(l.loc).Format("2006-01-02T15:04:05-0700")
	_, _ = fmt.Fprintf(l.w, "%s runner: %s\n", ts, textsafe.Line(msg))
}

// truncate keeps the first n characters (Python's s[:n]).
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// tail keeps the last n characters of s with surrounding white space removed (Python's s.strip()[-n:]).
func tail(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) <= n {
		return string(r)
	}
	return string(r[len(r)-n:])
}
