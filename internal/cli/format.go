package cli

import (
	"errors"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/MIERAI/security-platform/internal/pyvalue"
	"github.com/MIERAI/security-platform/internal/textsafe"
)

// severities in order, worst first.
func severities() []string { return []string{"critical", "high", "medium", "low", "info"} }

// sevRank is a severity's position (worst = 0); unknown severities sort after info.
func sevRank(s string) int {
	for i, x := range severities() {
		if x == s {
			return i
		}
	}
	return len(severities())
}

// paint wraps s in an ANSI color when the output is a terminal (cli/sp.py c()).
func (s *session) paint(code, text string) string {
	if !s.env.Color {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

func (s *session) sevColor(sev string) string {
	codes := map[string]string{"critical": "1;31", "high": "31", "medium": "33", "low": "36"}
	code, ok := codes[sev]
	if !ok {
		code = "0"
	}
	return s.paint(code, sev)
}

// ljust pads s with spaces to n characters (code points, as Python's format width).
func ljust(s string, n int) string {
	if k := utf8.RuneCountInString(s); k < n {
		return s + strings.Repeat(" ", n-k)
	}
	return s
}

// rjust pads s on the left to n characters.
func rjust(s string, n int) string {
	if k := utf8.RuneCountInString(s); k < n {
		return strings.Repeat(" ", n-k) + s
	}
	return s
}

// head is s[:n] in code points (Python slicing).
func head(s string, n int) string {
	i := 0
	for pos := range s {
		if i == n {
			return s[:pos]
		}
		i++
	}
	return s
}

// safe makes text read from files safe for the terminal (textsafe.Line); ordinary text is unchanged.
func safe(s string) string { return textsafe.Line(s) }

// str is Python's str() of a value; text from files is made terminal-safe.
func str(v any) string { return safe(pyvalue.Str(v)) }

// field returns a mapping's value, nil when the mapping is nil or the key absent.
func field(m *pyvalue.Map, key string) any {
	if m == nil {
		return nil
	}
	return m.Value(key)
}

// get returns a mapping's value as text ("" when absent or null: the reference would fail on a missing field).
func get(m *pyvalue.Map, key string) string {
	v := field(m, key)
	if v == nil {
		return ""
	}
	return pyvalue.Str(v)
}

// errTime is returned for a timestamp that is not YYYY-MM-DD[THH:MM:SS...].
var errTime = errors.New("not a timestamp")

// ts parses the UTC timestamps of the ledger and tracker ("2026-11-01T08:00:00Z", or a date) into epoch seconds.
// The reference parses them as local time and corrects by the standard offset, which is an hour off under daylight
// saving time (CLI-D3); this is the target: the instant the text names.
func ts(v any) (float64, error) {
	s := pyvalue.Str(v)
	layout, n := "2006-01-02", 10
	if strings.Contains(s, "T") {
		layout, n = "2006-01-02T15:04:05", 19
	}
	if len(s) < n {
		return 0, errTime
	}
	t, err := time.ParseInLocation(layout, s[:n], time.UTC)
	if err != nil {
		return 0, errTime
	}
	return float64(t.Unix()), nil
}

// ago is "<n><unit> ago" for the time since t (cli/sp.py ago()).
func ago(t, now float64) string {
	d := now - t
	for _, u := range []struct {
		name string
		n    float64
	}{{"d", 86400}, {"h", 3600}, {"m", 60}} {
		if d >= u.n {
			return pyvalue.Str(int64(math.Floor(d/u.n))) + u.name + " ago"
		}
	}
	return "just now"
}

func epochNow(t time.Time) float64 {
	return float64(t.UnixNano()) / 1e9
}

// localDate is the local calendar date of an epoch instant.
func (s *session) localDate(epoch float64) string {
	return time.Unix(int64(math.Floor(epoch)), 0).In(s.env.Loc).Format("2006-01-02")
}

// number returns a value as a float when it is a number (bools count, as in Python).
func number(v any) (float64, bool) {
	return pyvalue.ToFloat64(v)
}

// isZero is Python's `v == 0` (0, 0.0 and False are equal to 0).
func isZero(v any) bool {
	f, ok := number(v)
	return ok && f == 0
}
