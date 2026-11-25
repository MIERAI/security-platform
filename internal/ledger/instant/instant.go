// Package instant converts the timestamps of the contracts to epoch seconds and back, on UTC instants only
// (LEDGER-D4: the reference parses local time and corrects by the standard offset, which is off by an hour
// across a daylight saving change).
//
// Accepted, as the reference accepts them: "YYYY-MM-DDTHH:MM:SS" followed by optional fractional seconds
// (ignored: whole seconds, as the reference) and an optional zone ("Z" or ±HH:MM / ±HHMM, applied); or a text
// without "T" whose first ten characters are a date "YYYY-MM-DD" (UTC midnight). Anything after these parts
// is ignored, as the reference ignores it.
package instant

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// ErrInvalid is returned for a text that is not a timestamp of the accepted forms.
var ErrInvalid = errors.New("not a timestamp")

const (
	dateLayout     = "2006-01-02"
	dateTimeLayout = "2006-01-02T15:04:05"
)

// Parse returns the epoch seconds of s.
func Parse(s string) (float64, error) {
	if !strings.Contains(s, "T") {
		if len(s) < len(dateLayout) {
			return 0, fmt.Errorf("%w: %q", ErrInvalid, s)
		}
		d, err := time.Parse(dateLayout, s[:len(dateLayout)])
		if err != nil {
			return 0, fmt.Errorf("%w: %q", ErrInvalid, s)
		}
		return float64(d.Unix()), nil
	}
	if len(s) < len(dateTimeLayout) {
		return 0, fmt.Errorf("%w: %q", ErrInvalid, s)
	}
	t, err := time.Parse(dateTimeLayout, s[:len(dateTimeLayout)])
	if err != nil {
		return 0, fmt.Errorf("%w: %q", ErrInvalid, s)
	}
	return float64(t.Unix() - zoneOffset(s[len(dateTimeLayout):])), nil
}

// zoneOffset reads the zone after the seconds (fraction skipped): seconds east of UTC, 0 when absent or not a
// well-formed offset.
func zoneOffset(rest string) int64 {
	rest = skipFraction(rest)
	if len(rest) < 5 || (rest[0] != '+' && rest[0] != '-') {
		return 0
	}
	hhmm := strings.Replace(rest[1:], ":", "", 1)
	if len(hhmm) < 4 {
		return 0
	}
	h, errH := strconv.Atoi(hhmm[:2])
	m, errM := strconv.Atoi(hhmm[2:4])
	if errH != nil || errM != nil || h > 23 || m > 59 || h < 0 || m < 0 {
		return 0
	}
	off := int64(h*3600 + m*60)
	if rest[0] == '-' {
		return -off
	}
	return off
}

func skipFraction(rest string) string {
	if !strings.HasPrefix(rest, ".") {
		return rest
	}
	i := 1
	for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
		i++
	}
	return rest[i:]
}

// ISO is time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t)): whole seconds, rounded down.
func ISO(t float64) string {
	return time.Unix(int64(math.Floor(t)), 0).UTC().Format("2006-01-02T15:04:05Z")
}
