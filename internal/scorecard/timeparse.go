package scorecard

import (
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	pv "github.com/MIERAI/security-platform/internal/pyvalue"
)

const day = 86400.0

// Date and time patterns of the contract (SPEC §6): a value with a "T" is read as its first 19 characters,
// %Y-%m-%dT%H:%M:%S, anything else as its first 10, %Y-%m-%d; both in UTC, case-insensitive, one-digit
// month/day/hour/minute/second allowed, seconds up to 61. Compiled once, never written.
var (
	dateOnly = regexp.MustCompile(`(?i)^(\d\d\d\d)-(1[0-2]|0[1-9]|[1-9])-(3[01]|[12]\d|0[1-9]|[1-9]| [1-9])`)
	dateTime = regexp.MustCompile(`(?i)^(\d\d\d\d)-(1[0-2]|0[1-9]|[1-9])-(3[01]|[12]\d|0[1-9]|[1-9]| [1-9])` +
		`T(2[0-3]|[0-1]\d|\d):([0-5]\d|\d):(6[0-1]|[0-5]\d|\d)`)
	durationText = regexp.MustCompile(`^` + ws + `*([0-9]+(?:\.[0-9]+)?)` + ws + `*([smhdw])` + ws + `*$`)
)

// ws is a white-space character (the Unicode spaces and the ASCII separators).
const ws = `[\t\n\v\f\r \x1c-\x1f\x85\p{Z}]`

// timestamp reads an ISO date or date-time (UTC) as epoch seconds; a malformed value is a ValueError.
func timestamp(v any) (float64, error) {
	s := pv.Str(v)
	text, re, format := firstRunes(s, 10), dateOnly, "%Y-%m-%d"
	if strings.Contains(s, "T") {
		text, re, format = firstRunes(s, 19), dateTime, "%Y-%m-%dT%H:%M:%S"
	}
	m := re.FindStringSubmatchIndex(text)
	if m == nil {
		return 0, pv.ValueError("time data " + pv.Repr(text) + " does not match format " + pv.Repr(format))
	}
	if m[1] != len(text) {
		return 0, pv.ValueError("unconverted data remains: " + text[m[1]:])
	}
	f := fields(text, m)
	if f[0] < 1 {
		return 0, pv.ValueError("year 0 is out of range")
	}
	if f[2] > daysIn(f[0], f[1]) {
		return 0, pv.ValueError("day is out of range for month")
	}
	t := time.Date(f[0], time.Month(f[1]), f[2], f[3], f[4], 0, 0, time.UTC)
	return float64(t.Unix() + int64(f[5])), nil
}

// fields returns year, month, day, hour, minute, second of a match (missing time fields are 0).
func fields(text string, m []int) [6]int {
	var f [6]int
	for i := range 6 {
		if 2*i+3 < len(m) && m[2*i+2] >= 0 {
			n, err := strconv.Atoi(strings.TrimSpace(text[m[2*i+2]:m[2*i+3]]))
			if err == nil { // always: the pattern matched digits only
				f[i] = n
			}
		}
	}
	return f
}

func daysIn(year, month int) int {
	return time.Date(year, time.Month(month)+1, 0, 0, 0, 0, 0, time.UTC).Day()
}

func firstRunes(s string, n int) string {
	i := 0
	for pos := range s {
		if i == n {
			return s[:pos]
		}
		i++
	}
	return s
}

// duration reads a duration: a number of seconds, or text such as "90d", "12h", "1.5w"; nil gives def.
func duration(v any, def float64) (float64, error) {
	if v == nil {
		return def, nil
	}
	if f, ok := pv.ToFloat64(v); ok {
		return f, nil
	}
	m := durationText.FindStringSubmatch(pv.Str(v))
	if m == nil {
		return 0, pv.ValueError("bad duration " + pv.Repr(v) + " (e.g. 90d, 12h)")
	}
	n, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, pv.ValueError("bad duration " + pv.Repr(v) + " (e.g. 90d, 12h)")
	}
	units := map[string]float64{"s": 1, "m": 60, "h": 3600, "d": day, "w": 7 * day}
	return n * units[m[2]], nil
}

// gmDate is the UTC calendar date (YYYY-MM-DD) of an epoch, rounded down to the second.
func gmDate(epoch float64) string {
	return time.Unix(int64(math.Floor(epoch)), 0).UTC().Format("2006-01-02")
}

// gmTime is the UTC time (YYYY-MM-DDTHH:MM:SSZ) of an epoch, rounded down to the second.
func gmTime(epoch float64) string {
	return time.Unix(int64(math.Floor(epoch)), 0).UTC().Format("2006-01-02T15:04:05Z")
}

// ageText prints an age in days ("2.3d") from one day on, else in hours ("1.0h").
func ageText(seconds float64) string {
	if seconds >= day {
		return pv.FormatFixed(seconds/day, 1) + "d"
	}
	return pv.FormatFixed(seconds/3600, 1) + "h"
}
