package identity

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
)

// The patterns of Python's time.strptime for "%Y-%m-%dT%H:%M:%S" and "%Y-%m-%d" (case-insensitive, whole string).
var (
	dateTimeRE = regexp.MustCompile(`(?i)^(\d{4})-(1[0-2]|0[1-9]|[1-9])-(3[01]|[12]\d|0[1-9]|[1-9]| [1-9])` +
		`T(2[0-3]|[0-1]\d|\d):([0-5]\d|\d):(6[0-1]|[0-5]\d|\d)$`)
	dateRE = regexp.MustCompile(`^(\d{4})-(1[0-2]|0[1-9]|[1-9])-(3[01]|[12]\d|0[1-9]|[1-9]| [1-9])$`)
)

// stamp is the collector's ts(): the first 19 characters of str(v) as an ISO date-time, else the first 10 as a
// date, read as UTC (the Python collector reads them as local time and subtracts the UTC offset; under TZ=UTC that is
// the same). ok is false when v is falsy or neither form parses. A value of exactly the epoch is 0, which the checks,
// like Python's, treat as absent.
func stamp(v pyjson.Value) (float64, bool) {
	if !truthy(v) {
		return 0, false
	}
	s := pyStr(v)
	if t, ok := parseStamp(dateTimeRE, cut(s, 19)); ok {
		return t, true
	}
	return parseStamp(dateRE, cut(s, 10))
}

func parseStamp(re *regexp.Regexp, s string) (float64, bool) {
	m := re.FindStringSubmatch(s)
	if m == nil {
		return 0, false
	}
	n := make([]int, 6)
	for i := 1; i < len(m); i++ {
		if m[i] == "" {
			continue
		}
		v, err := strconv.Atoi(trimSpace(m[i]))
		if err != nil {
			return 0, false
		}
		n[i-1] = v
	}
	year, month, day := n[0], time.Month(n[1]), n[2]
	if year < 1 {
		return 0, false // datetime.date(0, ...) is out of range
	}
	d := time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
	if d.Month() != month || d.Day() != day {
		return 0, false // "day is out of range for month"
	}
	return float64(d.Unix() + int64(n[3]*3600+n[4]*60+n[5])), true
}

func trimSpace(s string) string { return strings.TrimLeft(s, " ") }

// cut is s[:n] in characters.
func cut(s string, n int) string {
	i := 0
	for pos := range s {
		if i == n {
			return s[:pos]
		}
		i++
	}
	return s
}

// iso is the adapter's iso(): seconds since the epoch as RFC 3339 UTC; None for 0.
func iso(t float64) pyjson.Value {
	if t == 0 {
		return nil
	}
	return time.Unix(int64(t), 0).UTC().Format("2006-01-02T15:04:05Z")
}
