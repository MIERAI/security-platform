package events

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// Time formats the reference reads. Never written after initialisation.
var (
	// datetime.fromisoformat (Python 3.12), the extended forms: date, one separator character, time with optional
	// minutes, seconds and fraction (any number of digits, "." or ","), offset Z or +HH[[:]MM[[:]SS[.f]]]
	isoForm = regexp.MustCompile(`^(\d{4})-(\d\d)-(\d\d)(?:.(\d\d)(?::(\d\d)(?::(\d\d)(?:[.,](\d+))?)?)?` +
		`(Z|[+-]\d\d(?::?\d\d(?::?\d\d(?:\.\d+)?)?)?)?)?$`)
	// time.strptime(s, "%Y-%m-%d %H:%M:%S.%f%z")
	macForm = regexp.MustCompile(`^(\d{4})-(1[0-2]|0[1-9]|[1-9])-(3[01]|[12]\d|0[1-9]|[1-9]| [1-9]) (2[0-3]|[01]\d|\d):` +
		`([0-5]\d|\d):(6[01]|[0-5]\d|\d)\.(\d{1,6})(Z|[+-]\d\d:?[0-5]\d(?::?[0-5]\d(?:\.\d{1,6})?)?)$`)
	tzForm    = regexp.MustCompile(`^([+-])(\d\d):?(\d\d)$`)
	offsetRx  = regexp.MustCompile(`^([+-])(\d\d)(?::?(\d\d)(?::?(\d\d)(?:\.(\d+))?)?)?$`)
	bsdFields = regexp.MustCompile(`^([A-Z][a-z]{2}) (\d{1,2}) (\d\d):(\d\d):(\d\d)$`)
)

// fixedZone is a datetime.timezone: an offset in seconds (and microseconds, which Python allows).
type fixedZone struct{ sec, usec int64 }

// parseTZ is ship.py parse_tz: "" means none (local time).
func parseTZ(s string) (*fixedZone, error) {
	if s == "" {
		return nil, nil //nolint:nilnil // no offset configured: local time, as the reference
	}
	m := tzForm.FindStringSubmatch(s)
	if m == nil {
		return nil, pyErr("ValueError", fmt.Sprintf("utc_offset %s: expected +HH:MM", pyvalue.Repr(s)))
	}
	sec := atoi64(m[2])*3600 + atoi64(m[3])*60
	if m[1] == "-" {
		sec = -sec
	}
	if sec <= -86400 || sec >= 86400 {
		return nil, pyErr("ValueError", "offset must be a timedelta strictly between -timedelta(hours=24) and timedelta(hours=24).")
	}
	return &fixedZone{sec: sec}, nil
}

func atoi64(s string) int64 {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0 // callers pass digits only (regular expressions)
	}
	return n
}

// civil is a calendar date and wall-clock time with microseconds.
type civil struct {
	y, mo, d, h, mi, s, us int64
}

func (c civil) valid() bool {
	if c.mo < 1 || c.mo > 12 || c.d < 1 || c.h > 23 || c.mi > 59 || c.s > 59 || c.y < 1 {
		return false
	}
	return c.d <= int64(time.Date(int(c.y), time.Month(c.mo)+1, 0, 0, 0, 0, 0, time.UTC).Day())
}

// unixUTC is the civil time read in UTC, whole seconds.
func (c civil) unixUTC() int64 {
	return time.Date(int(c.y), time.Month(c.mo), int(c.d), int(c.h), int(c.mi), int(c.s), 0, time.UTC).Unix()
}

// aware is datetime.timestamp() of an aware datetime: exact microseconds, one division.
func (c civil) aware(z fixedZone) float64 {
	us := (c.unixUTC()-z.sec)*1_000_000 + c.us - z.usec
	return float64(us) / 1e6
}

// naive is datetime.timestamp() of a naive datetime: local time (mktime), then the microseconds added.
func (c civil) naive(loc *time.Location) float64 {
	t := time.Date(int(c.y), time.Month(c.mo), int(c.d), int(c.h), int(c.mi), int(c.s), 0, loc)
	return float64(t.Unix()) + float64(c.us)/1e6
}

// micro reads a fraction as microseconds, truncated to six digits (as datetime does).
func micro(frac string) int64 {
	if frac == "" {
		return 0
	}
	if len(frac) > 6 {
		frac = frac[:6]
	}
	return atoi64(frac + strings.Repeat("0", 6-len(frac)))
}

// parseOffset reads Z or +HH[[:]MM[[:]SS[.ffffff]]].
func parseOffset(s string) (fixedZone, bool) {
	if s == "Z" {
		return fixedZone{}, true
	}
	m := offsetRx.FindStringSubmatch(s)
	if m == nil {
		return fixedZone{}, false
	}
	z := fixedZone{sec: atoi64(m[2])*3600 + atoi64(m[3])*60 + atoi64(m[4]), usec: micro(m[5])}
	if m[3] != "" && atoi64(m[3]) > 59 || m[4] != "" && atoi64(m[4]) > 59 || z.sec >= 86400 {
		return fixedZone{}, false
	}
	if m[1] == "-" {
		z.sec, z.usec = -z.sec, -z.usec
	}
	return z, true
}

// isoTimestamp is datetime.fromisoformat(s).timestamp() for the extended ISO 8601 forms; ok false where Python
// raises ValueError. A time without offset is local time.
func isoTimestamp(s string, loc *time.Location) (float64, bool) {
	m := isoForm.FindStringSubmatch(s)
	if m == nil {
		return 0, false
	}
	c := civil{y: atoi64(m[1]), mo: atoi64(m[2]), d: atoi64(m[3]), h: atoi64(m[4]), mi: atoi64(m[5]), s: atoi64(m[6]), us: micro(m[7])}
	if !c.valid() {
		return 0, false
	}
	if m[8] == "" {
		return c.naive(loc), true
	}
	z, ok := parseOffset(m[8])
	if !ok {
		return 0, false
	}
	return c.aware(z), true
}

// isoTS is ship.py iso_ts: None (ok false) for an empty or unparsable value.
func isoTS(v any, loc *time.Location) (float64, bool, error) {
	if !pyvalue.Truthy(v) {
		return 0, false, nil
	}
	s, isText := v.(string)
	if !isText {
		return 0, false, pyErr("AttributeError", "'"+pyvalue.TypeName(v)+"' object has no attribute 'replace'")
	}
	s = strings.ReplaceAll(s, "Z", "+00:00")
	t, ok := isoTimestamp(s, loc)
	return t, ok, nil
}

// macTimestamp is datetime.strptime(s, "%Y-%m-%d %H:%M:%S.%f%z").timestamp().
func macTimestamp(s string) (float64, error) {
	m := macForm.FindStringSubmatch(s)
	if m == nil {
		return 0, pyErr("ValueError", fmt.Sprintf("time data %s does not match format '%%Y-%%m-%%d %%H:%%M:%%S.%%f%%z'", pyvalue.Repr(s)))
	}
	c := civil{y: atoi64(m[1]), mo: atoi64(m[2]), d: atoi64(strings.TrimSpace(m[3])), h: atoi64(m[4]), mi: atoi64(m[5]),
		s: atoi64(m[6]), us: micro(m[7])}
	if c.s > 59 {
		return 0, pyErr("ValueError", "second must be in 0..59")
	}
	if !c.valid() {
		return 0, pyErr("ValueError", "day is out of range for month")
	}
	z, ok := parseOffset(m[8])
	if !ok {
		return 0, pyErr("ValueError", fmt.Sprintf("Inconsistent use of : in %s", m[8]))
	}
	return c.aware(z), nil
}

// months are %b in the C locale.
func months() []string {
	return []string{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}
}

// bsdTime is ship.py bsd_time: "Nov 24 19:17:01" (no year) in the year that puts it closest to, and not more than
// a day after, now (the local year of now, else the year before). tz nil: local time.
func bsdTime(s string, now float64, tz *fixedZone, loc *time.Location) (float64, error) {
	f := bsdFields.FindStringSubmatch(strings.Join(strings.Fields(s), " "))
	y0 := int64(time.Unix(int64(now), 0).In(loc).Year())
	var e float64
	set := false
	for _, year := range []int64{y0, y0 - 1} {
		c, ok := bsdCivil(f, year)
		if !ok {
			continue // Feb 29 in a non-leap year, an unknown month
		}
		if tz != nil {
			e = c.aware(*tz)
		} else {
			e = float64(time.Date(int(c.y), time.Month(c.mo), int(c.d), int(c.h), int(c.mi), int(c.s), 0, loc).Unix())
		}
		set = true
		if e <= now+86400 {
			return e, nil
		}
	}
	if !set {
		return 0, pyErr("UnboundLocalError", "cannot access local variable 'e' where it is not associated with a value")
	}
	return e, nil
}

func bsdCivil(f []string, year int64) (civil, bool) {
	if f == nil {
		return civil{}, false
	}
	mo := int64(0)
	for i, name := range months() {
		if strings.EqualFold(name, f[1]) {
			mo = int64(i + 1)
		}
	}
	c := civil{y: year, mo: mo, d: atoi64(f[2]), h: atoi64(f[3]), mi: atoi64(f[4]), s: atoi64(f[5])}
	return c, c.valid()
}

// fmtUTC is datetime.fromtimestamp(e, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ").
func fmtUTC(e float64) string {
	us := roundHalfEven(e * 1e6)
	sec := floorDiv(us, 1_000_000)
	return time.Unix(sec, 0).UTC().Format("2006-01-02T15:04:05Z")
}

// fmtLocal is time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e)).
func fmtLocal(e float64, loc *time.Location) string {
	return time.Unix(int64(e), 0).In(loc).Format("2006-01-02 15:04:05")
}

func roundHalfEven(f float64) int64 {
	r := int64(f)
	diff := f - float64(r)
	switch {
	case diff > 0.5 || diff == 0.5 && r%2 != 0:
		r++
	case diff < -0.5 || diff == -0.5 && r%2 != 0:
		r--
	}
	return r
}

func floorDiv(a, b int64) int64 {
	q := a / b
	if (a%b != 0) && (a < 0) != (b < 0) {
		q--
	}
	return q
}
