package pyvalue

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// The YAML 1.1 implicit types of plain scalars (the resolver of the reference implementation's YAML library).
// Compiled once, never written.
var (
	yamlBool  = regexp.MustCompile(`^(?:yes|Yes|YES|no|No|NO|true|True|TRUE|false|False|FALSE|on|On|ON|off|Off|OFF)$`)
	yamlFloat = regexp.MustCompile(`^(?:[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?` +
		`|\.[0-9][0-9_]*(?:[eE][-+][0-9]+)?|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*` +
		`|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$`)
	yamlInt = regexp.MustCompile(`^(?:[-+]?0b[0-1_]+|[-+]?0[0-7_]+|[-+]?(?:0|[1-9][0-9_]*)|[-+]?0x[0-9a-fA-F_]+` +
		`|[-+]?[1-9][0-9_]*(?::[0-5]?[0-9])+)$`)
	yamlNull      = regexp.MustCompile(`^(?:~|null|Null|NULL|)$`)
	yamlTimestamp = regexp.MustCompile(`^([0-9]{4})-([0-9]{1,2})-([0-9]{1,2})` +
		`(?:(?:[Tt]|[ \t]+)([0-9]{1,2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]*))?` +
		`(?:[ \t]*(Z|([-+])([0-9]{1,2})(?::([0-9]{2}))?))?)?$`)
	yamlDateOnly = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
)

func scalar(n *yaml.Node) (any, error) {
	tag := n.Tag
	quoted := n.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle|yaml.LiteralStyle|yaml.FoldedStyle) != 0
	switch {
	case n.Style&yaml.TaggedStyle != 0:
	case quoted:
		tag = "!!str"
	default:
		tag = resolvePlain(n.Value)
	}
	return construct(tag, n.Value)
}

// resolvePlain types a plain scalar: bool, float, int, null, timestamp (in this order), else text.
func resolvePlain(s string) string {
	switch {
	case yamlBool.MatchString(s):
		return "!!bool"
	case yamlFloat.MatchString(s):
		return "!!float"
	case yamlInt.MatchString(s):
		return "!!int"
	case yamlNull.MatchString(s):
		return "!!null"
	case isTimestamp(s):
		return "!!timestamp"
	case s == "=":
		return "!!value"
	}
	return "!!str"
}

func isTimestamp(s string) bool {
	return yamlDateOnly.MatchString(s) || (yamlTimestamp.MatchString(s) && strings.ContainsAny(s, "Tt \t"))
}

func construct(tag, s string) (any, error) {
	switch tag {
	case "!!str":
		return s, nil
	case "!!null":
		return nil, nil
	case "!!bool":
		return constructBool(s)
	case "!!int":
		return constructInt(s)
	case "!!float":
		return constructFloat(s)
	case "!!timestamp":
		return constructTimestamp(s)
	}
	return nil, fmt.Errorf("%w: could not determine a constructor for the tag %s", ErrDocument, tag)
}

func constructBool(s string) (any, error) {
	switch strings.ToLower(s) {
	case "yes", "true", "on":
		return true, nil
	case "no", "false", "off":
		return false, nil
	}
	return nil, fmt.Errorf("%w: not a boolean: %q", ErrDocument, s)
}

func constructInt(text string) (any, error) {
	s, sign := splitSign(strings.ReplaceAll(text, "_", ""))
	var (
		n   int64
		err error
	)
	switch {
	case s == "0":
		return int64(0), nil
	case strings.HasPrefix(s, "0b"):
		n, err = strconv.ParseInt(s[2:], 2, 64)
	case strings.HasPrefix(s, "0x"):
		n, err = strconv.ParseInt(s[2:], 16, 64)
	case strings.HasPrefix(s, "0"):
		n, err = strconv.ParseInt(s[1:], 8, 64)
	case strings.Contains(s, ":"):
		var f float64
		f, err = sexagesimal(s)
		n = int64(f)
	default:
		n, err = strconv.ParseInt(s, 10, 64)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: integer %q: %w", ErrDocument, text, err)
	}
	return sign * n, nil
}

func splitSign(s string) (string, int64) {
	switch {
	case strings.HasPrefix(s, "-"):
		return s[1:], -1
	case strings.HasPrefix(s, "+"):
		return s[1:], 1
	}
	return s, 1
}

// sexagesimal reads 1:30:15(.5): each part times 60 to the power of its position from the right.
func sexagesimal(s string) (float64, error) {
	parts := strings.Split(s, ":")
	total, base := 0.0, 1.0
	for i := len(parts) - 1; i >= 0; i-- {
		f, err := strconv.ParseFloat(parts[i], 64)
		if err != nil {
			return 0, fmt.Errorf("sexagesimal part %q: %w", parts[i], err)
		}
		total += f * base
		base *= 60
	}
	return total, nil
}

func constructFloat(text string) (any, error) {
	s, sign := splitSign(strings.ToLower(strings.ReplaceAll(text, "_", "")))
	switch {
	case s == ".inf":
		return float64(sign) * math.Inf(1), nil
	case s == ".nan":
		return math.NaN(), nil
	case strings.Contains(s, ":"):
		f, err := sexagesimal(s)
		if err != nil {
			return nil, fmt.Errorf("%w: float %q: %w", ErrDocument, text, err)
		}
		return float64(sign) * f, nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil && !math.IsInf(f, 0) {
		return nil, fmt.Errorf("%w: float %q: %w", ErrDocument, text, err)
	}
	return float64(sign) * f, nil
}

func constructTimestamp(s string) (any, error) {
	m := yamlTimestamp.FindStringSubmatch(s)
	if m == nil {
		return nil, fmt.Errorf("%w: timestamp %q", ErrDocument, s)
	}
	y, mo, d := atoi(m[1]), atoi(m[2]), atoi(m[3])
	if !validDate(y, mo, d) {
		return nil, fmt.Errorf("%w: timestamp %q: day is out of range for month", ErrDocument, s)
	}
	if m[4] == "" {
		return Date{Year: y, Month: mo, Day: d}, nil
	}
	h, mi, sec := atoi(m[4]), atoi(m[5]), atoi(m[6])
	if h > 23 || mi > 59 || sec > 59 {
		return nil, fmt.Errorf("%w: timestamp %q: time out of range", ErrDocument, s)
	}
	text := fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", y, mo, d, h, mi, sec)
	if frac := microseconds(m[7]); frac != 0 {
		text += fmt.Sprintf(".%06d", frac)
	}
	z, ok := zone(m[8], m[9], m[10], m[11])
	if !ok {
		return nil, fmt.Errorf("%w: timestamp %q: offset out of range", ErrDocument, s)
	}
	return DateTime{Text: text + z}, nil
}

// atoi reads a submatch of [0-9]+ (at most a few digits): never fails.
func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

func validDate(y, m, d int) bool {
	if y < 1 || m < 1 || m > 12 || d < 1 {
		return false
	}
	return d <= time.Date(y, time.Month(m)+1, 0, 0, 0, 0, 0, time.UTC).Day()
}

// microseconds reads up to six fraction digits (more are cut, fewer padded with zeros).
func microseconds(frac string) int {
	if len(frac) > 6 {
		frac = frac[:6]
	}
	for len(frac) < 6 {
		frac += "0"
	}
	return atoi(frac)
}

// zone is the UTC offset in text form: "" without a zone, "+00:00" for Z, else ±HH:MM; false when the offset
// is a day or more.
func zone(tz, sign, hours, minutes string) (string, bool) {
	switch {
	case tz == "":
		return "", true
	case sign == "":
		return "+00:00", true
	}
	offset := atoi(hours)*60 + atoi(minutes)
	if offset >= 24*60 {
		return "", false
	}
	if sign == "-" && offset != 0 {
		return fmt.Sprintf("-%02d:%02d", offset/60, offset%60), true
	}
	return fmt.Sprintf("+%02d:%02d", offset/60, offset%60), true
}
