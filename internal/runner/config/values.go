package config

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// ErrValue is the error class of a configuration value of the wrong kind.
var ErrValue = errors.New("bad value")

// maxSeconds bounds durations (about 31 years) so arithmetic on epochs cannot overflow.
const maxSeconds = 1 << 30

// Duration is the reference's parse_duration: "90s", "30m", "2h", "7d", "1w", or a number of seconds; absent or
// empty is 0. A fractional amount is truncated toward zero after scaling ("1.5m" = 90).
func Duration(v any) (int64, error) {
	switch x := v.(type) {
	case nil:
		return 0, nil
	case bool:
		return boolInt(x), nil
	case int64:
		return bounded(float64(x), v)
	case int:
		return bounded(float64(x), v)
	case float64:
		return bounded(x, v)
	case string:
		return durationText(x)
	default:
		return 0, fmt.Errorf("%w: duration of type %T", ErrValue, v)
	}
}

func durationText(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	t := strings.TrimSpace(s)
	units := map[byte]float64{'s': 1, 'm': 60, 'h': 3600, 'd': 86400, 'w': 604800}
	if t == "" {
		return 0, fmt.Errorf("%w: duration %q", ErrValue, s)
	}
	if u, ok := units[t[len(t)-1]]; ok {
		f, err := strconv.ParseFloat(strings.TrimSpace(t[:len(t)-1]), 64)
		if err != nil {
			return 0, fmt.Errorf("%w: duration %q", ErrValue, s)
		}
		return bounded(f*u, s)
	}
	n, err := strconv.ParseInt(t, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: duration %q (want <n>s|m|h|d|w or seconds)", ErrValue, s)
	}
	return bounded(float64(n), s)
}

func bounded(f float64, orig any) (int64, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) || math.Abs(f) > maxSeconds {
		return 0, fmt.Errorf("%w: duration %v out of range", ErrValue, orig)
	}
	return int64(f), nil // truncation toward zero, as Python's int()
}

func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// Int is Python's int() of a configuration value: integers, floats (truncated), booleans and decimal text.
func Int(v any, def int64) (int64, error) {
	switch x := v.(type) {
	case nil:
		return def, nil
	case bool:
		return boolInt(x), nil
	case int64:
		return x, nil
	case float64:
		return floatInt(x)
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(x), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%w: integer %q", ErrValue, x)
		}
		return n, nil
	default:
		return 0, fmt.Errorf("%w: integer of type %T", ErrValue, v)
	}
}

func floatInt(x float64) (int64, error) {
	if math.IsNaN(x) || math.IsInf(x, 0) || math.Abs(x) > math.MaxInt32 {
		return 0, fmt.Errorf("%w: integer %v out of range", ErrValue, x)
	}
	return int64(x), nil
}

// Truthy is Python's truthiness of a configuration value.
func Truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case int64:
		return x != 0
	case int:
		return x != 0
	case float64:
		return x != 0
	case string:
		return x != ""
	case []any:
		return len(x) > 0
	case *Map:
		return x != nil && len(x.Keys) > 0
	default:
		return true
	}
}

// String returns a string value, or def when absent; other kinds are written as Python's str() would.
func String(v any, def string) string {
	switch x := v.(type) {
	case nil:
		return def
	case string:
		return x
	default:
		return Str(x)
	}
}

// Str is Python's str() of a decoded value (scalars; containers are not expected here).
func Str(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case bool:
		if x {
			return "True"
		}
		return "False"
	case string:
		return x
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		return pyvalue.FloatRepr(x)
	default:
		return fmt.Sprint(x)
	}
}
