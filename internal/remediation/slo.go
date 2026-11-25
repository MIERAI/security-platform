package remediation

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
)

// ErrConfig is wrapped by every error about the instance's `remediation:` section.
var ErrConfig = errors.New("remediation config")

// defaultSLO is the contract's table (ledger §7), in the order the reference lists it.
func defaultSLO() [][2]string {
	return [][2]string{{"kev_exposed", "1d"}, {"critical", "7d"}, {"high", "30d"}, {"medium", "90d"}, {"low", "180d"}}
}

func unitSeconds(u byte) (float64, bool) {
	switch u {
	case 's':
		return 1, true
	case 'm':
		return 60, true
	case 'h':
		return 3600, true
	case 'd':
		return 86400, true
	case 'w':
		return 604800, true
	default:
		return 0, false
	}
}

// SLOSeconds is the SLO table in seconds: the contract's defaults overridden by `remediation.slo` (cfg may be
// nil). A class whose duration is empty or zero has no SLO.
func SLOSeconds(cfg *pyjson.Object) (map[string]int64, error) {
	raw, err := sloTable(cfg)
	if err != nil {
		return nil, err
	}
	out := map[string]int64{}
	for _, k := range raw.Keys() {
		v, _ := raw.Get(k)
		d, ok, err := duration(v)
		if err != nil {
			return nil, fmt.Errorf("%w: slo.%s: %w", ErrConfig, k, err)
		}
		if ok && d != 0 {
			out[k] = d
		}
	}
	return out, nil
}

// sloTable is the defaults overridden by `slo:`, as written (durations not parsed yet).
func sloTable(cfg *pyjson.Object) (*pyjson.Object, error) {
	raw := pyjson.NewObject()
	for _, kv := range defaultSLO() {
		raw.Set(kv[0], kv[1])
	}
	if cfg == nil {
		return raw, nil
	}
	v, ok := cfg.Get("slo")
	if !ok || !pyjson.Truthy(v) {
		return raw, nil
	}
	o, isObj := v.(*pyjson.Object)
	if !isObj {
		return nil, fmt.Errorf("%w: slo must be a mapping", ErrConfig)
	}
	for _, k := range o.Keys() {
		x, _ := o.Get(k)
		raw.Set(k, x)
	}
	return raw, nil
}

// duration parses "7d", "12h", "1.5d", a plain number of seconds, or a number; ok is false for null or "".
func duration(v pyjson.Value) (secs int64, ok bool, err error) {
	if v == nil || v == "" {
		return 0, false, nil
	}
	if f, isNum := pyjson.Float(v); isNum {
		return truncate(f)
	}
	s, isStr := v.(string)
	if !isStr {
		return 0, false, fmt.Errorf("not a duration: %s", pyjson.Repr(v))
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false, fmt.Errorf("not a duration: %s", pyjson.Repr(v))
	}
	if mult, isUnit := unitSeconds(s[len(s)-1]); isUnit {
		f, perr := strconv.ParseFloat(strings.TrimSpace(s[:len(s)-1]), 64)
		if perr != nil {
			return 0, false, fmt.Errorf("not a duration: %s", pyjson.Repr(v))
		}
		return truncate(f * mult)
	}
	i, perr := strconv.ParseInt(s, 10, 64)
	if perr != nil {
		return 0, false, fmt.Errorf("not a duration: %s", pyjson.Repr(v))
	}
	return i, true, nil
}

func truncate(f float64) (secs int64, ok bool, err error) {
	if math.IsNaN(f) || math.IsInf(f, 0) || math.Abs(f) > 1e15 {
		return 0, false, fmt.Errorf("not a finite duration: %v", f)
	}
	return int64(f), true, nil
}

// ClassOf is the SLO class of a ledger entry: kev_exposed when attributes kev and exposed are both true, else
// its severity.
func ClassOf(e *pyjson.Object) string {
	if a := e.Obj("attributes"); a != nil && a.Truthy("kev") && a.Truthy("exposed") {
		return "kev_exposed"
	}
	return e.Str("severity")
}

// DueAt is the due date (epoch seconds) of an item whose SLO clock started at start; ok is false when the class
// has no SLO.
func DueAt(start float64, class string, slo map[string]int64) (float64, bool) {
	sec, ok := slo[class]
	if !ok {
		return 0, false
	}
	due := start + float64(sec)
	return due, due != 0
}
