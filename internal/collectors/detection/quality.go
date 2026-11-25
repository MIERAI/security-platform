package detection

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// Time and duration texts. Never written after initialisation.
var (
	durationText = regexp.MustCompile(`^(\d+(?:\.\d+)?)([smhdw])$`)
	// time.strptime(s, "%Y-%m-%dT%H:%M:%S"): the field alternatives of CPython's _strptime, case-insensitive
	strptimeText = regexp.MustCompile(`(?i)^([0-9]{4})-(1[0-2]|0[1-9]|[1-9])-(3[01]|[12][0-9]|0[1-9]|[1-9]| [1-9])` +
		`T(2[0-3]|[0-1][0-9]|[0-9]):([0-5][0-9]|[0-9]):(6[0-1]|[0-5][0-9]|[0-9])`)
	strpdateText = regexp.MustCompile(`^([0-9]{4})-(1[0-2]|0[1-9]|[1-9])-(3[01]|[12][0-9]|0[1-9]|[1-9]| [1-9])`)
	// a YAML timestamp as pyvalue keeps it (Python's str(datetime)): date, time, fraction, offset
	yamlTimeText = regexp.MustCompile(`^([0-9]{4})-([0-9]{2})-([0-9]{2}) ([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{6}))?(?:([+-])([0-9]{2}):([0-9]{2}))?$`)
)

const day = 86400.0

// ErrDuration is a duration that is neither a number of seconds nor <number><s|m|h|d|w>.
var ErrDuration = errors.New("bad duration")

// Duration is the reference's dur(): a number is seconds, text is <number><unit>.
func Duration(v any) (float64, error) {
	switch x := v.(type) {
	case bool, int64, float64:
		f, _ := pyvalue.ToFloat64(x)
		return f, nil
	}
	m := durationText.FindStringSubmatch(strings.TrimSpace(pyvalue.Str(v)))
	if m == nil {
		return 0, fmt.Errorf("%w %s", ErrDuration, pyvalue.Repr(v))
	}
	f, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, fmt.Errorf("%w %s", ErrDuration, pyvalue.Repr(v))
	}
	unit := map[string]float64{"s": 1, "m": 60, "h": 3600, "d": day, "w": 7 * day}[m[2]]
	return f * unit, nil
}

func (c *collector) duration(key, def string) (float64, error) {
	v := c.d.GetOr(key, def)
	f, err := Duration(v)
	if err != nil {
		return 0, fmt.Errorf("%w: detection.%s: %w", rundoc.ErrUsage, key, err)
	}
	return f, nil
}

// EventTime reads a recorded time as UTC epoch seconds (DETECTION-D2: the reference reads it as local time). Text
// is read as time.strptime(text[:19], "%Y-%m-%dT%H:%M:%S") reads it; a YAML timestamp (pyvalue.DateTime) is read
// with its offset (UTC without one). Anything else is not a time.
func EventTime(v any) (float64, bool) {
	switch x := v.(type) {
	case string:
		return strptime(x)
	case pyvalue.DateTime:
		return yamlTime(x.Text)
	}
	return 0, false
}

func strptime(s string) (float64, bool) {
	s = rundoc.Cut(s, 19)
	m := strptimeText.FindStringSubmatch(s)
	if len(m) == 0 || len(m[0]) != len(s) {
		return 0, false
	}
	return epoch(atoiAll(m[1:]))
}

func yamlTime(text string) (float64, bool) {
	m := yamlTimeText.FindStringSubmatch(text)
	if m == nil {
		return 0, false
	}
	t, ok := epoch(atoiAll(m[1:7]))
	if !ok {
		return 0, false
	}
	if m[7] != "" {
		if us, err := strconv.Atoi(m[7]); err == nil { // six digits by the expression
			t += float64(us) / 1e6
		}
	}
	if m[8] != "" {
		off := atoiAll(m[9:11])
		sec := float64(off[0]*3600 + off[1]*60)
		if m[8] == "+" {
			sec = -sec
		}
		t += sec
	}
	return t, true
}

func atoiAll(ss []string) []int {
	out := make([]int, len(ss))
	for i, s := range ss {
		if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil { // digits by the expressions
			out[i] = n
		}
	}
	return out
}

// epoch is calendar.timegm of a validated date (a day out of the month's range is not a time; seconds 60 and 61
// roll over as mktime/timegm do).
func epoch(f []int) (float64, bool) {
	for len(f) < 6 {
		f = append(f, 0)
	}
	y, mo, d, h, mi, s := f[0], f[1], f[2], f[3], f[4], f[5]
	if mo < 1 || mo > 12 || d < 1 || d > time.Date(y, time.Month(mo)+1, 0, 0, 0, 0, 0, time.UTC).Day() {
		return 0, false
	}
	return float64(time.Date(y, time.Month(mo), d, h, mi, s, 0, time.UTC).Unix()), true
}

// DateTime is time.strptime(text[:10], "%Y-%m-%d") as UTC epoch seconds (the catalog's released date).
func DateTime(text string) (float64, bool) {
	s := rundoc.Cut(text, 10)
	m := strpdateText.FindStringSubmatch(s)
	if len(m) == 0 || len(m[0]) != len(s) {
		return 0, false
	}
	return epoch(atoiAll(m[1:]))
}

func (c *collector) dataPath(key string, def ...string) string {
	if v, ok := c.d.Value(key).(string); ok && v != "" {
		return rundoc.ExpandUser(v, c.home)
	}
	return filepath.Join(append([]string{c.data}, def...)...)
}

// verdicts: alert verdicts a human recorded in the window, and the false-positive ratio (drills excluded).
func (c *collector) verdicts(context.Context) error {
	win, err := c.duration("fp_window", "30d")
	if err != nil {
		return err
	}
	var rows []any
	if p := c.dataPath("verdicts", "detections", "verdicts.yaml"); exists(p) {
		if doc, err := loadYAML(p, maxDataFile); err == nil { // unreadable or unparsable: no verdicts, as the reference reads it
			rows = rundoc.List(rundoc.Get(doc, "verdicts"))
		}
	}
	counts := map[string]int{}
	for _, v := range rows {
		m, ok := v.(*pyvalue.Map)
		if !ok {
			continue
		}
		t, ok := EventTime(m.GetOr("fired_at", ""))
		if !ok || c.now-t > win {
			continue
		}
		if s, isText := m.GetOr("verdict", "?").(string); isText {
			counts[s]++
		}
	}
	for _, k := range []string{"true_positive", "false_positive", "benign", "drill"} {
		c.metric("security_detection_verdicts", float64(counts[k]), "Alert verdicts recorded by a human in the window",
			label("result", k))
	}
	if judged := counts["true_positive"] + counts["false_positive"] + counts["benign"]; judged > 0 {
		c.metric("security_detection_false_positive_ratio", float64(counts["false_positive"])/float64(judged),
			"False positives / judged alerts (drills excluded) in the window")
	}
	return nil
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// drillFiles is sorted(glob(<dir>/*.yaml)) (hidden files skipped, as glob does).
func drillFiles(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if ok, merr := path.Match("*.yaml", e.Name()); merr == nil && ok && !strings.HasPrefix(e.Name(), ".") {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(out)
	return out
}

const drillAsset = "detection-drills:lab"

// drills: the last drill is recent, detected within the target time to detect, and followed the runbook.
func (c *collector) drills(context.Context) error {
	var drills []*pyvalue.Map
	for _, p := range drillFiles(c.dataPath("drills", "detections", "drills")) {
		if x, err := loadYAML(p, maxDataFile); err == nil {
			if m, ok := x.(*pyvalue.Map); ok && pyvalue.Truthy(m.Value("action_at")) {
				drills = append(drills, m)
			}
		}
	}
	c.doc.OK(drillAsset)
	maxAge, err := c.duration("drill_max_age", "90d")
	if err != nil {
		return err
	}
	target, err := c.duration("ttd_target", "5m")
	if err != nil {
		return err
	}
	if len(drills) == 0 {
		return c.finding(&rundoc.Finding{Asset: drillAsset, Check: "detection.drill_overdue",
			Title: "no detection drill has been recorded", Severity: "medium",
			Remediation: "run a benign drill in the lab (docs/incident-response.md#drills)"}, "drills.json", map[string]any{"drills": 0})
	}
	last := drills[0]
	for _, x := range drills[1:] {
		if pyvalue.Str(x.Value("action_at")) > pyvalue.Str(last.Value("action_at")) {
			last = x
		}
	}
	return c.lastDrill(last, maxAge, target)
}

func (c *collector) lastDrill(last *pyvalue.Map, maxAge, target float64) error {
	t, ok := EventTime(last.Value("action_at"))
	if !ok {
		c.doc.Gap(drillAsset, "the last drill's action_at is not a time: "+rundoc.Cut(pyvalue.Repr(last.Value("action_at")), 60))
		return nil
	}
	c.metric("security_detection_drill_last_timestamp_seconds", t, "When the last detection drill acted")
	ttd, hasTTD := last.Get("ttd_seconds")
	hasTTD = hasTTD && ttd != nil
	var ttdF float64
	if hasTTD {
		f, ok := floatOf(ttd)
		if !ok {
			c.doc.Gap(drillAsset, "the last drill's ttd_seconds is not a number")
			return nil
		}
		ttdF = f
		c.metric("security_detection_drill_ttd_seconds", f, "Time to detect in the last drill (alert received - action)")
	}
	passed := last.Value("result") == "pass" && hasTTD && ttdF <= target
	p := 0.0
	if passed {
		p = 1
	}
	c.metric("security_detection_drill_pass", p, "1 if the last drill detected within the target and followed the runbook")
	switch {
	case c.now-t > maxAge:
		return c.finding(&rundoc.Finding{Asset: drillAsset, Check: "detection.drill_overdue", Severity: "medium",
			Title:       "the last detection drill is older than " + pyvalue.Str(c.d.GetOr("drill_max_age", "90d")),
			Remediation: "run a benign drill in the lab (docs/incident-response.md#drills)"},
			"drills.json", map[string]any{"last": rundoc.Loose(last.Value("id"))})
	case !passed:
		return c.finding(&rundoc.Finding{Asset: drillAsset, Check: "detection.drill_failed", Severity: "high",
			Title:       "the last detection drill did not detect within the target",
			Remediation: "fix the pipeline stage that was slow or silent; repeat the drill"},
			"drills.json", map[string]any{"last": rundoc.Loose(last.Value("id")), "ttd_seconds": rundoc.Loose(ttd)})
	}
	return nil
}

// ruleset: the detection rule content was reviewed recently (catalog `released`).
func (c *collector) ruleset() error {
	rel := pyvalue.Str(c.cat.GetOr("released", ""))
	const asset = "detection-ruleset:catalog"
	t, ok := DateTime(rel)
	if !ok {
		c.doc.Gap(asset, "catalog has no released date")
		return nil
	}
	c.doc.OK(asset)
	age := (c.now - t) / day
	c.metric("security_detection_ruleset_age_days", pyvalue.Round(age, 1), "Days since the detection rule content was last reviewed/released")
	c.metric("security_detection_ruleset_info", 1, "Detection catalog version", label("version", pyvalue.Str(c.cat.GetOr("version", ""))))
	maxAge, err := c.duration("ruleset_max_age", "90d")
	if err != nil {
		return err
	}
	if age <= maxAge/day {
		return nil
	}
	return c.finding(&rundoc.Finding{Asset: asset, Check: "detection.ruleset_stale", Severity: "medium",
		Title:       "detection rules not reviewed for " + pyvalue.FormatFixed(age, 0) + " days",
		Remediation: "review the catalog against upstream (falco-rules, ATT&CK); bump `released`"},
		"ruleset.json", map[string]any{"released": rel, "upstream": rundoc.Loose(c.cat.Value("upstream"))})
}

// floatOf is float(v) when Python's float() accepts v.
func floatOf(v any) (float64, bool) {
	f, err := pyvalue.ToFloat(v)
	return f, err == nil
}
