package scorecard

import (
	"math"
	"sort"
	"strings"

	pv "github.com/MIERAI/security-platform/internal/pyvalue"
)

const (
	helpScore = "Security scorecard: weighted pass ratio of the controls (0-100); the weakest dimension decides"
	helpCount = "Controls per dimension and result (details in the private scorecard report)"
	helpRegr  = "Times the dimension dropped below its threshold (counter; the alert fires on increases)"
	helpAtt   = "Attested (human) controls by state; expired ones fail again"
)

type series struct {
	name   string
	labels [][2]string
	value  any // int64 or float64 (or a value read back from the regression state)
	help   string
}

func label(pairs ...string) [][2]string {
	out := make([][2]string, 0, len(pairs)/2)
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, [2]string{pairs[i], pairs[i+1]})
	}
	return out
}

// Prometheus is the scorecard's metrics in the text format (SPEC §5, contracts/metrics/registry.json).
func (r *Result) Prometheus() string {
	s := r.scoreSeries()
	s = append(s,
		series{"security_score_overall", nil, r.Overall, "Overall score = the weakest dimension's score"},
		series{"security_score_threshold", nil, r.Threshold, "A dimension below this fails the scorecard"},
		series{"security_score_pass", nil, boolInt(r.Status == "PASS"), "1 while every dimension meets its threshold"})
	s = append(s, r.countSeries()...)
	s = append(s, r.regressionSeries()...)
	a := r.Attestations
	for _, x := range []struct {
		state string
		n     int
	}{{"valid", a.Valid}, {"expiring", a.Expiring}, {"expired", a.Expired}, {"missing", a.Missing}} {
		s = append(s, series{"security_attestations", label("state", x.state), int64(x.n), helpAtt})
	}
	s = append(s, series{"security_scorecard_last_compute_timestamp_seconds", nil, int64(math.Trunc(r.Now)),
		"When the scorecard was last computed"})
	return render(s)
}

func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

func (r *Result) scoreSeries() []series {
	var s []series
	for _, d := range r.Dims {
		s = append(s, series{"security_score", label("dimension", d.ID), d.Score, helpScore})
	}
	for _, p := range r.Pillars {
		s = append(s, series{"security_score", label("pillar", p.Key), p.Score, helpScore})
	}
	for _, f := range r.Functions {
		if f.Controls > 0 {
			s = append(s, series{"security_score", label("function", f.Key), f.Score, helpScore})
		}
	}
	keys := make([]string, 0, len(r.Cross))
	for k := range r.Cross {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		dim, pl, _ := strings.Cut(k, "|")
		s = append(s, series{"security_score", label("dimension", dim, "pillar", pl), r.Cross[k], helpScore})
	}
	return s
}

func (r *Result) countSeries() []series {
	counts := map[[2]string]int64{}
	for _, c := range r.Controls {
		st := "fail"
		if c.Status == "pass" || c.Status == "na" {
			st = c.Status
		}
		counts[[2]string{c.Dimension, st}]++
	}
	var s []series
	for _, d := range r.Dims {
		for _, st := range []string{"pass", "fail", "na"} {
			s = append(s, series{"security_score_controls", label("dimension", d.ID, "status", st),
				counts[[2]string{d.ID, st}], helpCount})
		}
	}
	return s
}

func (r *Result) regressionSeries() []series {
	if r.Regressions == nil {
		return nil
	}
	keys := r.Regressions.Keys()
	sort.Strings(keys)
	s := make([]series, 0, len(keys))
	for _, k := range keys {
		s = append(s, series{"security_score_regressions_total", label("dimension", k), r.Regressions.Value(k), helpRegr})
	}
	return s
}

// render writes the text format: HELP and TYPE (counter for *_total, else gauge) before a name's first sample,
// labels sorted, label values with \ → /, " → ', newline → space; floats as FormatG, other values as text.
func render(all []series) string {
	var b strings.Builder
	seen := map[string]bool{}
	for _, s := range all {
		if !seen[s.name] {
			seen[s.name] = true
			if s.help != "" {
				b.WriteString("# HELP " + s.name + " " + s.help + "\n")
			}
			kind := "gauge"
			if strings.HasSuffix(s.name, "_total") {
				kind = "counter"
			}
			b.WriteString("# TYPE " + s.name + " " + kind + "\n")
		}
		b.WriteString(s.name + renderLabels(s.labels) + " " + renderValue(s.value) + "\n")
	}
	return b.String()
}

func renderLabels(labels [][2]string) string {
	if len(labels) == 0 {
		return ""
	}
	sorted := append([][2]string(nil), labels...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i][0] < sorted[j][0] })
	parts := make([]string, len(sorted))
	esc := strings.NewReplacer("\\", "/", `"`, "'", "\n", " ")
	for i, l := range sorted {
		parts[i] = l[0] + `="` + esc.Replace(l[1]) + `"`
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func renderValue(v any) string {
	if f, ok := v.(float64); ok {
		return pv.FormatG(f)
	}
	return pv.Str(v)
}
