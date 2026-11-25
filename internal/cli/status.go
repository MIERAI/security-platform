package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/cli/flags"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// Limits of the status screen.
const (
	week         = 7 * 86400
	maxGapLines  = 8
	maxTopRisks  = 5
	noteWidth    = 80
	reasonWidth  = 100
	headlineSize = 90
)

func openEntries(led *ledgerDoc) []*pyvalue.Map {
	var out []*pyvalue.Map
	for _, e := range led.entries {
		if get(e, "status") == "open" {
			out = append(out, e)
		}
	}
	return out
}

// statusView is what `sp status` reads.
type statusView struct {
	inst  *pyvalue.Map
	led   *ledgerDoc
	items map[string]*pyvalue.Map
	open  []*pyvalue.Map
	now   float64
}

func runStatus(_ context.Context, s *session, _ *flags.Result) (int, error) {
	v, err := s.loadStatus()
	if err != nil {
		return 0, err
	}
	var b strings.Builder
	b.WriteString(s.paint("1", "security-platform status - "+str(v.inst.GetOr("name", ""))) + "\n")
	if len(v.led.entries) == 0 && !v.led.collectors {
		b.WriteString("  no scan yet: run `sp run`\n")
		return ExitOK, emit(s.env.Stdout, b.String())
	}
	s.statusFindings(&b, v)
	s.statusScores(&b, v)
	s.statusJobs(&b, v)
	s.statusGaps(&b)
	s.statusTop(&b, v.open)
	return ExitOK, emit(s.env.Stdout, b.String())
}

func (s *session) loadStatus() (*statusView, error) {
	if err := s.locate(); err != nil {
		return nil, err
	}
	inst, err := s.instance()
	if err != nil {
		return nil, err
	}
	led, err := s.ledger()
	if err != nil {
		return nil, err
	}
	items, err := s.items()
	if err != nil {
		return nil, err
	}
	return &statusView{inst: inst, led: led, items: items, open: openEntries(led), now: epochNow(s.env.Now())}, nil
}

func (s *session) statusFindings(b *strings.Builder, v *statusView) {
	if len(v.open) > 0 {
		var parts []string
		for _, sev := range severities() {
			if n := countSeverity(v.open, sev); n > 0 {
				parts = append(parts, fmt.Sprintf("%s %d", s.sevColor(sev), n))
			}
		}
		b.WriteString("\nOpen findings: " + strings.Join(parts, ", ") + "\n")
	} else {
		b.WriteString("\nOpen findings: none\n")
	}
	if n := countOverdue(v.items); n > 0 {
		b.WriteString(s.paint("31", fmt.Sprintf("Overdue fixes: %d", n)) + " (past their remediation SLO; `sp findings --overdue`)\n")
	}
	if n := countUnassigned(v.items); n > 0 {
		fmt.Fprintf(b, "Without an owner: %d (set remediation.default_owner)\n", n)
	}
	fmt.Fprintf(b, "Fixed in the last 7 days: %d", countFixedSince(v.led, v.now-week))
	if n := countReopened(v.open); n > 0 {
		fmt.Fprintf(b, "   Came back (regressions): %d", n)
	}
	b.WriteString("\n")
}

func countUnassigned(items map[string]*pyvalue.Map) int {
	n := 0
	for _, it := range items {
		if get(it, "status") == "open" && get(it, "owner") == "unassigned" {
			n++
		}
	}
	return n
}

// countFixedSince counts the findings fixed after since.
func countFixedSince(led *ledgerDoc, since float64) int {
	n := 0
	for _, e := range led.entries {
		if get(e, "status") != "fixed" || !pyvalue.Truthy(e.Value("fixed_at")) {
			continue
		}
		if t, err := ts(e.Value("fixed_at")); err == nil && t > since {
			n++
		}
	}
	return n
}

func countReopened(open []*pyvalue.Map) int {
	n := 0
	for _, e := range open {
		if pyvalue.Truthy(e.Value("reopened_count")) {
			n++
		}
	}
	return n
}

func countSeverity(es []*pyvalue.Map, sev string) int {
	n := 0
	for _, e := range es {
		if get(e, "severity") == sev {
			n++
		}
	}
	return n
}

func (s *session) statusScores(b *strings.Builder, v *statusView) {
	if sc := s.scorecard(); sc != nil {
		fmt.Fprintf(b, "\nScorecard: %s  (%s, threshold %s)\n", scorecardLine(sc), str(sc.GetOr("status", "?")),
			str(sc.GetOr("threshold", int64(75))))
		if pil, ok := sc.Value("pillars").(*pyvalue.Map); ok && pil.Len() > 0 {
			parts := make([]string, 0, pil.Len())
			for _, k := range pil.Keys() {
				parts = append(parts, safe(k)+" "+str(scoreOf(pil.Value(k))))
			}
			b.WriteString("  pillars: " + strings.Join(parts, ", ") + "\n")
		}
	}
	sli := v.led.sli
	if sli.Len() == 0 {
		return
	}
	var bad []string
	for _, k := range sli.Keys() {
		m, _ := sli.Value(k).(*pyvalue.Map)
		if !pyvalue.Truthy(field(m, "ok")) {
			bad = append(bad, safe(k)+"="+str(field(m, "value")))
		}
	}
	fmt.Fprintf(b, "\nSecurity SLIs: %d/%d on target", sli.Len()-len(bad), sli.Len())
	if len(bad) > 0 {
		b.WriteString(": off target " + strings.Join(bad, ", "))
	}
	b.WriteString("\n")
}

// scoreOf is a dimension's or pillar's score: v["score"] for a mapping, v itself otherwise.
func scoreOf(v any) any {
	if m, ok := v.(*pyvalue.Map); ok {
		return m.Value("score")
	}
	return v
}

// scorecardLine is the overall (weakest) score and the three weakest dimensions (cli/sp.py scorecard_line).
func scorecardLine(sc *pyvalue.Map) string {
	total := sc.GetOr("overall", sc.Value("score"))
	type dim struct {
		name  string
		score any
	}
	var dims []dim
	switch d := sc.Value("dimensions").(type) {
	case *pyvalue.Map:
		for _, k := range d.Keys() {
			dims = append(dims, dim{k, scoreOf(d.Value(k))})
		}
	case []any:
		for _, x := range d {
			if m, ok := x.(*pyvalue.Map); ok {
				dims = append(dims, dim{pyvalue.Str(m.GetOr("id", m.Value("name"))), m.Value("score")})
			}
		}
	}
	sort.SliceStable(dims, func(i, j int) bool { return scoreLess(dims[i].score, dims[j].score) })
	out := "?"
	if total != nil {
		out = str(total) + "/100"
	}
	if len(dims) > 3 {
		dims = dims[:3]
	}
	if len(dims) > 0 {
		parts := make([]string, len(dims))
		for i, d := range dims {
			parts[i] = safe(d.name) + " " + str(d.score)
		}
		out += "   weakest: " + strings.Join(parts, ", ")
	}
	return out
}

// scoreLess orders scores lowest first, missing (or non-numeric) ones last.
func scoreLess(a, b any) bool {
	fa, oka := number(a)
	fb, okb := number(b)
	if oka != okb {
		return oka
	}
	return oka && fa < fb
}

func (s *session) statusJobs(b *strings.Builder, v *statusView) {
	b.WriteString("\nJobs:\n")
	names, jobs := jobsOf(v.inst)
	states := s.jobStates()
	for _, n := range names {
		st := states[n]
		if st == nil || !pyvalue.Truthy(st.Value("runs_total")) {
			fmt.Fprintf(b, "  %s   %s\n", s.paint("33", "never"), safe(n))
			continue
		}
		lastGood := "never"
		if last := st.Value("last_success"); pyvalue.Truthy(last) {
			if t, ok := number(last); ok {
				lastGood = ago(t, v.now)
			}
		}
		if late, ok := lateSlot(n, jobs[n], st, v.now, s.env.Loc); ok {
			fmt.Fprintf(b, "  %s    %s slot %s not run yet (%s late); last good run %s\n", s.paint("33", "LATE"),
				ljust(safe(n), 20), time.Unix(late, 0).In(s.env.Loc).Format("2006-01-02 15:04"),
				strings.Replace(ago(float64(late), v.now), " ago", "", 1), lastGood)
			continue
		}
		if isZero(st.Value("last_rc")) {
			fmt.Fprintf(b, "  %s  %s last good run %s\n", s.paint("32", "ok"), ljust(safe(n), 20), lastGood)
			continue
		}
		fmt.Fprintf(b, "  %s  %s last good run %s  (%s)\n", s.paint("31", "FAILING"), ljust(safe(n), 20), lastGood,
			safe(head(get(st, "last_note"), noteWidth)))
	}
}

// statusGaps lists what the newest collector outputs could not check (coverage gaps).
func (s *session) statusGaps(b *strings.Builder) {
	type gap struct{ collector, reason string }
	var gaps []gap
	paths, err := filepath.Glob(filepath.Join(s.data, "latest", "*.findings.json"))
	if err != nil {
		return
	}
	sort.Strings(paths)
	for _, p := range paths {
		v, _, err := s.readJSON(p, maxDocument)
		d, ok := v.(*pyvalue.Map)
		if err != nil || !ok {
			continue
		}
		col := pyvalue.Str(field(asMap(d.Value("collector")), "name"))
		cov, _ := d.Value("coverage").([]any)
		for _, x := range cov {
			if g, ok := x.(*pyvalue.Map); ok && get(g, "status") == "gap" {
				gaps = append(gaps, gap{col, pyvalue.Str(g.GetOr("reason", ""))})
			}
		}
	}
	if len(gaps) == 0 {
		return
	}
	b.WriteString(s.paint("33", fmt.Sprintf("\nCould not check %d thing(s)", len(gaps))) + " (no finding there does NOT mean safe):\n")
	for i, g := range gaps {
		if i == maxGapLines {
			break
		}
		fmt.Fprintf(b, "  %s: %s\n", safe(g.collector), safe(head(g.reason, reasonWidth)))
	}
}

func asMap(v any) *pyvalue.Map {
	m, _ := v.(*pyvalue.Map)
	return m
}

// byRiskThenAge sorts entries worst severity first, then oldest first (stable).
func byRiskThenAge(es []*pyvalue.Map) []*pyvalue.Map {
	out := append([]*pyvalue.Map(nil), es...)
	sort.SliceStable(out, func(i, j int) bool {
		if ri, rj := sevRank(get(out[i], "severity")), sevRank(get(out[j], "severity")); ri != rj {
			return ri < rj
		}
		return get(out[i], "first_seen") < get(out[j], "first_seen")
	})
	return out
}

func (s *session) statusTop(b *strings.Builder, open []*pyvalue.Map) {
	top := byRiskThenAge(open)
	if len(top) == 0 {
		return
	}
	top = top[:min(len(top), maxTopRisks)]
	b.WriteString("\nTop risks (sp explain <id>):\n")
	for _, e := range top {
		sev := get(e, "severity")
		fmt.Fprintf(b, "  %s  %s %s\n", safe(get(e, "id")), ljust(s.sevColor(safe(sev)), 8),
			safe(head(s.texts.Headline(get(e, "check"), get(e, "title")), headlineSize)))
	}
}
