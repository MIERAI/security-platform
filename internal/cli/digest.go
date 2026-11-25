package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/MIERAI/security-platform/internal/cli/flags"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// maxDigestHeadlines bounds the serious findings a digest lists (one per check family).
const maxDigestHeadlines = 5

func runDigest(_ context.Context, s *session, a *flags.Result) (int, error) {
	if err := s.locate(); err != nil {
		return 0, err
	}
	days := a.Int("days")
	if a.Bool("daily") {
		days = 1
	}
	text, err := s.digest(days)
	if err != nil {
		return 0, err
	}
	return ExitOK, emit(s.env.Stdout, text+"\n")
}

// digestCounts are the period's numbers.
type digestCounts struct {
	open, fresh, fixed, back []*pyvalue.Map
	overdue, failingJobs     int
}

// countEntries sorts the ledger's entries into open, new, fixed and came-back ones of the period (since).
func (c *digestCounts) countEntries(led *ledgerDoc, since float64) {
	after := func(e *pyvalue.Map, key string) bool {
		t, err := ts(e.Value(key))
		return err == nil && t >= since
	}
	for _, e := range led.entries {
		switch get(e, "status") {
		case "open":
			c.open = append(c.open, e)
			if after(e, "first_seen") {
				c.fresh = append(c.fresh, e)
			}
			if pyvalue.Truthy(e.Value("reopened_count")) && after(e, "last_seen") {
				c.back = append(c.back, e)
			}
		case "fixed":
			if pyvalue.Truthy(e.Value("fixed_at")) && after(e, "fixed_at") {
				c.fixed = append(c.fixed, e)
			}
		}
	}
}

func countOverdue(items map[string]*pyvalue.Map) int {
	n := 0
	for _, it := range items {
		if pyvalue.Truthy(it.Value("overdue")) {
			n++
		}
	}
	return n
}

// countFailing counts the jobs that ran and whose last run failed.
func countFailing(states map[string]*pyvalue.Map) int {
	n := 0
	for _, st := range states {
		rc := st.Value("last_rc")
		if pyvalue.Truthy(st.Value("runs_total")) && rc != nil && !isZero(rc) {
			n++
		}
	}
	return n
}

// digest is the short summary notifiers send. AGGREGATES ONLY (contract §3): counts, check families and plain
// words, finding ids for `sp explain`; never an asset name, address, port or evidence.
func (s *session) digest(days int64) (string, error) {
	inst, err := s.instance()
	if err != nil {
		return "", err
	}
	led, err := s.ledger()
	if err != nil {
		return "", err
	}
	items, err := s.items()
	if err != nil {
		return "", err
	}
	now := epochNow(s.env.Now())
	c := digestCounts{overdue: countOverdue(items), failingJobs: countFailing(s.jobStates())}
	c.countEntries(led, now-float64(days)*86400)
	lines := []string{fmt.Sprintf("Security %s (%s)", s.localDate(now), str(inst.GetOr("name", ""))), openLine(c.open),
		periodLine(days, c)}
	if c.overdue > 0 {
		lines = append(lines, fmt.Sprintf("Overdue fixes: %d", c.overdue))
	}
	if sc := s.scorecard(); sc != nil {
		lines = append(lines, "Scorecard: "+scorecardLine(sc))
	}
	if c.failingJobs > 0 {
		lines = append(lines, fmt.Sprintf("Jobs failing: %d (sp status)", c.failingJobs))
	}
	lines = append(lines, s.digestWorst(c)...)
	if len(c.open) == 0 && c.overdue == 0 && c.failingJobs == 0 {
		lines = append(lines, "All clear.")
	}
	return strings.Join(lines, "\n"), nil
}

// openLine counts the open findings above info by severity.
func openLine(open []*pyvalue.Map) string {
	var parts []string
	for _, sev := range severities() {
		if n := countSeverity(open, sev); n > 0 && sev != "info" {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	if len(parts) == 0 {
		return "Open: nothing above info"
	}
	return "Open: " + strings.Join(parts, ", ")
}

func periodLine(days int64, c digestCounts) string {
	period := "today"
	if days != 1 {
		period = fmt.Sprintf("last %d days", days)
	}
	line := fmt.Sprintf("%s: %d new, %d fixed", period, len(c.fresh), len(c.fixed))
	if len(c.back) > 0 {
		line += fmt.Sprintf(", %d came back", len(c.back))
	}
	return line
}

// serious are the critical and high entries of es.
func serious(es []*pyvalue.Map) []*pyvalue.Map {
	var out []*pyvalue.Map
	for _, e := range es {
		if sev := get(e, "severity"); sev == "critical" || sev == "high" {
			out = append(out, e)
		}
	}
	return out
}

// digestWorst lists the critical and high findings (the new ones, else all open ones) once per headline, with how
// many share the check.
func (s *session) digestWorst(c digestCounts) []string {
	pool := c.fresh
	if len(pool) == 0 {
		pool = c.open
	}
	worst := serious(pool)
	if len(worst) == 0 {
		return nil
	}
	out := []string{"Top:"}
	if len(c.fresh) > 0 {
		out = []string{"New and serious:"}
	}
	seen := map[string]bool{}
	for _, e := range byRiskThenAge(worst) {
		check := get(e, "check")
		h := safe(s.texts.Headline(check, check))
		if seen[h] {
			continue
		}
		seen[h] = true
		line := fmt.Sprintf("- %s: %s", safe(get(e, "severity")), h)
		if n := countCheck(pool, check); n > 1 {
			line += fmt.Sprintf(" (x%d)", n)
		}
		out = append(out, line+fmt.Sprintf("  [sp explain %s]", safe(get(e, "id"))))
		if len(seen) == maxDigestHeadlines {
			break
		}
	}
	return out
}

func countCheck(es []*pyvalue.Map, check string) int {
	n := 0
	for _, e := range es {
		if get(e, "check") == check {
			n++
		}
	}
	return n
}
