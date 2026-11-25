package scorecard

import (
	"sort"
	"strconv"
	"strings"

	pv "github.com/MIERAI/security-platform/internal/scorecard/pyvalue"
)

// maxListedJobs bounds the problems a job detail lists.
const maxListedJobs = 6

// collectorsFresh: every named collector ("*" = every collector of the ledger) covered at least one asset
// within maxAge (its last_good_run).
func (e *evaluator) collectorsFresh(names any, maxAge float64) (bool, string, error) {
	cols, err := e.in.ledgerSection("collectors")
	if err != nil {
		return false, "", err
	}
	if pv.Equal(names, "*") {
		keys := cols.Keys()
		sort.Strings(keys)
		if len(keys) == 0 {
			return false, "no collector has run yet", nil
		}
		names = stringsToValues(keys)
	}
	list := pv.AsList(names)
	var stale []string
	for _, n := range list {
		why, err := e.staleCollector(cols, n, maxAge)
		if err != nil {
			return false, "", err
		}
		if why != "" {
			stale = append(stale, why)
		}
	}
	if len(stale) > 0 {
		return false, strings.Join(stale, "; "), nil
	}
	return true, strconv.Itoa(len(list)) + " collector(s) fresh", nil
}

func (e *evaluator) staleCollector(cols *pv.Map, n any, maxAge float64) (string, error) {
	c, _ := lookup(cols, n)
	m, ok := orEmpty(c)
	if !ok {
		return "", pv.AttributeError(c, "get")
	}
	last := m.Value("last_good_run")
	if !pv.Truthy(last) {
		return pv.Str(n) + ": never covered anything", nil
	}
	t, err := timestamp(last)
	if err != nil {
		return "", err
	}
	if e.now-t > maxAge {
		return pv.Str(n) + ": last good run " + ageText(e.now-t) + " ago", nil
	}
	return "", nil
}

func evalCollectorFresh(e *evaluator, src *pv.Map) (outcome, error) {
	maxAge, err := duration(src.Value("max_age"), 2*day)
	if err != nil {
		return outcome{}, err
	}
	ok, why, err := e.collectorsFresh(src.GetOr("collectors", "*"), maxAge)
	if err != nil {
		return outcome{}, err
	}
	return verdict(ok, why), nil
}

// evalJob: runner jobs ("*" = every job with a state) whose last run succeeded within max_age.
func evalJob(e *evaluator, src *pv.Map) (outcome, error) {
	jobs := src.GetOr("jobs", "*")
	if pv.Equal(jobs, "*") {
		names := e.in.jobNames()
		if len(names) == 0 {
			return outcome{"unknown", "no runner job state (is the runner installed?)"}, nil
		}
		jobs = stringsToValues(names)
	}
	maxAge, err := duration(src.Value("max_age"), 2*day)
	if err != nil {
		return outcome{}, err
	}
	list := pv.AsList(jobs)
	var bad []string
	for _, j := range list {
		why, err := e.jobProblem(j, maxAge, src)
		if err != nil {
			return outcome{}, err
		}
		if why != "" {
			bad = append(bad, why)
		}
	}
	if len(bad) == 0 {
		return outcome{"pass", strconv.Itoa(len(list)) + " job(s) healthy"}, nil
	}
	if len(bad) > maxListedJobs {
		bad = bad[:maxListedJobs]
	}
	return outcome{"fail", strings.Join(bad, "; ")}, nil
}

func (e *evaluator) jobProblem(j any, maxAge float64, src *pv.Map) (string, error) {
	name, _ := j.(string)
	st := e.in.jobs[name]
	if _, isText := j.(string); !isText || !pv.Truthy(st) {
		return pv.Str(j) + ": never ran", nil
	}
	m, ok := st.(*pv.Map)
	if !ok {
		return "", pv.AttributeError(st, "get")
	}
	last := m.Value("last_success")
	if !pv.Truthy(last) {
		return pv.Str(j) + ": no success within " + pv.Str(src.GetOr("max_age", "2d")), nil
	}
	age, err := pv.Sub(e.now, last)
	if err != nil {
		return "", err
	}
	if age > maxAge {
		return pv.Str(j) + ": no success within " + pv.Str(src.GetOr("max_age", "2d")), nil
	}
	if rc := m.Value("last_rc"); rc != nil && !pv.Equal(rc, int64(0)) {
		return pv.Str(j) + ": last run failed (rc=" + pv.Str(rc) + ")", nil
	}
	return "", nil
}

func stringsToValues(s []string) []any {
	out := make([]any, len(s))
	for i, x := range s {
		out[i] = x
	}
	return out
}
