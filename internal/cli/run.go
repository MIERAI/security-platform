package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/MIERAI/security-platform/internal/cli/flags"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// notByDefault are the job types `sp run` without job names leaves out: they publish or send what the others
// produce.
func notByDefault() []string {
	return []string{"digest", "snapshot", "push", "pull-snapshot", "notify"}
}

// derived are the job types that work on what collectors and ingests produced: they run last.
func derived() []string {
	return []string{"remediation", "export", "digest", "snapshot", "push", "pull-snapshot", "notify"}
}

const maxRunNote = 100

func runRun(ctx context.Context, s *session, a *flags.Result) (int, error) {
	if err := s.locate(); err != nil {
		return 0, err
	}
	inst, err := s.instance()
	if err != nil {
		return 0, err
	}
	order, jobs := jobsOf(inst)
	names, err := selectJobs(a.Args("jobs"), order, jobs)
	if err != nil {
		return 0, err
	}
	argv, err := s.runnerArgv(names)
	if err != nil {
		return 0, err
	}
	if werr := emitf(s.env.Stdout, "running %d job(s): %s  (each job's log: %s/runs/<date>/)\n", len(names),
		safe(strings.Join(names, ", ")), s.data); werr != nil {
		return 0, werr
	}
	t0 := epochNow(s.env.Now())
	rc, err := s.env.Exec(ctx, argv, s.env.Stdout, s.env.Stderr)
	if err != nil {
		return 0, die(ExitFail, "the runner could not be started: %v", err)
	}
	return rc, s.runResults(names, t0)
}

// runResults prints one line per job from the state the runner recorded: ok when it succeeded after t0.
func (s *session) runResults(names []string, t0 float64) error {
	var b strings.Builder
	states := s.jobStates()
	for _, n := range names {
		st := states[n]
		last, _ := number(field(st, "last_success"))
		good := isZero(field(st, "last_rc")) && last >= t0-1
		dur, _ := number(field(st, "last_duration"))
		mark, note := s.paint("32", "ok"), ""
		if !good {
			mark, note = s.paint("31", "FAILED"), safe(head(get(st, "last_note"), maxRunNote))
		}
		fmt.Fprintf(&b, "  %s  %s %ss  %s\n", mark, ljust(safe(n), 20), rjust(pyvalue.FormatFixed(dur, 0), 6), note)
	}
	b.WriteString("next: sp status   |   sp findings --open --severity high\n")
	return emit(s.env.Stdout, b.String())
}

// selectJobs returns the jobs to run: the named ones, else every job but those of notByDefault; collectors and
// ingests first, then what derives from the ledger (stable otherwise). Unknown names are an error.
func selectJobs(given, order []string, jobs map[string]*pyvalue.Map) ([]string, error) {
	typ := func(n string) string { return pyvalue.Str(jobs[n].GetOr("type", "collector")) }
	names := given
	if len(names) == 0 {
		for _, n := range order {
			if !slices.Contains(notByDefault(), typ(n)) {
				names = append(names, n)
			}
		}
	}
	var unknown []string
	for _, n := range names {
		if _, ok := jobs[n]; !ok {
			unknown = append(unknown, n)
		}
	}
	if len(unknown) > 0 {
		configured := strings.Join(order, ", ")
		if configured == "" {
			configured = "none"
		}
		return nil, die(ExitUsage, "not in runner.jobs: %s (configured: %s)", safe(strings.Join(unknown, ", ")), safe(configured))
	}
	names = slices.Clone(names)
	sort.SliceStable(names, func(i, j int) bool {
		return !slices.Contains(derived(), typ(names[i])) && slices.Contains(derived(), typ(names[j]))
	})
	return names, nil
}

// runnerArgv is the runner's `run` command for these jobs: the reference runner of the product tree (the default
// trigger, docs/runner.md), with the data directory and instance config of this command.
func (s *session) runnerArgv(names []string) ([]string, error) {
	if s.env.Tree == "" {
		return nil, die(ExitFail, "the product tree (runner, collectors) was not found: %v", s.env.TreeErr)
	}
	py, err := s.env.Python()
	if err != nil {
		return nil, die(ExitFail, "%v", err)
	}
	argv := []string{py, filepath.Join(s.env.Tree, "runner", "runner.py"), "run"}
	argv = append(argv, names...)
	return append(argv, "--instance", s.instancePath, "--data", s.data), nil
}
