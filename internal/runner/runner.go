//go:build unix

package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/runner/config"
)

// Runner runs one instance's jobs against one data directory.
type Runner struct {
	inst     *config.Instance
	data     string
	stateDir string
	latest   string
	tree     string // the Python tree (collectors, core, the bridge)
	python   string
	exe      string // this binary, for implementations: go
	environ  []string
	filter   envFilter
	clock    *Clock
	log      *Logger
	loc      *time.Location
	wall     func() time.Time
	release  string
}

// Options is everything a Runner takes from its process.
type Options struct {
	Instance string
	Data     string
	Tree     string
	Python   string
	Exe      string
	Environ  []string
	Clock    *Clock
	Log      *Logger
	Loc      *time.Location
	Wall     func() time.Time
}

// New loads the instance and prepares the data directory (contract §4: state/runner, its locks, latest/).
func New(o Options) (*Runner, error) {
	instPath, err := absPath(o.Instance, o.Environ)
	if err != nil {
		return nil, err
	}
	inst, err := config.Load(instPath)
	if err != nil {
		return nil, fmt.Errorf("instance %s: %w", instPath, err)
	}
	inst.Path = instPath
	data, err := absPath(o.Data, o.Environ)
	if err != nil {
		return nil, err
	}
	r := &Runner{inst: inst, data: data, stateDir: filepath.Join(data, "state", "runner"),
		latest: filepath.Join(data, "latest"), tree: o.Tree, python: o.Python, exe: o.Exe, environ: o.Environ,
		filter: newEnvFilter(inst.EnvPassthrough), clock: o.Clock, log: o.Log, loc: o.Loc, wall: o.Wall}
	for _, d := range []string{r.stateDir, filepath.Join(r.stateDir, "locks"), r.latest} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, fmt.Errorf("create %s: %w", d, err)
		}
	}
	r.release = readRelease(filepath.Join(o.Tree, "RELEASE"))
	return r, nil
}

var errNoPath = errors.New("path not given")

// absPath is os.path.abspath(os.path.expanduser(p)).
func absPath(p string, environ []string) (string, error) {
	if p == "" {
		return "", errNoPath
	}
	p = expandUser(p, environ)
	a, err := filepath.Abs(p)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", p, err)
	}
	return a, nil
}

// expandUser replaces a leading ~ with $HOME (Python's os.path.expanduser for the current user).
func expandUser(p string, environ []string) string {
	if p != "~" && !strings.HasPrefix(p, "~/") {
		return p
	}
	home := lookup(environ, "HOME")
	if home == "" {
		return p
	}
	return home + p[1:]
}

func lookup(environ []string, key string) string {
	for i := len(environ) - 1; i >= 0; i-- {
		if k, v, ok := strings.Cut(environ[i], "="); ok && k == key {
			return v
		}
	}
	return ""
}

// readRelease is the product release the tree was installed as (RELEASE: version=...), "" in a checkout.
func readRelease(path string) string {
	data, err := readFile(path, 4096)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok && k == "version" {
			return v
		}
	}
	return ""
}

// Tick runs whatever is due (all jobs, or only the named ones), then store-and-forward and pruning (all jobs only),
// then publishes. The tick lock makes an overlapping tick exit at once. Job failures never fail a tick.
func (r *Runner) Tick(ctx context.Context, names []string) {
	lk, err := acquire(filepath.Join(r.stateDir, "locks"), "tick", false)
	if errors.Is(err, errLocked) {
		r.log.Printf("another tick is still running; this one exits")
		return
	}
	if err != nil {
		r.log.Printf("tick lock: %v", err)
		return
	}
	defer r.unlock(lk)
	r.noteWithheld()
	for _, j := range r.selected(names) {
		if ctx.Err() != nil {
			break
		}
		r.tickJob(ctx, j)
	}
	if len(names) == 0 && ctx.Err() == nil {
		r.forward(ctx)
		r.prune()
	}
	r.publishLogged(ctx)
}

func (r *Runner) tickJob(ctx context.Context, j *config.Job) {
	st := r.LoadState(j.Name)
	d := Due(j, st, r.clock.Decision(), r.loc)
	if d.Missed && st.Int("missed_slot", -1) < d.Slot {
		r.countMissed(j.Name, d.Slot, d.Reason)
	}
	if d.HasRun {
		r.execute(ctx, j, &d.Slot)
	}
}

// countMissed records that a slot will never run (RUNNER-D2), once per slot.
func (r *Runner) countMissed(job string, slot int64, why string) {
	st := r.LoadState(job)
	st["missed_slots_total"] = st.Int("missed_slots_total", 0) + 1
	st["missed_slot"] = slot
	if err := r.SaveState(job, st); err != nil {
		r.log.Printf("%s: state: %v", job, err)
		return
	}
	r.log.Printf("%s: slot %s %s", job, time.Unix(slot, 0).In(r.loc).Format("2006-01-02T15:04:05-0700"), why)
}

// Run runs the named jobs now (all when none are named), ignoring the schedule, and returns the highest exit code.
func (r *Runner) Run(ctx context.Context, names []string) int {
	lk, err := acquire(filepath.Join(r.stateDir, "locks"), "tick", false)
	if err == nil { // as the reference: a manual run also holds the tick lock when it can, and runs regardless
		defer r.unlock(lk)
	}
	rc := 0
	for _, j := range r.selected(names) {
		if ctx.Err() != nil {
			break
		}
		if got, ran := r.execute(ctx, j, nil); ran {
			rc = max(rc, got)
		}
	}
	if !r.publishLogged(ctx) {
		rc = max(rc, 1)
	}
	return rc
}

func (r *Runner) selected(names []string) []*config.Job {
	if len(names) == 0 {
		return r.inst.Jobs
	}
	out := make([]*config.Job, 0, len(names))
	for _, n := range names {
		if j, ok := r.inst.Job(n); ok {
			out = append(out, j)
		}
	}
	return out
}

// Unknown returns the names that are not jobs of the instance.
func (r *Runner) Unknown(names []string) []string {
	var bad []string
	for _, n := range names {
		if _, ok := r.inst.Job(n); !ok {
			bad = append(bad, n)
		}
	}
	return bad
}

// noteWithheld logs, once per tick, the names of credential-like variables jobs do not get (never their values),
// so a switch from the Python runner that inherited everything is easy to diagnose.
func (r *Runner) noteWithheld() {
	if names := r.filter.withheldCredentials(r.environ); len(names) > 0 {
		r.log.Printf("environment: not passed to jobs (list in runner.env_passthrough to allow): %s",
			truncate(strings.Join(names, ", "), 300))
	}
}

// unlock releases a lock and logs a failure (the kernel releases it anyway when the process exits).
func (r *Runner) unlock(lk *Lock) {
	if err := lk.Release(); err != nil {
		r.log.Printf("%v", err)
	}
}
