//go:build unix

package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// killGrace is how long a job has between SIGTERM and SIGKILL (contract §4).
const killGrace = 30 * time.Second

// rcTimeout is the exit code recorded for a job killed after its timeout.
const rcTimeout = 124

// spawnSpec is one child process of a job.
type spawnSpec struct {
	argv    []string
	env     []string
	timeout int64  // seconds; 0 = none (as the reference)
	logPath string // stdout and stderr are appended here, unbuffered: partial output survives a kill
	job     string // records the process group for stale-run detection when set
}

// spawn runs a job's program in its own session and process group and returns its exit code (-N when signal N
// ended it, as the reference reports it). After the timeout, or when the runner is stopped, the whole group gets
// SIGTERM, then SIGKILL after killGrace; that is recorded as 124 and noted in the log.
func (r *Runner) spawn(ctx context.Context, s spawnSpec) (int, error) {
	lf, err := os.OpenFile(s.logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600) // #nosec G304 -- run directory
	if err != nil {
		return 0, fmt.Errorf("open job log: %w", err)
	}
	defer func() {
		if cerr := lf.Close(); cerr != nil {
			r.log.Printf("%s: job log: %v", s.job, cerr)
		}
	}()
	jobCtx, cancel := context.WithCancel(ctx)
	if s.timeout > 0 {
		jobCtx, cancel = context.WithTimeout(ctx, time.Duration(s.timeout)*time.Second)
	}
	defer cancel()
	prog, err := lookPath(s.argv[0], s.env)
	if err != nil {
		return 0, err
	}
	cmd := exec.CommandContext(jobCtx, prog, s.argv[1:]...) // #nosec G204 -- argument vector from the instance, no shell
	cmd.Env, cmd.Stdout, cmd.Stderr = s.env, lf, lf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Cancel = func() error { return killGroup(cmd.Process.Pid, syscall.SIGTERM) }
	cmd.WaitDelay = killGrace
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("start %s: %w", filepath.Base(s.argv[0]), err)
	}
	pgid := cmd.Process.Pid
	r.recordOwner(s, pgid)
	werr := cmd.Wait()
	r.clearOwner(s.job)
	if jobCtx.Err() != nil {
		if kerr := killGroup(pgid, syscall.SIGKILL); kerr != nil { // whatever survived SIGTERM and the grace period
			r.log.Printf("%s: %v", s.job, kerr)
		}
		why := fmt.Sprintf("killed after timeout %ds", s.timeout)
		if ctx.Err() != nil {
			why = "killed: the runner was stopped"
		}
		_, _ = fmt.Fprintf(lf, "\nrunner: %s\n", why) // best effort: the state records 124 anyway
		return rcTimeout, nil
	}
	return exitStatus(cmd, werr)
}

func exitStatus(cmd *exec.Cmd, werr error) (int, error) {
	var exitErr *exec.ExitError
	if werr != nil && !errors.As(werr, &exitErr) {
		return 0, fmt.Errorf("wait: %w", werr)
	}
	ps := cmd.ProcessState
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return -int(ws.Signal()), nil
	}
	return ps.ExitCode(), nil
}

// owner is what staleRun reads of locks/<job>.owner.json, the record of a running job's process group (the file
// also names the job's pid and the runner's, for people). started is wall-clock time: it is about real processes,
// not the schedule.
type owner struct {
	pgid             int
	started, timeout int64
}

func (r *Runner) ownerPath(job string) string {
	return filepath.Join(r.stateDir, "locks", job+".owner.json")
}

func (r *Runner) recordOwner(s spawnSpec, pgid int) {
	if s.job == "" {
		return
	}
	o := map[string]any{"pid": int64(pgid), "pgid": int64(pgid), "started": r.wall().Unix(), "timeout": s.timeout,
		"runner_pid": int64(os.Getpid())}
	if err := writeJSON(r.ownerPath(s.job), o); err != nil {
		r.log.Printf("%s: cannot record the running process group: %v", s.job, err)
	}
}

func (r *Runner) clearOwner(job string) {
	if job != "" {
		if err := removeIfExists(r.ownerPath(job)); err != nil {
			r.log.Printf("%s: %v", job, err)
		}
	}
}

// staleRun checks the record a previous run of the job left behind. The job lock alone cannot see a run whose
// runner died (killed, crashed, host suspended) while its job's process group lives on. Such an orphan still
// within its time limit keeps the job from starting again (true: skip); one beyond its limit and the grace period
// is killed; a record whose group is gone is stale and removed.
func (r *Runner) staleRun(job string) bool {
	m, ok := readJSONObject(r.ownerPath(job))
	if !ok {
		return false
	}
	o := owner{pgid: int(State(m).Int("pgid", 0)), started: State(m).Int("started", 0), timeout: State(m).Int("timeout", 0)}
	if !groupAlive(o.pgid) {
		r.clearOwner(job)
		return false
	}
	age := r.wall().Unix() - o.started
	if o.timeout == 0 || age < o.timeout+int64(killGrace/time.Second) {
		r.log.Printf("%s: a previous run (process group %d, started %ds ago) is still running without its runner; skipped",
			job, o.pgid, age)
		return true
	}
	r.log.Printf("%s: killing the orphaned process group %d of a previous run (%ds old, timeout %ds)", job, o.pgid, age, o.timeout)
	if err := killGroup(o.pgid, syscall.SIGKILL); err != nil {
		r.log.Printf("%s: %v", job, err)
	}
	r.clearOwner(job)
	return false
}

// errNotFound is returned when a program name is not found on the job's PATH.
var errNotFound = errors.New("not found on PATH")

// lookPath resolves a program name without a slash on the PATH of the job's environment (as the reference's
// Popen with env= does), never through a relative PATH entry.
func lookPath(name string, env []string) (string, error) {
	if strings.Contains(name, "/") {
		return name, nil
	}
	for _, dir := range filepath.SplitList(lookup(env, "PATH")) {
		if !filepath.IsAbs(dir) {
			continue
		}
		p := filepath.Join(dir, name)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("start %s: %w", name, errNotFound)
}
