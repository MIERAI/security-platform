//go:build unix

package runner

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/MIERAI/security-platform/internal/runner/config"
)

// rcInternal is recorded when the runner itself fails while running a job (contract §4).
const rcInternal = 70

// execute runs one job under its lock and records the result (contract §4 "State"). slot is nil for a manual
// run. It returns the job's exit code and whether it ran at all (false: the lock was held).
func (r *Runner) execute(ctx context.Context, j *config.Job, slot *int64) (int, bool) {
	lk, err := acquire(filepath.Join(r.stateDir, "locks"), j.Name, false)
	if err != nil {
		if errors.Is(err, errLocked) {
			r.log.Printf("%s: already running (lock held), skipped", j.Name)
		} else {
			r.log.Printf("%s: %v, skipped", j.Name, err)
		}
		return 0, false
	}
	defer r.unlock(lk)
	if r.staleRun(j.Name) {
		return 0, false
	}
	started := time.Now()
	if err = r.recordStart(j.Name, slot); err != nil {
		r.log.Printf("%s: state: %v", j.Name, err)
	}
	runDir, err := r.makeRunDir(j.Name)
	var rc int
	var note string
	if err != nil {
		rc, note = rcInternal, failureNote(err)
	} else {
		r.log.Printf("%s: start (%s) -> %s", j.Name, j.Type, r.rel(runDir))
		rc, note = r.runJob(ctx, j, runDir)
	}
	dur := time.Since(started).Seconds()
	r.recordEnd(ctx, j, slot, result{rc: rc, note: note, dur: dur, runDir: runDir})
	r.log.Printf("%s: rc=%d in %.0fs: %s", j.Name, rc, dur, truncate(note, 200))
	return rc, true
}

func (r *Runner) recordStart(job string, slot *int64) error {
	st := r.LoadState(job)
	if slot != nil {
		if !st.Has("slot") || st.Int("slot", 0) != *slot {
			st["slot"], st["attempts"] = *slot, int64(0)
		}
		st["attempts"] = st.Int("attempts", 0) + 1
	}
	st["last_attempt"] = int64(r.clock.Now())
	return r.SaveState(job, st)
}

type result struct {
	rc     int
	note   string
	dur    float64
	runDir string
}

func (r *Runner) recordEnd(ctx context.Context, j *config.Job, slot *int64, res result) {
	st := r.LoadState(j.Name)
	st["last_rc"] = int64(res.rc)
	st["last_duration"] = math.Round(res.dur*10) / 10
	st["last_note"] = truncate(res.note, 500)
	st["runs_total"] = st.Int("runs_total", 0) + 1
	st["runner_version"] = Version
	if res.runDir != "" {
		st["last_run_dir"] = r.rel(res.runDir)
	}
	switch res.rc {
	case 0:
		st["last_success"] = int64(r.clock.Now())
		if slot != nil {
			st["done_slot"] = *slot
		}
	default:
		st["failures_total"] = st.Int("failures_total", 0) + 1
		if slot != nil && st.Int("attempts", 0) > j.Retries {
			st["done_slot"] = *slot // give up on this slot; the next slot tries again
			st["missed_slots_total"] = st.Int("missed_slots_total", 0) + 1
			st["missed_slot"] = *slot
		}
	}
	if err := r.SaveState(j.Name, st); err != nil {
		r.log.Printf("%s: state: %v", j.Name, err)
	}
	r.sendState(ctx, j.Name)
}

// rel is a path relative to the data directory, with forward slashes.
func (r *Runner) rel(p string) string {
	rel, err := filepath.Rel(r.data, p)
	if err != nil {
		return p
	}
	return filepath.ToSlash(rel)
}

// makeRunDir creates runs/<YYYY-MM-DD>/<HHMMSS>-<job>/ from the runner's clock, fresh for every run: when two
// runs fall into the same second (possible with --now), the later one gets a numbered suffix (.2, .3, ...).
func (r *Runner) makeRunDir(job string) (string, error) {
	t := r.clock.Time(r.loc)
	parent := filepath.Join(r.data, "runs", t.Format("2006-01-02"))
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", fmt.Errorf("create run directory: %w", err)
	}
	base := t.Format("150405") + "-" + job
	for i := 1; i < 1000; i++ {
		name := base
		if i > 1 {
			name += "." + strconv.Itoa(i)
		}
		d := filepath.Join(parent, name)
		err := os.Mkdir(d, 0o700)
		if err == nil {
			return d, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("create run directory: %w", err)
		}
	}
	return "", fmt.Errorf("create run directory: %w", os.ErrExist)
}

// failureNote is the note of an internal error, in the reference's "<kind>: <message>" form.
func failureNote(err error) string {
	return "RunnerError: " + truncate(err.Error(), 200)
}
