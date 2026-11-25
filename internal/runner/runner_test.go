//go:build unix

package runner

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestFailingJobRetriesThenGivesUpAndCountsTheSlot: retries at least retry_delay apart on the --now clock
// (RUNNER-D1), then the slot is given up and counted as missed (RUNNER-D2), exported with the job's series.
func TestFailingJobRetriesThenGivesUpAndCountsTheSlot(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	fail := f.script(t, "fail.sh", "echo partial output; exit 3\n")
	writeTestJSON(t, f.instance, map[string]any{"name": "t", "scorecard": map[string]any{"enabled": false},
		"runner": map[string]any{"jobs": map[string]any{"flaky": map[string]any{"type": "command", "argv": []string{fail},
			"schedule": "30 3 * * *", "retries": 1, "retry_delay": "20m"}}}})
	ctx := context.Background()
	steps := []struct {
		at       string
		runs     int64
		attempts int64
	}{{"2030-01-07T03:30:00Z", 1, 1}, {"2030-01-07T03:35:00Z", 1, 1}, {"2030-01-07T03:51:00Z", 2, 2},
		{"2030-01-07T04:30:00Z", 2, 2}}
	for _, s := range steps {
		r := f.runner(t, epoch(t, s.at))
		r.Tick(ctx, nil)
		st := r.LoadState("flaky")
		if st.Int("runs_total", 0) != s.runs || st.Int("attempts", 0) != s.attempts || st.Int("last_rc", 0) != 3 {
			t.Fatalf("at %s: state %v", s.at, st)
		}
	}
	r := f.runner(t, epoch(t, "2030-01-07T04:30:00Z"))
	st := r.LoadState("flaky")
	slot := int64(epoch(t, "2030-01-07T03:30:00Z"))
	if st.Int("done_slot", 0) != slot || st.Int("missed_slots_total", 0) != 1 || st.Int("missed_slot", 0) != slot {
		t.Errorf("after giving up: %v", st)
	}
	if st.Int("last_attempt", 0) != int64(epoch(t, "2030-01-07T03:51:00Z")) {
		t.Errorf("last_attempt %v is not on the --now clock", st["last_attempt"])
	}
	text := r.MetricsText()
	for _, want := range []string{`security_runner_job_missed_slots_total{job="flaky",site="hub"} 1`,
		`security_runner_job_failures_total{job="flaky",site="hub"} 2`, `security_runner_tick_max_gap_seconds{site="hub"} 3600`} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics lack %s:\n%s", want, text)
		}
	}
	logs, _ := filepath.Glob(filepath.Join(f.data, "runs", "2030-01-07", "*-flaky", "flaky.log"))
	if len(logs) != 2 {
		t.Errorf("run logs %v, want two runs", logs)
	}
}

func TestMaxDelayCountsTheSlotOnce(t *testing.T) {
	t.Parallel()
	f := newFixture(t, map[string]any{"jobs": map[string]any{"nightly": map[string]any{"type": "command",
		"argv": []string{"true"}, "schedule": "30 3 * * *", "max_delay": "3h"}}})
	for _, at := range []string{"2030-01-07T12:00:00Z", "2030-01-07T12:15:00Z"} {
		f.runner(t, epoch(t, at)).Tick(context.Background(), nil)
	}
	r := f.runner(t, epoch(t, "2030-01-07T12:15:00Z"))
	if st := r.LoadState("nightly"); st.Int("missed_slots_total", 0) != 1 || st.Int("runs_total", 0) != 0 {
		t.Errorf("state %v: want one missed slot and no run", st)
	}
	if !strings.Contains(f.log.String(), "nightly: slot 2030-01-07T03:30:00+0000 missed (older than max_delay)") {
		t.Errorf("log:\n%s", f.log)
	}
}

func TestPendingSlotIsExported(t *testing.T) {
	t.Parallel()
	f := newFixture(t, map[string]any{"jobs": map[string]any{"a": map[string]any{"type": "command",
		"argv": []string{"true"}, "schedule": "0 * * * *"}}})
	r := f.runner(t, epoch(t, "2030-01-07T12:30:00Z"))
	want := `security_runner_job_pending_slot_timestamp_seconds{job="a",site="hub"} ` +
		strconv.FormatInt(int64(epoch(t, "2030-01-07T12:00:00Z")), 10)
	if !strings.Contains(r.MetricsText(), want) {
		t.Errorf("no pending slot before the tick:\n%s", r.MetricsText())
	}
	r.Tick(context.Background(), nil)
	if strings.Contains(r.MetricsText(), "pending_slot") {
		t.Error("pending slot still exported after the run")
	}
}

// TestTimeoutKillsTheProcessGroup: the job and the background process it started both die; the output written
// before the kill stays in the run directory; the result is 124.
func TestTimeoutKillsTheProcessGroup(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	pidFile := filepath.Join(f.dir, "child.pid")
	slow := f.script(t, "slow.sh", "sleep 60 &\necho $! > "+pidFile+"\necho started\nwait\n")
	writeTestJSON(t, f.instance, map[string]any{"scorecard": map[string]any{"enabled": false}, "runner": map[string]any{
		"jobs": map[string]any{"slow": map[string]any{"type": "command", "argv": []string{slow}, "schedule": "0 * * * *",
			"timeout": "4s"}}}}) // long enough for a loaded test machine to start the script
	r := f.runner(t, epoch(t, "2030-01-07T12:30:00Z"))
	start := time.Now()
	r.Tick(context.Background(), nil)
	if el := time.Since(start); el > 40*time.Second {
		t.Errorf("took %v", el)
	}
	if st := r.LoadState("slow"); st.Int("last_rc", 0) != rcTimeout {
		t.Fatalf("state %v", st)
	}
	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	if pid > 0 && !gone(pid, 10*time.Second) {
		t.Errorf("the job's background process %d survived", pid)
	}
	logs, _ := filepath.Glob(filepath.Join(f.data, "runs", "*", "*-slow", "slow.log"))
	if len(logs) != 1 {
		t.Fatalf("logs %v", logs)
	}
	out, _ := os.ReadFile(logs[0])
	if !strings.Contains(string(out), "started") || !strings.Contains(string(out), "runner: killed after timeout 4s") {
		t.Errorf("log %q", out)
	}
	if _, err := os.Stat(r.ownerPath("slow")); !os.IsNotExist(err) {
		t.Error("the owner record of a finished run remains")
	}
}

func TestLockedJobIsSkipped(t *testing.T) {
	// not parallel: a process forked by a parallel test holds a copy of the lock until it execs
	f := newFixture(t, map[string]any{"jobs": map[string]any{"a": map[string]any{"type": "command",
		"argv": []string{"true"}, "schedule": "0 * * * *"}}})
	r := f.runner(t, epoch(t, "2030-01-07T12:30:00Z"))
	lk, err := acquire(filepath.Join(r.stateDir, "locks"), "a", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acquire(filepath.Join(r.stateDir, "locks"), "a", false); !errors.Is(err, errLocked) {
		t.Errorf("second lock: %v", err)
	}
	if _, ran := r.execute(context.Background(), r.inst.Jobs[0], nil); ran {
		t.Error("ran while locked")
	}
	if err := lk.Release(); err != nil {
		t.Fatal(err)
	}
	if rc, ran := r.execute(context.Background(), r.inst.Jobs[0], nil); !ran || rc != 1 {
		t.Errorf("after release: rc=%d ran=%v (exit 0 without a document is 1): %v", rc, ran, r.LoadState("a"))
	}
	if !strings.Contains(f.log.String(), "a: already running (lock held), skipped") {
		t.Errorf("log:\n%s", f.log)
	}
}

// TestOrphanedRunIsNotStartedTwice: a run whose runner died while its process group lives on blocks the job
// within its timeout, and is killed after it.
func TestOrphanedRunIsNotStartedTwice(t *testing.T) {
	// not parallel: a process forked by a parallel test holds a copy of the lock until it execs
	f := newFixture(t, map[string]any{"jobs": map[string]any{"a": map[string]any{"type": "command",
		"argv": []string{"true"}, "schedule": "0 * * * *", "timeout": "10m"}}})
	r := f.runner(t, epoch(t, "2030-01-07T12:30:00Z"))
	orphan := exec.Command("sleep", "60")
	orphan.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := orphan.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- orphan.Wait() }()
	pg := int64(orphan.Process.Pid)
	t.Cleanup(func() {
		if err := killGroup(int(pg), syscall.SIGKILL); err != nil {
			t.Log(err)
		}
	})
	writeTestJSON(t, r.ownerPath("a"), map[string]any{"pgid": pg, "started": time.Now().Unix(), "timeout": 600})
	if _, ran := r.execute(context.Background(), r.inst.Jobs[0], nil); ran {
		t.Fatal("started while an orphaned run is alive")
	}
	writeTestJSON(t, r.ownerPath("a"), map[string]any{"pgid": pg, "started": time.Now().Unix() - 3600, "timeout": 600})
	if _, ran := r.execute(context.Background(), r.inst.Jobs[0], nil); !ran {
		t.Fatalf("an orphan beyond its timeout still blocks the job:\n%s", f.log)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Error("the orphan exited normally instead of being killed")
		}
	case <-time.After(10 * time.Second):
		t.Error("the orphan was not killed")
	}
}

func TestStatusIsThePythonJSON(t *testing.T) {
	t.Parallel()
	f := newFixture(t, map[string]any{"jobs": map[string]any{"b": map[string]any{"type": "command",
		"argv": []string{"true"}, "schedule": "0 * * * *"}, "a": map[string]any{"type": "command",
		"argv": []string{"true"}, "schedule": "30 3 * * *", "max_delay": "1h"}}})
	r := f.runner(t, epoch(t, "2030-01-07T12:30:00Z"))
	out, err := r.Status()
	if err != nil {
		t.Fatal(err)
	}
	want := `{
 "a": {
  "due": "missed (older than max_delay)",
  "failures_total": 0,
  "job": "a",
  "runs_total": 0,
  "schedule": "30 3 * * *",
  "schema": "security-platform/runner-state/v1"
 },
 "b": {
  "due": "due",
  "failures_total": 0,
  "job": "b",
  "runs_total": 0,
  "schedule": "0 * * * *",
  "schema": "security-platform/runner-state/v1"
 }
}`
	if string(out) != want {
		t.Errorf("status =\n%s\nwant\n%s", out, want)
	}
}

// TestStateFileFormat: what the Go runner writes is byte for byte what Python's json.dump(st, indent=1,
// sort_keys=True) writes, and unknown fields of another implementation survive.
func TestStateFileFormat(t *testing.T) {
	t.Parallel()
	f := newFixture(t, map[string]any{})
	r := f.runner(t, 0)
	st := r.LoadState("x")
	st["last_duration"], st["last_note"], st["pushed"] = 0.0, "é ok", map[string]any{"exceptions": "ab"}
	if err := r.SaveState("x", st); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(r.statePath("x"))
	if err != nil {
		t.Fatal(err)
	}
	want := `{
 "failures_total": 0,
 "job": "x",
 "last_duration": 0.0,
 "last_note": "\u00e9 ok",
 "pushed": {
  "exceptions": "ab"
 },
 "runs_total": 0,
 "schema": "security-platform/runner-state/v1"
}`
	if string(got) != want {
		t.Errorf("state file =\n%s\nwant\n%s", got, want)
	}
	if fi, err := os.Stat(r.statePath("x")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, %v", fi.Mode(), err)
	}
}

func TestPrune(t *testing.T) {
	t.Parallel()
	f := newFixture(t, map[string]any{"retention": "2d"})
	for _, d := range []string{"2030-01-01", "2030-01-05", "2030-01-07", "notadate"} {
		if err := os.MkdirAll(filepath.Join(f.data, "runs", d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	f.runner(t, epoch(t, "2030-01-07T12:00:00Z")).Tick(context.Background(), nil)
	left, _ := filepath.Glob(filepath.Join(f.data, "runs", "*"))
	var names []string
	for _, l := range left {
		names = append(names, filepath.Base(l))
	}
	if strings.Join(names, ",") != "2030-01-05,2030-01-07,notadate" {
		t.Errorf("left %v", names)
	}
}

func TestRunDirIsFresh(t *testing.T) {
	t.Parallel()
	f := newFixture(t, map[string]any{})
	r := f.runner(t, epoch(t, "2030-01-07T12:00:00Z"))
	r.clock = NewClock(epoch(t, "2030-01-07T12:00:00Z"), func() time.Time { return time.Unix(0, 0) }) // frozen
	a, err := r.makeRunDir("j")
	if err != nil {
		t.Fatal(err)
	}
	b, err := r.makeRunDir("j")
	if err != nil {
		t.Fatal(err)
	}
	if a == b || filepath.Base(b) != filepath.Base(a)+".2" || !strings.HasPrefix(r.rel(a), "runs/2030-01-07/1200") {
		t.Errorf("run dirs %s, %s", r.rel(a), r.rel(b))
	}
}

// gone waits until a process no longer runs: it does not exist, or it is a zombie its new parent has not reaped
// yet (an orphaned child of the killed job is reparented, and reaping takes a moment on some systems).
func gone(pid int, limit time.Duration) bool {
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if syscall.Kill(pid, 0) != nil {
			return true
		}
		if stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat"); err == nil {
			if _, rest, ok := strings.Cut(string(stat), ") "); ok && strings.HasPrefix(rest, "Z") {
				return true
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}
