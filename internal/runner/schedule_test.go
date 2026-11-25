//go:build unix

package runner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/MIERAI/security-platform/internal/runner/config"
	"github.com/MIERAI/security-platform/internal/runner/cron"
)

func job(t *testing.T, name, schedule string, mut func(*config.Job)) *config.Job {
	t.Helper()
	s, err := cron.Parse(schedule)
	if err != nil {
		t.Fatal(err)
	}
	j := &config.Job{Name: name, Type: config.TypeCommand, Schedule: s, RetryDelay: 900}
	if mut != nil {
		mut(j)
	}
	return j
}

// TestDue covers contract §3 (the reference's tests/test_runner.py Due cases and every reason).
func TestDue(t *testing.T) {
	t.Parallel()
	slot := epoch(t, "2026-01-05T03:30:00Z")
	now := epoch(t, "2026-01-05T12:00:00Z")
	retry := func(j *config.Job) { j.Retries, j.RetryDelay = 1, 1200 }
	tests := []struct {
		name   string
		job    *config.Job
		st     State
		now    float64
		reason string
		run    bool
		slot   float64
	}{
		{"missed slot is caught up once", job(t, "a", "30 3 * * *", retry), NewState("a"), now, ReasonDue, true, slot},
		{"older than max_delay", job(t, "b", "30 3 * * *", func(j *config.Job) { j.MaxDelay = 3 * 3600 }), NewState("b"), now, ReasonMissed, false, slot},
		{"within max_delay", job(t, "b", "30 3 * * *", func(j *config.Job) { j.MaxDelay = 3 * 3600 }), NewState("b"),
			epoch(t, "2026-01-05T04:00:00Z"), ReasonDue, true, slot},
		{"done", job(t, "a", "30 3 * * *", nil), State{"done_slot": int64(slot)}, now, ReasonDone, false, slot},
		{"waiting to retry", job(t, "a", "30 3 * * *", retry), State{"slot": int64(slot), "attempts": int64(1),
			"last_attempt": int64(now)}, now + 600, ReasonWaiting, false, slot},
		{"retry", job(t, "a", "30 3 * * *", retry), State{"slot": int64(1767583800), "attempts": int64(1),
			"last_attempt": int64(now)}, now + 1300, "retry 1", true, slot},
		{"retries exhausted", job(t, "a", "30 3 * * *", retry), State{"slot": int64(slot), "attempts": int64(2),
			"last_attempt": int64(now)}, now + 1300, ReasonExhausted, false, slot},
		{"no slot", job(t, "n", "0 0 31 2 *", nil), NewState("n"), now, ReasonNoSlot, false, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d := Due(tt.job, tt.st, tt.now, time.UTC)
			if d.Reason != tt.reason || d.HasRun != tt.run || float64(d.Slot) != tt.slot {
				t.Errorf("Due = %+v, want %s run=%v slot=%v", d, tt.reason, tt.run, tt.slot)
			}
		})
	}
}

func TestDueJitter(t *testing.T) {
	t.Parallel()
	j := job(t, "c", "30 3 * * *", func(j *config.Job) { j.Jitter = 3600 })
	slot := int64(epoch(t, "2026-01-05T03:30:00Z"))
	off := Offset("c", slot, 3600)
	if d := Due(j, NewState("c"), float64(slot+off-60), time.UTC); d.Slot != slot-86400 {
		t.Errorf("before its jitter: slot %d, want the previous day's", d.Slot)
	}
	if d := Due(j, NewState("c"), float64(slot+off), time.UTC); d.Slot != slot || !d.HasRun {
		t.Errorf("at its jitter: %+v", d)
	}
}

// TestOffsetMatchesReference: sha1("<job>|<slot>") jitter, bit for bit as the Python runner (testdata/reference.json).
func TestOffsetMatchesReference(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("testdata", "reference.json"))
	if err != nil {
		t.Fatal(err)
	}
	var ref struct {
		Offset []struct {
			Job    string `json:"job"`
			Slot   int64  `json:"slot"`
			Jitter int64  `json:"jitter"`
			Offset int64  `json:"offset"`
		} `json:"offset"`
	}
	if err := json.Unmarshal(data, &ref); err != nil {
		t.Fatal(err)
	}
	for _, c := range ref.Offset {
		if got := Offset(c.Job, c.Slot, c.Jitter); got != c.Offset {
			t.Errorf("Offset(%s, %d, %d) = %d, want %d", c.Job, c.Slot, c.Jitter, got, c.Offset)
		}
	}
	if Offset("x", 1, 0) != 0 {
		t.Error("no jitter, no offset")
	}
}

func TestPending(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		d  Decision
		ok bool
	}{{Decision{Slot: 5, HasRun: true}, true}, {Decision{Slot: 5, Reason: ReasonWaiting}, true},
		{Decision{Slot: 5, Reason: ReasonDone}, false}, {Decision{Slot: 5, Reason: ReasonMissed, Missed: true}, false}} {
		if _, ok := pending(tt.d); ok != tt.ok {
			t.Errorf("pending(%+v) = %v", tt.d, ok)
		}
	}
}
