package cli

import (
	"crypto/sha1" // #nosec G505 -- not for security: the runner contract fixes sha1 so every implementation jitters alike
	"encoding/binary"
	"math"
	"strconv"
	"time"

	"github.com/MIERAI/security-platform/internal/pyvalue"
	"github.com/MIERAI/security-platform/internal/runner/config"
	"github.com/MIERAI/security-platform/internal/runner/cron"
)

// lateAfter: a trigger ticks every 5-15 minutes, so a slot not started 15 minutes after its jittered start was
// missed (machine off, broken trigger).
const lateAfter = 15 * 60

// lateSlot returns the oldest scheduled slot after the last finished one (done_slot) whose jittered start is more
// than lateAfter ago: a run the runner should have started and did not (contract cli §2, runner §3: cron in local
// time, jitter sha1("<job>|<slot>")). ok is false when nothing is late or the schedule cannot be read.
func lateSlot(name string, job, st *pyvalue.Map, now float64, loc *time.Location) (int64, bool) {
	done, ok := number(field(st, "done_slot"))
	expr, isText := field(job, "schedule").(string)
	if !ok || !isText || expr == "" || math.IsNaN(done) || math.IsInf(done, 0) {
		return 0, false
	}
	sched, err := cron.Parse(expr)
	if err != nil {
		return 0, false
	}
	jitter, err := config.Duration(field(job, "jitter"))
	if err != nil {
		return 0, false
	}
	slot, ok := sched.Next(int64(done), loc)
	if !ok {
		return 0, false
	}
	start := slot + jitterOffset(name, slot, jitter)
	if now-float64(start) > lateAfter {
		return slot, true
	}
	return 0, false
}

// jitterOffset is the runner's deterministic jitter: int(sha1("<job>|<slot>")[:8], 16) mod jitter (runner §3).
func jitterOffset(job string, slot, jitter int64) int64 {
	if jitter <= 0 {
		return 0
	}
	sum := sha1.Sum([]byte(job + "|" + strconv.FormatInt(slot, 10))) // #nosec G401 -- see the import
	return int64(binary.BigEndian.Uint32(sum[:4])) % jitter
}
