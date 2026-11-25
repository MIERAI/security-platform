//go:build unix

package runner

import (
	"crypto/sha1" // #nosec G505 -- not for security: the contract fixes sha1 so every implementation jitters alike
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"github.com/MIERAI/security-platform/internal/runner/config"
)

// Reasons of contract §3 / §5.
const (
	ReasonDue       = "due"
	ReasonDone      = "done"
	ReasonMissed    = "missed (older than max_delay)"
	ReasonExhausted = "retries exhausted"
	ReasonWaiting   = "waiting to retry"
	ReasonNoSlot    = "no slot"
)

// Offset is the deterministic jitter of a job's slot: int(sha1("<job>|<slot>")[:8], 16) mod jitter (0 without
// jitter).
func Offset(job string, slot, jitter int64) int64 {
	if jitter <= 0 {
		return 0
	}
	sum := sha1.Sum([]byte(job + "|" + strconv.FormatInt(slot, 10))) // #nosec G401 -- see the import
	hexed := hex.EncodeToString(sum[:])
	b, err := hex.DecodeString(hexed[:8])
	if err != nil {
		return 0 // unreachable: hex.EncodeToString wrote it
	}
	return int64(binary.BigEndian.Uint32(b)) % jitter
}

// Decision is the outcome of §3 for one job at one instant.
type Decision struct {
	Slot   int64
	HasRun bool // the job should run now for Slot
	Reason string
	// Missed is set when Slot will never run because of max_delay (counted once per slot, RUNNER-D2).
	Missed bool
}

// Due applies contract §3 to a job and its state at now (epoch seconds).
func Due(j *config.Job, st State, now float64, loc *time.Location) Decision {
	n := int64(now)
	slot, ok := j.Schedule.Prev(n, loc)
	if !ok {
		return Decision{Reason: ReasonNoSlot}
	}
	if now < float64(slot+Offset(j.Name, slot, j.Jitter)) { // this slot's jittered start is still ahead
		if slot, ok = j.Schedule.Prev(slot-60, loc); !ok {
			return Decision{Reason: ReasonNoSlot}
		}
	}
	if st.Has("done_slot") && st.Int("done_slot", -1) >= slot {
		return Decision{Slot: slot, Reason: ReasonDone}
	}
	if j.MaxDelay != 0 && now-float64(slot) > float64(j.MaxDelay) {
		return Decision{Slot: slot, Reason: ReasonMissed, Missed: true}
	}
	if st.Has("slot") && st.Int("slot", 0) == slot { // attempted this slot already and failed
		attempts := st.Int("attempts", 0)
		if attempts > j.Retries {
			return Decision{Slot: slot, Reason: ReasonExhausted}
		}
		last, _ := st.Float("last_attempt") // absent: 0, as the reference's default
		if now < last+float64(j.RetryDelay) {
			return Decision{Slot: slot, Reason: ReasonWaiting}
		}
		return Decision{Slot: slot, HasRun: true, Reason: fmt.Sprintf("retry %s", retryCount(st))}
	}
	return Decision{Slot: slot, HasRun: true, Reason: ReasonDue}
}

// retryCount is the attempts field as the reference prints it in "retry <n>" (Python's str of the value).
func retryCount(st State) string {
	return config.Str(fromJSON(st["attempts"]))
}

// pending reports the slot that is due and not done yet (RUNNER-D2 / CLI-D1): due, a retry, or waiting to retry.
func pending(d Decision) (int64, bool) {
	switch {
	case d.HasRun, d.Reason == ReasonWaiting:
		return d.Slot, true
	default:
		return 0, false
	}
}
