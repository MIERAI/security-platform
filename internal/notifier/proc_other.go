//go:build !unix

package notifier

import (
	"os/exec"
	"time"
)

// ownProcessGroup: without process groups the command itself is killed at the deadline.
func ownProcessGroup(cmd *exec.Cmd) {
	cmd.WaitDelay = 5 * time.Second
}
