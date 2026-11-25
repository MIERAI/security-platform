//go:build unix

package notifier

import (
	"errors"
	"os/exec"
	"syscall"
	"time"
)

// ownProcessGroup starts the command in a new session and, at the deadline, kills its whole process group: a
// shell's children would otherwise keep running and keep the stderr pipe open.
func ownProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil || cmd.Process.Pid <= 1 {
			return nil
		}
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			return err
		}
		return nil
	}
	cmd.WaitDelay = 5 * time.Second
}
