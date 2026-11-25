//go:build unix

package execad

import (
	"os/exec"
	"syscall"
)

// setGroup starts the program in its own process group and makes a cancel (timeout) kill the whole group, so a
// child's own children cannot keep running or keep the output pipes open.
func setGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
