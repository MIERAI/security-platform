//go:build unix

package execadapter

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

// ownGroup starts the command in a new session: on timeout the whole process group is stopped, not only the
// direct child (a profile's children would otherwise keep running and keep the output pipe open).
func ownGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}

func killGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return cmd.Process.Kill()
	}
	return nil
}

// exitStatus is Python's returncode: the exit status, or minus the signal that ended the process.
func exitStatus(ps *os.ProcessState) int {
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return -int(ws.Signal())
	}
	return ps.ExitCode()
}
