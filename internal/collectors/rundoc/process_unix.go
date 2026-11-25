//go:build unix

package rundoc

import (
	"io/fs"
	"os"
	"os/exec"
	"syscall"
)

// setGroup runs the child in its own process group and kills the whole group when its context ends.
func setGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil || cmd.Process.Pid <= 1 {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}

// signalOf is the signal that ended a process (0 when it exited).
func signalOf(ps *os.ProcessState) int {
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return int(ws.Signal())
	}
	return 0
}

func candidates(p string) []string { return []string{p} }

func executable(fi fs.FileInfo) bool { return fi.Mode().Perm()&0o111 != 0 }
