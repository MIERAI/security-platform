//go:build unix

package rundoc

import (
	"io/fs"
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

func candidates(p string) []string { return []string{p} }

func executable(fi fs.FileInfo) bool { return fi.Mode().Perm()&0o111 != 0 }
