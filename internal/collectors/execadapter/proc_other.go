//go:build !unix

package execadapter

import (
	"os"
	"os/exec"
)

// ownGroup: no process groups here; a timeout stops the direct child.
func ownGroup(*exec.Cmd) {}

func killGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return cmd.Process.Kill()
}

func exitStatus(ps *os.ProcessState) int { return ps.ExitCode() }
