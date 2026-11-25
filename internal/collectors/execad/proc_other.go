//go:build !unix

package execad

import "os/exec"

// setGroup: without process groups the program itself is killed on timeout (exec.CommandContext's default).
func setGroup(*exec.Cmd) {}
