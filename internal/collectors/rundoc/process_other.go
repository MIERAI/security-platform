//go:build !unix

package rundoc

import (
	"io/fs"
	"os/exec"
)

// setGroup: without process groups, the child alone is killed when its context ends (exec's default).
func setGroup(*exec.Cmd) {}

func candidates(p string) []string { return []string{p, p + ".exe", p + ".bat", p + ".cmd"} }

func executable(fs.FileInfo) bool { return true }
