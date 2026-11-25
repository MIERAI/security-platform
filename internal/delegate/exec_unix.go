//go:build unix

package delegate

import (
	"context"
	"fmt"
	"os"
	"syscall"
)

// Replace replaces the sp process with the interpreter (execve). It returns only on failure.
func Replace(_ context.Context, s Spec) (int, error) {
	argv := s.Argv()
	err := syscall.Exec(argv[0], argv, s.Env) // #nosec G204 -- argument vector, no shell; see package doc
	return 0, fmt.Errorf("exec %s: %w", argv[0], err)
}

func exitCode(ps *os.ProcessState) int {
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return ps.ExitCode()
}
