//go:build !unix

package delegate

import (
	"context"
	"os"
)

// Replace runs the interpreter as a child process (there is no exec here) and returns its exit code.
func Replace(ctx context.Context, s Spec) (int, error) {
	return Child(ctx, s)
}

func exitCode(ps *os.ProcessState) int {
	return ps.ExitCode()
}
