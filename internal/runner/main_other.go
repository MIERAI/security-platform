//go:build !unix

package runner

import (
	"context"
	"fmt"
)

// Main reports that the runner needs a Unix-like system: it relies on process groups and sessions (a timed-out
// job is killed with its whole group), on flock(2) locks shared with the Python runner, and on POSIX signals. The
// Python runner has the same requirement (fcntl). On Windows run it under WSL.
func Main(_ context.Context, env Env) int {
	_, _ = fmt.Fprintln(env.Stderr, "sp runner: needs a Unix-like system (process groups, flock); on Windows use WSL") // exit status says it
	return ExitNoConfig
}
