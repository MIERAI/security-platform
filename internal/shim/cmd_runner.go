package shim

import (
	"context"
	"time"

	"github.com/MIERAI/security-platform/internal/runner"
)

// runRunner is `sp runner ...`: the Go runner (internal/runner, docs/runner.md).
func runRunner(ctx context.Context, env Env, args []string) int {
	return runner.Main(ctx, runner.Env{Args: args, Stdout: env.Stdout, Stderr: env.Stderr, Getenv: env.Getenv,
		Environ: env.Environ, Executable: env.Executable, Wall: time.Now})
}
