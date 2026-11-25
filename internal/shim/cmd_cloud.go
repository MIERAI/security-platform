package shim

import (
	"context"
	"runtime"

	cloudcollector "github.com/MIERAI/security-platform/internal/collectors/cloud"
)

// runCloud is `sp cloud ...`: the Go implementation of the cloud collector and its credential callbacks
// (internal/collectors/cloud, docs/cloud.md).
func runCloud(ctx context.Context, env Env, args []string) int {
	return cloudcollector.Main(ctx, args, cloudcollector.Env{Getenv: env.Getenv, Environ: env.Environ,
		Stderr: env.Stderr, Executable: env.Executable, GOOS: runtime.GOOS}, env.Stdout)
}
