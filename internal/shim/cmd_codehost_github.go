package shim

import (
	"context"

	"github.com/MIERAI/security-platform/internal/collectors/codehostgithub"
)

// runCodehostGitHub is `sp codehost-github ...`: the Go implementation of the codehost-github collector (collectors/codehost-github) (internal/collectors/codehostgithub).
func runCodehostGitHub(ctx context.Context, env Env, args []string) int {
	return codehostgithub.Main(ctx, collectorEnv(env), args, env.Stdout)
}
