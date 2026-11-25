package shim

import (
	"context"

	"github.com/MIERAI/security-platform/internal/collectors/codehostgitea"
)

// runCodehostGitea is `sp codehost-gitea ...`: the Go implementation of the codehost-gitea collector (collectors/codehost-gitea) (internal/collectors/codehostgitea).
func runCodehostGitea(ctx context.Context, env Env, args []string) int {
	return codehostgitea.Main(ctx, collectorEnv(env), args, env.Stdout)
}
