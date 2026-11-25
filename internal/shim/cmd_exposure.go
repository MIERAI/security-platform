package shim

import (
	"context"

	"github.com/MIERAI/security-platform/internal/collectors/exposure"
)

// runExposure is `sp exposure ...`: the Go implementation of the exposure collector (collectors/exposure) (internal/collectors/exposure).
func runExposure(ctx context.Context, env Env, args []string) int {
	return exposure.Main(ctx, collectorEnv(env), args)
}
