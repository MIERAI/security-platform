package shim

import (
	"context"

	"github.com/MIERAI/security-platform/internal/collectors/detection"
)

// runDetection is `sp detection ...`: the Go implementation of the detection collector (collectors/detection) (internal/collectors/detection).
func runDetection(ctx context.Context, env Env, args []string) int {
	return detection.Main(ctx, collectorEnv(env), args)
}
