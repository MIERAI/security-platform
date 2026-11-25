package shim

import (
	"context"

	"github.com/MIERAI/security-platform/internal/events"
)

// runEvents is `sp events ...`: the Go implementation of the events shipper (events/ship.py) (internal/events).
func runEvents(ctx context.Context, env Env, args []string) int {
	return events.Main(ctx, collectorEnv(env), args)
}
