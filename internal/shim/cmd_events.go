package shim

import (
	"context"
	"time"

	"github.com/MIERAI/security-platform/internal/events"
)

// runEvents is `sp events ship ...`: the Go implementation of the events shipper (events/ship.py, internal/events).
func runEvents(ctx context.Context, env Env, args []string) int {
	return events.Main(ctx, events.Env{Getenv: env.Getenv, Stdout: env.Stdout, Stderr: env.Stderr, Now: time.Now,
		Location: time.Local}, args)
}
