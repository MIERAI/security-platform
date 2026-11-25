// Package events is the events shipper (events/ship.py). (Placeholder: implemented in this pull request.)
package events

import (
	"context"
	"fmt"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
)

// Main is `sp events ...`.
func Main(_ context.Context, env rundoc.Env, _ []string) int {
	_, _ = fmt.Fprintln(env.Stderr, "sp events: not implemented yet") // the status says it too
	return 2
}
