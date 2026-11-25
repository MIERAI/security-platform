// Package exposure is the exposure collector (collectors/exposure). (Placeholder: implemented in this pull request.)
package exposure

import (
	"context"
	"fmt"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
)

// Main is `sp exposure ...`.
func Main(_ context.Context, env rundoc.Env, _ []string) int {
	_, _ = fmt.Fprintln(env.Stderr, "sp exposure: not implemented yet") // the status says it too
	return 2
}
