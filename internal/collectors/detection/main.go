// Package detection is the detection collector (collectors/detection). (Placeholder: implemented in this pull request.)
package detection

import (
	"context"
	"fmt"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
)

// Main is `sp detection ...`.
func Main(_ context.Context, env rundoc.Env, _ []string) int {
	_, _ = fmt.Fprintln(env.Stderr, "sp detection: not implemented yet") // the status says it too
	return 2
}
