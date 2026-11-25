// Package codehostgitea is the codehost-gitea collector (collectors/codehost-gitea). (Placeholder: implemented in this pull request.)
package codehostgitea

import (
	"context"
	"fmt"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
)

// Main is `sp codehost-gitea ...`.
func Main(_ context.Context, env rundoc.Env, _ []string) int {
	_, _ = fmt.Fprintln(env.Stderr, "sp codehost-gitea: not implemented yet") // the status says it too
	return 2
}
