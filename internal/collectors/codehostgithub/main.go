// Package codehostgithub is the codehost-github collector (collectors/codehost-github). (Placeholder: implemented in this pull request.)
package codehostgithub

import (
	"context"
	"fmt"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
)

// Main is `sp codehost-github ...`.
func Main(_ context.Context, env rundoc.Env, _ []string) int {
	_, _ = fmt.Fprintln(env.Stderr, "sp codehost-github: not implemented yet") // the status says it too
	return 2
}
