package shim

import (
	"context"

	"github.com/MIERAI/security-platform/internal/collectors/identity"
	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
)

// runIdentity is `sp identity ...`: the Go implementation of the identity collector (internal/collectors/identity).
func runIdentity(ctx context.Context, env Env, args []string) int {
	return identity.Main(ctx, args, &rundoc.Env{Getenv: env.Getenv, Environ: env.Environ, Stderr: env.Stderr}, env.Stdout)
}
