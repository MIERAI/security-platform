package shim

import (
	"context"

	"github.com/MIERAI/security-platform/internal/collectors/k8s"
	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
)

// runK8s is `sp k8s ...`: the Go implementation of the k8s collector (internal/collectors/k8s).
func runK8s(ctx context.Context, env Env, args []string) int {
	return k8s.Main(ctx, args, &rundoc.Env{Getenv: env.Getenv, Environ: env.Environ, Stderr: env.Stderr}, env.Stdout)
}
