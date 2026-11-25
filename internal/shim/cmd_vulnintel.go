package shim

import (
	"context"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/collectors/vulnintel"
)

// runVulnIntel is `sp vuln-intel ...`: the Go implementation of the vuln-intel collector (internal/collectors/vulnintel).
func runVulnIntel(ctx context.Context, env Env, args []string) int {
	return vulnintel.Main(ctx, args, &rundoc.Env{Getenv: env.Getenv, Environ: env.Environ, Stderr: env.Stderr}, env.Stdout)
}
