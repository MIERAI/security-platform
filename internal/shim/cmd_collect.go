package shim

import (
	"context"

	"github.com/MIERAI/security-platform/internal/collectors/host"
	"github.com/MIERAI/security-platform/internal/collectors/hostsbom"
	"github.com/MIERAI/security-platform/internal/collectors/secretsfiles"
)

// runHost is `sp host collect|version`: the Go implementation of the host collector (internal/collectors/host).
func runHost(ctx context.Context, env Env, args []string) int {
	return host.Main(ctx, args, collectorEnv(env), env.Stdout)
}

// runHostSBOM is `sp host-sbom collect|version` (internal/collectors/hostsbom).
func runHostSBOM(ctx context.Context, env Env, args []string) int {
	return hostsbom.Main(ctx, args, collectorEnv(env), env.Stdout)
}

// runSecretsFiles is `sp secrets-files collect|version` (internal/collectors/secretsfiles).
func runSecretsFiles(ctx context.Context, env Env, args []string) int {
	return secretsfiles.Main(ctx, args, collectorEnv(env), env.Stdout)
}
