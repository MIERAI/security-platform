package shim

import (
	"context"
	"fmt"
	"time"

	"github.com/MIERAI/security-platform/internal/collectors/collkit"
	"github.com/MIERAI/security-platform/internal/collectors/host"
	"github.com/MIERAI/security-platform/internal/collectors/hostsbom"
	"github.com/MIERAI/security-platform/internal/collectors/secretsfiles"
)

// runHost is `sp host collect|version`: the Go implementation of the host collector (internal/collectors/host).
func runHost(ctx context.Context, env Env, args []string) int {
	return runExecCollector(ctx, env, args, execCollector{"host", host.Version, host.Main})
}

// runHostSBOM is `sp host-sbom collect|version` (internal/collectors/hostsbom).
func runHostSBOM(ctx context.Context, env Env, args []string) int {
	return runExecCollector(ctx, env, args, execCollector{"host-sbom", hostsbom.Version, hostsbom.Main})
}

// runSecretsFiles is `sp secrets-files collect|version` (internal/collectors/secretsfiles).
func runSecretsFiles(ctx context.Context, env Env, args []string) int {
	return runExecCollector(ctx, env, args, execCollector{"secrets-files", secretsfiles.Version, secretsfiles.Main})
}

// execCollector is one exec-adapter collector: its name, version and run.
type execCollector struct {
	name, version string
	main          func(context.Context, collkit.Env) int
}

// runExecCollector runs one exec-adapter collector run (collector protocol: SP_RUN_DIR, SP_INSTANCE, ...), e.g. as a
// runner `command` job with `argv: [sp, host, collect]`, or prints its version.
func runExecCollector(ctx context.Context, env Env, args []string, c execCollector) int {
	name := c.name
	switch {
	case len(args) == 1 && args[0] == "collect":
		return c.main(ctx, collkit.Env{Getenv: env.Getenv, Environ: env.Environ, Stderr: env.Stderr, Now: time.Now})
	case len(args) == 1 && args[0] == "version":
		if _, err := fmt.Fprintln(env.Stdout, c.version); err != nil {
			return 1
		}
		return ExitOK
	}
	return fail(env, ExitUsage, "usage: sp %s collect   run the %s collector (collector protocol: SP_RUN_DIR, SP_INSTANCE)\n"+
		"       sp %s version   print the collector's version", name, name, name)
}
