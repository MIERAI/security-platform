package shim

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/collectors/collkit"
	"github.com/MIERAI/security-platform/internal/collectors/host"
	"github.com/MIERAI/security-platform/internal/collectors/hostsbom"
	"github.com/MIERAI/security-platform/internal/collectors/secretsfiles"
)

// collectors are the collectors `sp collect NAME` runs in Go (collector protocol: SP_RUN_DIR, SP_INSTANCE, ...).
func collectors() map[string]func(context.Context, collkit.Env) int {
	return map[string]func(context.Context, collkit.Env) int{
		"host":          host.Main,
		"host-sbom":     hostsbom.Main,
		"secrets-files": secretsfiles.Main,
	}
}

// runCollect is `sp collect NAME`: one run of a Go collector, e.g. as a runner `command` job with
// `argv: [sp, collect, host]`.
func runCollect(ctx context.Context, env Env, args []string) int {
	run, ok := collectors()[strings.Join(args, " ")]
	if len(args) != 1 || !ok {
		names := make([]string, 0, len(collectors()))
		for n := range collectors() {
			names = append(names, n)
		}
		sort.Strings(names)
		return fail(env, ExitUsage, "usage: sp collect NAME   (NAME: %s)", strings.Join(names, ", "))
	}
	return run(ctx, collkit.Env{Getenv: env.Getenv, Environ: env.Environ, Stderr: env.Stderr, Now: time.Now})
}
