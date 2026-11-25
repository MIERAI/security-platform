package shim

import (
	"context"
	"time"

	"github.com/MIERAI/security-platform/internal/ledger/cli"
)

// runLedger is `sp ledger ...`: the Go ledger component (merge, track), docs/go.md.
func runLedger(ctx context.Context, env Env, args []string) int {
	return cli.Run(ctx, cli.Env{Stdout: env.Stdout, Stderr: env.Stderr, Environ: env.Environ, Now: time.Now}, args)
}
