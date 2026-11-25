// Package identity is the Go implementation of the `identity` collector (collectors/identity): `sp identity collect`.
package identity

import (
	"context"
	"errors"
	"io"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
)

// Version is the collector's version (collectors/identity/VERSION).
const Version = "0.0.0"

// Main is `sp identity ...`.
func Main(ctx context.Context, args []string, env *rundoc.Env, stdout io.Writer) int {
	return rundoc.Main(ctx, &rundoc.Collector{Name: "identity", Version: Version, Collect: collect}, args, env, stdout)
}

func collect(context.Context, *rundoc.Run, *rundoc.Env) error {
	return errors.New("not implemented yet")
}
