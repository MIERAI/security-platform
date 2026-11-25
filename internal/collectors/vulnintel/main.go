// Package vulnintel is the Go implementation of the `vuln-intel` collector (collectors/vuln-intel): `sp vuln-intel collect`.
package vulnintel

import (
	"context"
	"errors"
	"io"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
)

// Version is the collector's version (collectors/vuln-intel/VERSION).
const Version = "0.0.0"

// Main is `sp vuln-intel ...`.
func Main(ctx context.Context, args []string, env *rundoc.Env, stdout io.Writer) int {
	return rundoc.Main(ctx, &rundoc.Collector{Name: "vuln-intel", Version: Version, Collect: collect}, args, env, stdout)
}

func collect(context.Context, *rundoc.Run, *rundoc.Env) error {
	return errors.New("not implemented yet")
}
