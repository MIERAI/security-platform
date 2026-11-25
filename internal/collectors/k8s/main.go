// Package k8s is the Go implementation of the `k8s` collector (collectors/k8s): `sp k8s collect`.
package k8s

import (
	"context"
	"errors"
	"io"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
)

// Version is the collector's version (collectors/k8s/VERSION).
const Version = "0.0.0"

// Main is `sp k8s ...`.
func Main(ctx context.Context, args []string, env *rundoc.Env, stdout io.Writer) int {
	return rundoc.Main(ctx, &rundoc.Collector{Name: "k8s", Version: Version, Collect: collect}, args, env, stdout)
}

func collect(context.Context, *rundoc.Run, *rundoc.Env) error {
	return errors.New("not implemented yet")
}
