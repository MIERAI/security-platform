package shim

import (
	"context"

	"github.com/MIERAI/security-platform/internal/collectors/detection"
	"github.com/MIERAI/security-platform/internal/pyhome"
)

// runDetection is `sp detection collect`: the Go implementation of the detection collector
// (internal/collectors/detection). The detection catalog (detections/catalog.yaml) comes from the located product
// tree; without one the catalog is empty, which the run reports (no released date: a coverage gap).
func runDetection(ctx context.Context, env Env, args []string) int {
	tree := ""
	if home, err := pyhome.Locate(env.Getenv, env.Executable); err == nil {
		tree = home.Dir
	}
	return detection.Main(ctx, collectorEnv(env), tree, args)
}
