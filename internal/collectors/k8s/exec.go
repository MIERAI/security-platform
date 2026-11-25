package k8s

import (
	"context"
	"errors"

	"github.com/MIERAI/security-platform/internal/collectors/execadapter"
	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// newExecutor is host_exec, the exec adapter (internal/collectors/execadapter) that runs kube-bench on a node,
// with its processes run by run (rundoc.Exec; tests fake it). Configuration errors are the reference's exceptions.
func newExecutor(cfg *pyvalue.Map, env []string, run func(context.Context, *rundoc.Cmd) rundoc.Result) (*execadapter.Executor, error) {
	ex, err := execadapter.New(cfg, env)
	switch {
	case err == nil:
		return ex.WithRunner(run), nil
	case errors.Is(err, execadapter.ErrNotImplemented):
		return nil, &kubeError{"NotImplementedError", execadapter.Reason(err)}
	case errors.Is(err, execadapter.ErrHost):
		return nil, &kubeError{"KeyError", "'host'"}
	default:
		typ := "local"
		if cfg.Has("type") {
			typ = rundoc.Str(cfg.Value("type"))
		}
		return nil, &kubeError{"KeyError", pyvalue.Repr(typ)}
	}
}
