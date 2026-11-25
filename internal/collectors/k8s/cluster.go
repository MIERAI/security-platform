package k8s

import (
	"context"
	"errors"
	"fmt"
)

// clusterRun is one cluster's collection: its config, its kubectl, and where its evidence goes.
type clusterRun struct {
	*collector
	cfg   *clusterConfig
	kube  *kubectl
	asset string // k8s-cluster:<name>
}

// cluster reads one cluster. An unreachable cluster is an error (the caller records the gap); a part that cannot
// be read is a gap of that part only (K8S-D1), and the other parts are still evaluated.
func (c *collector) cluster(ctx context.Context, cfg *clusterConfig) error {
	cr := &clusterRun{collector: c, cfg: cfg, asset: "k8s-cluster:" + cfg.name,
		kube: &kubectl{kubeconfig: cfg.kubeconfig, env: c.env.Environ, run: c.exec}}
	if _, err := get[struct{}](ctx, cr.kube, "namespaces", false); err != nil { // reachable at all?
		return err
	}
	c.run.Doc.OK(cr.asset, "")
	for _, p := range []struct {
		name string
		run  func(context.Context) error
		gap  func(error)
	}{
		{"workloads", cr.workloads, cr.workloadsGap},
		{"rbac", cr.rbac, func(err error) { cr.partGap("k8s-identity:"+cfg.name, "rbac", err, nil) }},
		{"secrets", cr.secrets, func(err error) { cr.partGap(cr.asset+"/secrets", "secrets", err, nil) }},
		{"policy", cr.policy, func(err error) { cr.partGap(cr.asset+"/policy", "policy", err, []string{"k8s.policy.*"}) }},
		{"operator", cr.operator, func(err error) {
			cr.partGap("k8s-identity:"+cfg.name+"/operator-kubeconfig", "operator", err, nil)
		}},
		{"cis", cr.cis, func(err error) { cr.cisGap(err.Error()) }},
	} {
		if !cfg.parts[p.name] {
			continue
		}
		if err := p.run(ctx); err != nil {
			var f *fatalError
			if errors.As(err, &f) || ctx.Err() != nil {
				return err
			}
			p.gap(err)
		}
	}
	return nil
}

// partGap records that one part of the cluster could not be read.
func (cr *clusterRun) partGap(asset, part string, err error, checks []string) {
	cr.run.Doc.Gap(asset, part+": "+err.Error(), checks)
}

// workloadsGap: the workloads' findings stay unknown and the image inventory is partial.
func (cr *clusterRun) workloadsGap(err error) {
	cr.partGap("k8s-workload:"+cr.cfg.name, "workloads", err, nil)
	cr.partGap("k8s-namespace:"+cr.cfg.name, "workloads", err, nil)
	cr.sources.Set(cr.asset, "failed: "+errKind(err))
}

// raw stores one evidence file of this cluster and returns its pointer.
func (cr *clusterRun) raw(file string, v any) (string, error) {
	p, err := cr.run.Doc.Raw(cr.run.Dir, cr.cfg.name+"-"+file, v)
	if err != nil {
		return "", &fatalError{fmt.Errorf("evidence: %w", err)}
	}
	return p, nil
}

// fatalError fails the whole run (the run directory cannot be written), never a gap.
type fatalError struct{ err error }

func (e *fatalError) Error() string { return e.err.Error() }
func (e *fatalError) Unwrap() error { return e.err }
