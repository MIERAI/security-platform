// Package k8s is the Go implementation of the `k8s` collector (collectors/k8s): Kubernetes posture through kubectl,
// READ-ONLY (`get` and `auth whoami`, nothing else), and the inventory of running images (inventory/v1) that
// vuln-intel matches against advisories. `sp k8s collect`.
//
// Instance config `kubernetes: [{name, kubeconfig, role, parts?, host_exec?, kube_bench?: {benchmark, tarball}}]`
// as for the Python collector; parts: workloads, rbac, secrets (metadata only), policy (PolicyReports), operator
// (the caller's own credential), cis (kube-bench on a node through host_exec).
package k8s

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// Version is the collector's version (collectors/k8s/VERSION).
const Version = "0.4.0"

// Main is `sp k8s ...`.
func Main(ctx context.Context, args []string, env *rundoc.Env, stdout io.Writer) int {
	return rundoc.Main(ctx, &rundoc.Collector{Name: "k8s", Version: Version, Collect: collect}, args, env, stdout)
}

// collector is one run over every configured cluster.
type collector struct {
	run       *rundoc.Run
	env       *rundoc.Env
	exec      func(context.Context, *rundoc.Cmd) rundoc.Result
	inventory []*pyjson.Object
	sources   *pyjson.Object // k8s-cluster:<name> -> complete | failed: <why> | not inventoried (...)
}

func collect(ctx context.Context, run *rundoc.Run, env *rundoc.Env) error {
	c := &collector{run: run, env: env, exec: rundoc.Exec, sources: pyjson.NewObject()}
	return c.collect(ctx)
}

func (c *collector) collect(ctx context.Context) error {
	for _, v := range rundoc.List(c.run.Instance.Value("kubernetes")) {
		cfg, err := parseCluster(v, c.run.Home)
		if err != nil {
			return err
		}
		asset := "k8s-cluster:" + cfg.name
		c.sources.Set(asset, "not inventoried (parts without workloads)")
		if err := c.cluster(ctx, cfg); err != nil {
			var f *fatalError
			if errors.As(err, &f) || ctx.Err() != nil {
				return err
			}
			c.run.Doc.Gap(asset, err.Error(), nil)
			if c.sources.Str(asset) != "complete" {
				c.sources.Set(asset, "failed: "+errKind(err))
			}
		}
	}
	return c.writeInventory()
}

// writeInventory writes inventory.<name>-images.json: complete only when every configured cluster's pods were
// listed, so an image missing from `items` is no longer running (consumers may retire its findings).
func (c *collector) writeInventory() error {
	complete := c.sources.Len() > 0
	for _, k := range c.sources.Keys() {
		complete = complete && c.sources.Str(k) == "complete"
	}
	items := make([]pyjson.Value, len(c.inventory))
	for i, it := range c.inventory {
		items[i] = it
	}
	doc := pyjson.NewObject()
	doc.Set("schema", "security-platform/inventory/v1")
	doc.Set("kind", "container-image")
	doc.Set("items", items)
	doc.Set("complete", complete)
	doc.Set("sources", c.sources)
	data, err := pyjson.Marshal(doc, pyjson.Options{Indent: 1, EnsureASCII: true}) // json.dump(indent=1): key order kept
	if err != nil {
		return fmt.Errorf("encode the image inventory: %w", err)
	}
	if err := rundoc.WriteFile(filepath.Join(c.run.Dir, "inventory."+c.run.Doc.Name+"-images.json"), data); err != nil {
		return err
	}
	c.run.Doc.Metric("security_inventory_images", float64(len(c.inventory)), "Running images (cluster x image)", nil)
	return nil
}

// errKind is the exception name the reference records for a failed cluster ("failed: RuntimeError").
func errKind(err error) string {
	var ke *kubeError
	if errors.As(err, &ke) {
		return ke.kind
	}
	return "RuntimeError"
}

// clusterConfig is one `kubernetes:` entry.
type clusterConfig struct {
	name, kubeconfig string
	prod             bool
	parts            map[string]bool
	hostExec         *pyvalue.Map
	kubeBench        *pyvalue.Map
	raw              *pyvalue.Map
}

func allParts() []string {
	return []string{"workloads", "rbac", "secrets", "policy", "operator", "cis"}
}

func parseCluster(v any, home string) (*clusterConfig, error) {
	m := rundoc.Map(v)
	if m == nil || !m.Has("name") {
		return nil, fmt.Errorf("%w: every kubernetes entry needs a name", rundoc.ErrUsage)
	}
	cfg := &clusterConfig{name: rundoc.Str(m.Value("name")), prod: rundoc.Str(m.Value("role")) == "prod",
		parts: map[string]bool{}, hostExec: rundoc.Map(m.Value("host_exec")), kubeBench: rundoc.Map(m.Value("kube_bench")), raw: m}
	if kc := m.Value("kubeconfig"); kc != nil {
		if s := rundoc.Str(kc); s != "" && s != "in-cluster" {
			cfg.kubeconfig = rundoc.ExpandUser(s, home)
		}
	}
	parts := rundoc.Strings(m.Value("parts"))
	if len(parts) == 0 {
		parts = allParts()
	}
	for _, p := range parts {
		cfg.parts[p] = true
	}
	return cfg, nil
}
