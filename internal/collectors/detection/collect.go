// Package detection is the detection collector (collectors/detection): is detection actually working, and how good
// is it? READ-ONLY. It checks the detection pipeline from the outside (docs/detection.md) — sensors and in-cluster
// backstop rules (kubectl get, read-only), page routing in Alertmanager, delivery of every expected log source to the
// log store (LogQL counts, never line content), the catalog's rules in the log store's ruler, alert history — and
// measures its quality: verdicts, drills, rule-content age. Every HTTP call is a GET (roclient, or curl on an exec
// target); a bearer token comes only from a token_file that grants nothing to group and others.
package detection

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// Version is the collector's version (collectors/detection/VERSION; TestVersionMatchesTree keeps them equal).
const Version = "0.2.0"

// Name is the collector's name.
const Name = "detection"

const (
	layer          = "detection"
	maxCatalogFile = 4 << 20
	maxDataFile    = 16 << 20
)

// Main is `sp detection collect`; tree is the product tree holding detections/catalog.yaml ("" when none).
func Main(ctx context.Context, env rundoc.Env, tree string, args []string) int {
	return rundoc.Main(ctx, env, args, Name, func(ctx context.Context, env rundoc.Env) error {
		return Collect(ctx, env, tree)
	})
}

// collector is one run.
type collector struct {
	doc   *rundoc.Document
	env   rundoc.Env
	home  string
	now   float64 // epoch seconds
	inst  *pyvalue.Map
	d     *pyvalue.Map // the instance's detection section
	cat   *pyvalue.Map // the detection catalog
	data  string       // SP_DATA
	kube  kubectlFunc
	httpT time.Duration
}

// Collect is one run of the collector (collector protocol).
func Collect(ctx context.Context, env rundoc.Env, tree string) error {
	return collect(ctx, env, tree, runKubectl)
}

func collect(ctx context.Context, env rundoc.Env, tree string, kube kubectlFunc) error {
	run, err := rundoc.Start(env, Name, Version)
	if err != nil {
		return err
	}
	c := &collector{doc: run.Doc, env: env, home: env.Home(), now: float64(env.Now().UnixNano()) / 1e9,
		inst: run.Instance, data: env.Getenv("SP_DATA"), cat: loadCatalog(tree), kube: kube, httpT: defaultTimeout}
	c.d = rundoc.Map(run.Instance.Value("detection"))
	if err := c.run(ctx); err != nil {
		return err
	}
	return run.Finish()
}

func (c *collector) run(ctx context.Context) error {
	if c.d.Len() == 0 {
		c.doc.Gap("detection-config:instance", "no `detection:` section in the instance")
	} else if err := c.checks(ctx); err != nil {
		return err
	}
	return c.ruleset()
}

// checks are the checks of a configured detection section, in the reference's order.
func (c *collector) checks(ctx context.Context) error {
	steps := []func(context.Context) error{c.scope, c.sensors, c.backstop, c.routing, c.logStore, c.alertHistory,
		c.verdicts, c.drills}
	for _, step := range steps {
		if err := step(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (c *collector) logStore(ctx context.Context) error {
	cfg := c.d.Value("log_store")
	if !pyvalue.Truthy(cfg) {
		c.doc.Gap("detection-ruler:log-store", "no detection.log_store configured")
		return nil
	}
	store, err := c.endpoint(cfg)
	if err != nil {
		return fmt.Errorf("%w: detection.log_store: %w", rundoc.ErrUsage, err)
	}
	if err := c.sources(ctx, store); err != nil {
		return err
	}
	return c.ruler(ctx, store)
}

// loadCatalog reads detections/catalog.yaml of the tree; an unreadable or missing catalog is an empty one (its
// missing released date is then a coverage gap).
func loadCatalog(tree string) *pyvalue.Map {
	if tree == "" {
		return pyvalue.NewMap()
	}
	m, err := loadYAML(filepath.Join(tree, "detections", "catalog.yaml"), maxCatalogFile)
	if err != nil {
		return pyvalue.NewMap()
	}
	return rundoc.Map(m)
}

// loadYAML is spsdk.load_config for the collector's own data files: YAML (or JSON), any top-level value.
func loadYAML(path string, limit int64) (any, error) {
	data, err := rundoc.ReadLimited(path, limit)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", filepath.Base(path), err)
	}
	v, err := pyvalue.DecodeYAML(data)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", filepath.Base(path), err)
	}
	return v, nil
}

// raw stores evidence; a failure to write it fails the run (the document would point at nothing).
func (c *collector) raw(file string, v any) (string, error) {
	return c.doc.Raw(file, v)
}

// finding adds a finding with its evidence written first (as the reference evaluates c.raw before c.finding).
func (c *collector) finding(f *rundoc.Finding, evFile string, ev any) error {
	p, err := c.raw(evFile, ev)
	if err != nil {
		return err
	}
	f.Layer, f.Evidence = layer, p
	c.doc.Add(f)
	return nil
}

func (c *collector) metric(name string, v float64, help string, labels ...[2]string) {
	c.doc.Metric(name, v, help, labels...)
}

func label(k, v string) [2]string { return [2]string{k, v} }
