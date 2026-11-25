// Package hostsbom is the `host-sbom` collector (collectors/host-sbom/collector.py in Go, `sp collect host-sbom`):
// the software inventory of every host, read-only, through an exec adapter and an OS profile
// (collectors/host-sbom/profiles, sent unchanged). A profile prints `key=value` platform facts and
// `pkg<TAB>ecosystem<TAB>name<TAB>version<TAB>src<TAB>srcver<TAB>arch` lines.
//
// Outputs (inventory/v1, read by vuln-intel): inventory.host-packages.json (kind host-package) and
// inventory.host-platforms.json (kind host-platform), plus — for `sbom_paths` on a local host — a CycloneDX SBOM of
// language packages from `trivy rootfs` in <data>/sbom/host-<name>-fs.cdx.json (collector-protocol COLLECTOR-D1).
package hostsbom

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/MIERAI/security-platform/collectors"
	"github.com/MIERAI/security-platform/internal/collectors/collkit"
	"github.com/MIERAI/security-platform/internal/collectors/execadapter"
	"github.com/MIERAI/security-platform/internal/collectors/pytext"
	"github.com/MIERAI/security-platform/internal/collectors/spdoc"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// Version is the collector's version (collectors/host-sbom/VERSION; a test keeps them equal).
const Version = "0.2.0"

const (
	schema        = "security-platform/inventory/v1"
	scriptTimeout = 300 * time.Second
	maxErrorTail  = 160
)

// Main runs the collector and returns its exit status.
func Main(ctx context.Context, env collkit.Env) int {
	return collkit.Main(ctx, env, "host-sbom", Version, collect)
}

// inventory is what the run collects across hosts.
type inventory struct {
	packages, platforms []any
	ecosystems          map[string]int
}

func collect(ctx context.Context, r *collkit.Run) error {
	hosts, err := collkit.Targets(r.Inst, "hosts", "name")
	if err != nil {
		return err
	}
	inv := &inventory{packages: []any{}, platforms: []any{}, ecosystems: map[string]int{}}
	for _, h := range hosts {
		if err := collectHost(ctx, r, h, inv); err != nil {
			return err
		}
	}
	for _, f := range []struct {
		kind, name string
		items      []any
	}{{"host-package", "host-packages", inv.packages}, {"host-platform", "host-platforms", inv.platforms}} {
		doc := pyvalue.NewMap()
		doc.Set("schema", schema)
		doc.Set("kind", f.kind)
		doc.Set("generated_at", r.Now().UTC().Format("2006-01-02T15:04:05Z"))
		doc.Set("items", f.items)
		if err := spdoc.WriteFile(r.Dir, "inventory."+f.name+".json", doc, 0); err != nil {
			return err
		}
	}
	kinds := make([]string, 0, len(inv.ecosystems))
	for k := range inv.ecosystems {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		r.Doc.Metric("security_sbom_host_packages", float64(inv.ecosystems[k]), "Installed packages inventoried on hosts",
			map[string]string{"kind": k})
	}
	r.Doc.Metric("security_sbom_hosts", float64(len(inv.platforms)), "Hosts with a software inventory", nil)
	return nil
}

// run executes a host's profile; a host that cannot run returns a gap reason instead.
func run(ctx context.Context, r *collkit.Run, h *pyvalue.Map, name string) (execadapter.Result, error) {
	if !collkit.SafeFileName(name) {
		return execadapter.Result{}, collkit.Gap("invalid host name for an evidence file: " + pyvalue.Repr(name))
	}
	profile, _ := h.Value("profile").(string) // not text: an unknown profile below
	ext := ".sh"
	if profile == "windows" {
		ext = ".ps1"
	}
	var script string
	var err error
	if collkit.SafeFileName(profile) {
		script, err = collectors.Script("host-sbom/profiles/" + profile + ext)
	}
	if script == "" || err != nil {
		return execadapter.Result{}, collkit.Gap("invalid configuration: unknown profile " + pyvalue.Repr(h.Value("profile")))
	}
	e, err := execadapter.New(h.Value("exec"), r.Environ)
	if err != nil {
		return execadapter.Result{}, collkit.Gap("invalid configuration: " + err.Error())
	}
	var res execadapter.Result
	if profile == "windows" {
		res, err = execadapter.PowerShell(ctx, e, script, scriptTimeout, false)
	} else {
		res, err = e.Run(ctx, []string{"sh", "-s"}, script, scriptTimeout, false)
	}
	if errors.Is(err, execadapter.ErrOutputTooLarge) {
		return res, collkit.Gap("inventory failed: " + err.Error())
	}
	return res, err
}

func collectHost(ctx context.Context, r *collkit.Run, h *pyvalue.Map, inv *inventory) error {
	if h.Value("sbom") == false {
		return nil
	}
	name := pyvalue.Str(h.Value("name"))
	asset := "host:" + name
	if !collkit.InScope(r.Inst, h.Value("name"), "host-sbom") {
		return nil // instance scope: another collector covers this asset (not a gap)
	}
	if !pyvalue.Truthy(h.Value("exec")) {
		r.Doc.Gap(asset, pyvalue.Str(h.GetOr("gap", "no exec adapter configured")), nil)
		return nil
	}
	res, err := run(ctx, r, h, name)
	if why, ok := collkit.AsGap(err); ok {
		r.Doc.Gap(asset, why, nil)
		return nil
	}
	if err != nil {
		return fmt.Errorf("host %s: %w", name, err)
	}
	kv, pkgs := parse(res.Out)
	if kv["os.family"] == "" {
		r.Doc.Gap(asset, "inventory failed rc="+strconv.Itoa(res.RC)+": "+pytext.Tail(pytext.Strip(res.Err), maxErrorTail), nil)
		return nil
	}
	r.Doc.OK(asset)
	p := platform(h, kv, len(pkgs))
	p.Set("fs_sbom", fsSBOM(ctx, r, h, name))
	inv.platforms = append(inv.platforms, p)
	for _, x := range pkgs {
		inv.packages = append(inv.packages, x.item(h.Value("name")))
		inv.ecosystems[x.ecosystem]++
	}
	ev := pyvalue.NewMap()
	ev.Set("platform", p)
	ev.Set("packages", int64(len(pkgs)))
	ev.Set("rc", int64(res.RC))
	ptr, err := r.Doc.Raw(r.Dir, name+".json", ev)
	if err != nil || len(pkgs) > 0 {
		return err
	}
	return r.Doc.Add(&spdoc.Finding{Layer: "host", Asset: asset, Check: "sbom.no_packages",
		Title:    "no package inventory for " + pyvalue.Str(h.Value("profile")) + " host (package manager not found)",
		Severity: "info", Evidence: ptr, Remediation: "check the profile / package manager"})
}
