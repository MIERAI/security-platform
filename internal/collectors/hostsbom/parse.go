package hostsbom

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/MIERAI/security-platform/internal/collectors/execadapter"
	"github.com/MIERAI/security-platform/internal/collectors/pytext"
	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

const (
	trivyTimeout = 900 * time.Second
	maxBuildTS   = 253402300799 // 9999-12-31T23:59:59Z: a later firmware build time is not a date
)

// pkg is one installed package.
type pkg struct{ ecosystem, name, version, source, sourceVersion, arch string }

// item is the host-package inventory item (key order as the Python collector writes it).
func (p pkg) item(host any) *pyvalue.Map {
	m := pyvalue.NewMap()
	m.Set("ecosystem", p.ecosystem)
	m.Set("name", p.name)
	m.Set("version", p.version)
	m.Set("source_name", p.source)
	m.Set("source_version", p.sourceVersion)
	m.Set("arch", p.arch)
	m.Set("host", host)
	return m
}

// parse reads platform facts (key=value; lines starting with "#" or a space are not facts) and package lines
// (pkg<TAB>ecosystem<TAB>name<TAB>version<TAB>src<TAB>srcver<TAB>arch; without name or version: skipped; an empty
// source defaults to the package).
func parse(out string) (map[string]string, []pkg) {
	kv := map[string]string{}
	var pkgs []pkg
	for _, line := range pytext.SplitLines(out) {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "pkg\t") {
			f := append(strings.Split(line, "\t"), make([]string, 7)...)[1:7]
			if f[1] == "" || f[2] == "" {
				continue
			}
			pkgs = append(pkgs, pkg{ecosystem: f[0], name: f[1], version: f[2], source: or(f[3], f[1]),
				sourceVersion: or(f[4], f[2]), arch: f[5]})
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, " ") {
			kv[pytext.Strip(k)] = pytext.Strip(v)
		}
	}
	return kv, pkgs
}

func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// platform is the host-platform inventory item (without fs_sbom, which the caller adds last).
func platform(h *pyvalue.Map, kv map[string]string, packages int) *pyvalue.Map {
	m := pyvalue.NewMap()
	m.Set("host", h.Value("name"))
	m.Set("profile", h.Value("profile"))
	for _, f := range [][2]string{{"os_family", "os.family"}, {"os_version", "os.version"}, {"os_build", "os.build"},
		{"os_name", "os.name"}, {"os_product", "os.product"}, {"os_edition", "os.edition"}, {"os_codename", "os.codename"},
		{"arch", "arch"}, {"kernel_running", "kernel.running"}, {"patch_level", "platform.patch_level"},
		{"vendor_patch_level", "platform.vendor_patch_level"}, {"rsr", "os.rsr"}} {
		m.Set(f[0], kv[f[1]])
	}
	var dev []string
	for _, k := range []string{"device.manufacturer", "device.model"} {
		if kv[k] != "" {
			dev = append(dev, kv[k])
		}
	}
	m.Set("device", strings.Join(dev, " "))
	m.Set("firmware", firmware(kv))
	m.Set("exposed", pyvalue.Truthy(h.GetOr("exposed", false)))
	m.Set("prod", pyvalue.Truthy(h.GetOr("prod", true)))
	m.Set("package_count", int64(packages))
	return m
}

// firmware is the firmware identity (vendor, model, version, channel, build_date: the build time as a UTC date),
// nil when there is none.
func firmware(kv map[string]string) any {
	fw := pyvalue.NewMap()
	for _, k := range []string{"vendor", "model", "version", "channel"} {
		if v := kv["firmware."+k]; v != "" {
			fw.Set(k, v)
		}
	}
	if ts := kv["firmware.build_ts"]; ts != "" && isDigits(ts) {
		if n, err := pyvalue.ParseInt(ts, 10); err == nil && n <= maxBuildTS {
			fw.Set("build_date", time.Unix(n, 0).UTC().Format("2006-01-02"))
		}
	}
	if fw.Len() == 0 {
		return nil
	}
	return fw
}

func isDigits(s string) bool {
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

// fsSBOM scans the host's sbom_paths with `trivy rootfs` (local hosts only) and returns the merged CycloneDX
// document's path relative to the data directory, or nil; a problem is a narrow gap host:<name>/fs-sbom.
func fsSBOM(ctx context.Context, r *job, h *pyvalue.Map, name string) any {
	paths, _ := h.Value("sbom_paths").([]any) // absent or not a list: no file-system SBOM
	if len(paths) == 0 {
		return nil
	}
	asset := "host:" + name + "/fs-sbom"
	if ex, _ := h.Value("exec").(*pyvalue.Map); ex == nil || ex.GetOr("type", "local") != "local" {
		r.Doc.Gap(asset, "sbom_paths needs a local exec adapter (trivy runs on the hub)", nil)
		return nil
	}
	merged, err := scan(ctx, r, paths)
	if err == nil && merged != nil {
		out := filepath.Join(data(r), "sbom", "host-"+name+"-fs.cdx.json")
		err = writeSBOM(out, merged)
		if err == nil {
			rel, rerr := filepath.Rel(data(r), out)
			if rerr == nil {
				return filepath.ToSlash(rel)
			}
			err = rerr
		}
	}
	if err != nil {
		r.Doc.Gap(asset, err.Error(), nil)
	}
	return nil
}

var errTrivy = errors.New("trivy rootfs")

// scan runs trivy on every existing directory and merges the components into the first document.
func scan(ctx context.Context, r *job, paths []any) (*pyvalue.Map, error) {
	e, err := execadapter.New(nil, r.env.Environ)
	if err != nil {
		return nil, err
	}
	var merged *pyvalue.Map
	for _, p := range paths {
		dir := rundoc.ExpandUser(pyvalue.Str(p), r.Home)
		if st, err := os.Stat(dir); err != nil || !st.IsDir() {
			continue
		}
		if strings.HasPrefix(dir, "-") {
			dir = "./" + dir // never read as an option
		}
		doc, err := trivy(ctx, e, filepath.Join(data(r), "cache", "trivy"), dir)
		if err != nil {
			return nil, err
		}
		merged = mergeComponents(merged, doc)
	}
	return merged, nil
}

// trivy is the CycloneDX document of `trivy rootfs` on one directory.
func trivy(ctx context.Context, e *execadapter.Executor, cache, dir string) (*pyvalue.Map, error) {
	res, err := e.Run(ctx, []string{"trivy", "--cache-dir", cache, "--quiet", "rootfs", "--cache-backend", "memory",
		"--skip-db-update", "--scanners", "vuln", "--format", "cyclonedx", dir}, "", trivyTimeout, false)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errTrivy, err)
	}
	if res.RC == execadapter.StatusNotFound && res.Out == "" {
		return nil, fmt.Errorf("%w: trivy is not installed (not on PATH)", errTrivy)
	}
	if res.RC != 0 {
		return nil, fmt.Errorf("%w rc=%d: %s", errTrivy, res.RC, pytext.Tail(pytext.Strip(res.Err), maxErrorTail))
	}
	doc, err := pyvalue.DecodeJSON([]byte(res.Out))
	m, ok := doc.(*pyvalue.Map)
	if err != nil || !ok {
		return nil, fmt.Errorf("%w: output is not a CycloneDX document", errTrivy)
	}
	return m, nil
}

func mergeComponents(merged, doc *pyvalue.Map) *pyvalue.Map {
	if merged == nil {
		return doc
	}
	have, _ := merged.SetDefault("components", []any{}).([]any) // not a list: replaced by the merged list
	add, _ := doc.Value("components").([]any)
	merged.Set("components", append(have, add...))
	return merged
}

func writeSBOM(path string, doc *pyvalue.Map) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create the SBOM directory: %w", err)
	}
	if err := rundoc.WriteJSON(path, rundoc.JSON(doc), pyjson.Compact()); err != nil {
		return fmt.Errorf("write the file-system SBOM: %w", err)
	}
	return nil
}

// data is the data directory (".", as the Python collectors, when SP_DATA is unset).
func data(r *job) string {
	if r.Data == "" {
		return "."
	}
	return r.Data
}
