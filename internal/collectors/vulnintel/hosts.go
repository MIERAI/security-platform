package vulnintel

import (
	"context"
	"path/filepath"
	"sort"
	"strings"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
)

// sbomTarget is an SBOM the OSV matcher reads: the asset, its path relative to the data directory, its meta.
type sbomTarget struct {
	asset, rel string
	meta       *matchMeta
}

// hostRun is the state of one host's matching.
type hostRun struct {
	asset string
	plat  *pyjson.Object
	pkgs  []*pyjson.Object
	meta  *matchMeta
	parts *pyjson.Object // matcher -> "ok" | "gap: <reason>", in the order they ran
}

func (h *hostRun) gap(part, reason string) { h.parts.Set(part, "gap: "+cut(reason, 200)) }

// hosts matches the host-platform / host-package inventories: distro packages and the running kernel, fs SBOMs,
// platform advisories, KEV entries of the firmware vendor. It returns the SBOMs for the OSV matcher.
func (c *collector) hosts(ctx context.Context, inv []invFile) []sbomTarget {
	plats := map[string]*pyjson.Object{}
	for _, p := range items(inv, "host-platform") {
		plats[pystr(get(p, "host"))] = p
	}
	pkgs := map[string][]*pyjson.Object{}
	for _, x := range items(inv, "host-package") {
		h := pystr(get(x, "host"))
		pkgs[h] = append(pkgs[h], x)
	}
	names := make([]string, 0, len(plats))
	for n := range plats {
		names = append(names, n)
	}
	sort.Strings(names)
	hcov := pyjson.NewObject()
	var targets []sbomTarget
	for _, name := range names {
		h := &hostRun{asset: "host:" + name, plat: plats[name], pkgs: pkgs[name], parts: pyjson.NewObject(),
			meta: &matchMeta{exposed: getOr(plats[name], "exposed", false), prod: getOr(plats[name], "prod", true)}}
		hcov.Set(h.asset, h.parts)
		c.countUnmatched(h)
		c.osPackages(ctx, h, name)
		if t, ok := c.fsSBOM(ctx, h); ok {
			targets = append(targets, t)
		}
		c.platform(ctx, h)
		c.firmware(h)
	}
	c.hostCoverage(hcov, plats)
	return targets
}

func (c *collector) countUnmatched(h *hostRun) {
	distro := distros()[strings.ToLower(sget(h.plat, "os_family"))]
	for _, x := range h.pkgs {
		if eco := pystr(get(x, "ecosystem")); !osEcosystem(eco) || distro == "" {
			c.unmatched[eco]++
		}
	}
}

// osPackages: the distro packages through a CycloneDX SBOM and trivy; kernel packages apart (only the running
// kernel counts, aggregated into one finding).
func (c *collector) osPackages(ctx context.Context, h *hostRun, name string) {
	cdx := osSBOM(h.plat, h.pkgs)
	if cdx == nil {
		return
	}
	sp := filepath.Join(c.dataDir, "sbom", "host-"+name+"-os.cdx.json")
	data, err := pyjson.Marshal(cdx, pyjson.Compact())
	if err == nil {
		err = rundoc.MkdirPrivate(filepath.Dir(sp))
	}
	if err == nil {
		err = rundoc.WriteFile(sp, data)
	}
	if err != nil {
		h.gap("os-packages", err.Error())
		return
	}
	rep, note := c.match(ctx, sp)
	if rep == nil {
		h.gap("os-packages", note)
		return
	}
	h.parts.Set("os-packages", "ok")
	kern := c.splitKernel(h, rep)
	c.handle(h.asset, h.meta, rep)
	c.kernel(h, name, kern)
}

// splitKernel takes the kernel packages' vulnerabilities out of the report (it is changed in place).
func (c *collector) splitKernel(h *hostRun, rep *pyjson.Object) []*pyjson.Object {
	src := map[string]string{}
	for _, x := range h.pkgs {
		src[pystr(get(x, "name"))] = sget(x, "source_name")
	}
	var kern []*pyjson.Object
	var rest []pyjson.Value
	for _, r := range lget(rep, "Results") {
		ro := obj(r)
		var keep []pyjson.Value
		for _, v := range lget(ro, "Vulnerabilities") {
			pkg := sget(obj(v), "PkgName")
			if isKernelPkg(pkg, src[pkg]) {
				kern = append(kern, obj(v))
			} else {
				keep = append(keep, v)
			}
		}
		if ro != nil {
			ro.Set("Vulnerabilities", keep)
		}
		rest = append(rest, r)
	}
	rep.Set("Results", rest)
	return kern
}

func (c *collector) kernel(h *hostRun, name string, kern []*pyjson.Object) {
	running := sget(h.plat, "kernel_running")
	var fixOrder []string
	fixable := map[string]*pyjson.Object{}
	runningPkgs, all := map[string]bool{}, map[string]bool{}
	for _, v := range kern {
		pkg := sget(v, "PkgName")
		all[pkg] = true
		if !kernelRunningPkg(pkg, running) {
			continue
		}
		runningPkgs[pkg] = true
		if id := pystr(get(v, "VulnerabilityID")); truthy(v, "FixedVersion") {
			if fixable[id] == nil {
				fixOrder = append(fixOrder, id)
			}
			fixable[id] = v
		}
	}
	var stale []string
	for p := range all {
		if !runningPkgs[p] {
			stale = append(stale, p)
		}
	}
	sort.Strings(stale)
	if len(fixOrder) > 0 {
		c.kernelFinding(h, fixOrder, fixable, stale)
	}
	c.doc.Metric("security_host_kernel_cves_fixable", float64(len(fixOrder)),
		"CVEs of the running kernel fixed in a newer kernel", map[string]string{"host": name})
}

// kernelFixes summarises the running kernel's fixable CVEs: those in KEV, how many are critical, the newest fixed
// version, the earliest publication.
type kernelFixes struct {
	kev          []string
	crit         int
	fixedTo, pub string
}

func (c *collector) kernelSummary(order []string, fixable map[string]*pyjson.Object) kernelFixes {
	var k kernelFixes
	for i, id := range order {
		v := fixable[id]
		if c.in.kev.has(id) {
			k.kev = append(k.kev, id)
		}
		if get(v, "Severity") == "CRITICAL" {
			k.crit++
		}
		fv := pystr(get(v, "FixedVersion"))
		if i == 0 || newVtuple(fv).compare(newVtuple(k.fixedTo)) > 0 {
			k.fixedTo = fv
		}
		p := cut(pystr(or(get(v, "PublishedDate"), "9999")), 10)
		if i == 0 || p < k.pub {
			k.pub = p
		}
	}
	sort.Strings(k.kev)
	return k
}

func (c *collector) kernelFinding(h *hostRun, order []string, fixable map[string]*pyjson.Object, stale []string) {
	k := c.kernelSummary(order, fixable)
	kevK, crit, fixedTo, pub := k.kev, k.crit, k.fixedTo, k.pub
	sev := "medium"
	switch {
	case len(kevK) > 0 && pyjson.Truthy(h.meta.exposed):
		sev = "critical"
	case len(kevK) > 0 || crit > 0:
		sev = "high"
	}
	key := h.asset + "|kernel"
	c.evidence.Set(key, pyjson.ObjectOf("running", get(h.plat, "kernel_running"), "cves", int64(len(order)),
		"critical", int64(crit), "kev", list(kevK), "fixed_in", fixedTo, "other_installed_kernel_packages", list(firstN(stale, 20))))
	kevNote := ""
	if len(kevK) > 0 {
		kevNote = ", KEV " + strings.Join(kevK, " ")
	}
	base := "high"
	if crit > 0 {
		base = "critical"
	}
	c.doc.AddFinding(&rundoc.Finding{Layer: "supply-chain", Asset: h.asset, Check: "vuln.kernel_fixes_available",
		Title: "running kernel " + pystr(get(h.plat, "kernel_running")) + ": " + itoa(len(order)) + " CVEs fixed in " +
			fixedTo + " (" + itoa(crit) + " critical" + kevNote + ")", Severity: sev,
		Evidence: "raw/vuln-intel/matches.json#" + key, Remediation: "install the fixed kernel and reboot into it (planned maintenance)",
		Kind: "vulnerability", Refs: list(firstN(kevK, 10)), Attributes: pyjson.ObjectOf("cve", first(kevK), "kev", len(kevK) > 0,
			"alertable", len(kevK) > 0, "exposed", h.meta.exposed, "prod", h.meta.prod, "base_severity", base,
			"published_at", pub, "kev_added", c.maxKEVAdded(kevK), "matcher", "trivy")})
}

// maxKEVAdded is the latest KEV date_added of the CVEs (None without any).
func (c *collector) maxKEVAdded(cves []string) pyjson.Value {
	var best pyjson.Value
	for _, x := range cves {
		d := c.kevAdded(x)
		if best == nil || pystr(d) > pystr(best) {
			best = d
		}
	}
	return best
}

func (c *collector) fsSBOM(ctx context.Context, h *hostRun) (sbomTarget, bool) {
	rel := sget(h.plat, "fs_sbom")
	if rel == "" {
		return sbomTarget{}, false
	}
	p := filepath.Join(c.dataDir, rel)
	if !exists(p) {
		return sbomTarget{}, false
	}
	rep, note := c.match(ctx, p)
	if rep == nil {
		h.gap("fs-packages", note)
		return sbomTarget{}, false
	}
	h.parts.Set("fs-packages", "ok")
	c.handle(h.asset, h.meta, rep)
	return sbomTarget{asset: h.asset, rel: rel, meta: h.meta}, true
}

// hostCoverage: a host is covered only when every matcher that applies to it covered it.
func (c *collector) hostCoverage(hcov *pyjson.Object, plats map[string]*pyjson.Object) {
	vendors := map[string]bool{}
	for _, p := range plats {
		if v, ok := getOK(oget(p, "firmware"), "vendor"); ok && v != nil {
			vendors[pystr(v)] = true
		}
	}
	c.doc.Metric("security_intel_firmware_vendors_without_source", float64(len(vendors)),
		"Firmware vendors in scope without a readable advisory source (only KEV covers them)", nil)
	for _, a := range hcov.Keys() {
		parts := obj(get(hcov, a))
		var bad []string
		for _, k := range parts.Keys() {
			if v := sget(parts, k); v != "ok" {
				bad = append(bad, k+" "+v)
			}
		}
		switch {
		case parts.Len() == 0:
			c.doc.Gap(a, "no matcher applies (no distro packages, fs SBOM, platform feed or firmware vendor)", nil)
		case len(bad) > 0:
			c.doc.Gap(a, "partial: "+strings.Join(bad, "; "), nil)
		default:
			c.doc.OK(a, "")
		}
	}
	if _, err := c.doc.Raw(c.runDir, "host-coverage.json", hcov); err != nil {
		c.rawErr = err
	}
}
