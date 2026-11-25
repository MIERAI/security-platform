package vulnintel

import (
	"context"
	"os"
	"sort"
	"strings"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
)

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// platform matches the host's platform advisories: one finding per missed release, so that time-to-know is
// measured per advisory.
func (c *collector) platform(ctx context.Context, h *hostRun) {
	switch strings.ToLower(sget(h.plat, "os_family")) {
	case "android":
		c.android(h)
	case "macos":
		c.apple(ctx, h)
	case "windows":
		c.windows(h)
	}
}

func (c *collector) kevOf(cves []string) []string {
	var out []string
	for _, x := range cves {
		if c.in.kev.has(x) {
			out = append(out, x)
		}
	}
	return out
}

func kevSuffix(prefix string, kevC []string) string {
	if len(kevC) == 0 {
		return ""
	}
	return prefix + strings.Join(kevC, " ")
}

func (c *collector) android(h *hostRun) {
	if c.in.android == nil {
		h.gap("platform", "feed android-bulletins not configured or unavailable")
		return
	}
	missed, ok := androidMissed(h.plat, c.in.android)
	if !ok {
		h.gap("platform", "security patch level unknown")
		return
	}
	h.parts.Set("platform", "ok")
	for _, b := range missed {
		var aliases []string
		crit := 0
		for _, e := range b.entries {
			for _, a := range e.Aliases {
				if strings.HasPrefix(a, "CVE-") {
					aliases = append(aliases, a)
				}
			}
			if e.Severity == "critical" {
				crit++
			}
		}
		cves := sortedSet(aliases)
		c.bulletinFinding(h, b, cves, c.kevOf(cves), crit)
	}
}

func (c *collector) bulletinFinding(h *hostRun, b bulletin, cves, kevC []string, crit int) {
	sev := "medium"
	switch {
	case len(kevC) > 0 && pyjson.Truthy(h.meta.exposed):
		sev = "critical"
	case len(kevC) > 0 || crit > 0:
		sev = "high"
	}
	key := h.asset + "|asb-" + b.spl
	c.evidence.Set(key, pyjson.ObjectOf("patch_level", get(h.plat, "patch_level"), "bulletin_spl", b.spl,
		"issues", int64(len(b.entries)), "critical", int64(crit), "kev", list(kevC), "cves", list(firstN(cves, 200))))
	c.doc.AddFinding(&rundoc.Finding{Layer: "host", Asset: h.asset, Check: "platform.android_bulletin." + b.spl,
		Title: "Android security patch level " + pystr(get(h.plat, "patch_level")) + " lacks bulletin " + b.spl + ": " +
			itoa(len(b.entries)) + " issues (" + itoa(crit) + " critical" + kevSuffix(", KEV ", kevC) + ")",
		Severity: sev, Evidence: "raw/vuln-intel/matches.json#" + key, NeedsHuman: true, Kind: "vulnerability",
		Remediation: "install the vendor OTA with this patch level (if the vendor stopped updates: retire/isolate the device)",
		Refs:        list(firstN(kevC, 10)), Attributes: pyjson.ObjectOf("advisory", "android-bulletin-"+b.spl, "cve", first(kevC),
			"kev", len(kevC) > 0, "alertable", len(kevC) > 0, "exposed", h.meta.exposed, "published_at", b.spl,
			"kev_added", c.kevAddedIf(kevC), "base_severity", baseSeverity(crit), "matcher", "android-bulletins")})
}

func baseSeverity(crit int) string {
	if crit > 0 {
		return "critical"
	}
	return "high"
}

func (c *collector) kevAddedIf(kevC []string) pyjson.Value {
	if len(kevC) == 0 {
		return nil
	}
	return c.maxKEVAdded(kevC)
}

func (c *collector) apple(ctx context.Context, h *hostRun) {
	if c.in.apple == nil {
		h.gap("platform", "feed apple-security-releases not configured or unavailable")
		return
	}
	h.parts.Set("platform", "ok")
	missed, _ := appleMissed(h.plat, c.in.apple)
	for _, r := range missed {
		var cves []string
		if r.HasURL && r.URL != "" {
			got, err := c.appleReleaseCVEs(ctx, r.URL)
			if err != nil {
				h.gap("platform-cves", "apple release page: "+err.Error())
			}
			cves = got
		}
		c.appleFinding(h, r, cves, c.kevOf(cves))
	}
}

func (c *collector) appleFinding(h *hostRun, r *appleRelease, cves, kevC []string) {
	sev := "medium"
	if len(kevC) > 0 {
		sev = "high"
		if pyjson.Truthy(h.meta.exposed) {
			sev = "critical"
		}
	}
	key := h.asset + "|" + r.Name
	c.evidence.Set(key, pyjson.ObjectOf("installed", get(h.plat, "os_version"), "release", r.json(), "cves", list(cves),
		"kev", list(kevC)))
	url := ""
	if r.HasURL {
		url = r.URL
	}
	c.doc.AddFinding(&rundoc.Finding{Layer: "host", Asset: h.asset, Check: "platform.apple_release." + r.Version,
		Title: r.Name + " (" + r.Date + ") not installed (host " + pystr(get(h.plat, "os_version")) + "): " + itoa(len(cves)) +
			" CVEs" + kevSuffix(", KEV ", kevC), Severity: sev, Evidence: "raw/vuln-intel/matches.json#" + key,
		Remediation: "install " + r.Name, NeedsHuman: true, Kind: "vulnerability", Refs: append(list(firstN(kevC, 10)), url),
		Attributes: pyjson.ObjectOf("advisory", r.Name, "cve", first(kevC), "kev", len(kevC) > 0, "alertable", len(kevC) > 0,
			"exposed", h.meta.exposed, "published_at", r.Date, "kev_added", c.kevAddedIf(kevC), "base_severity", "high",
			"matcher", "apple-security-releases")})
}

func (c *collector) windows(h *hostRun) {
	if c.in.msrc == nil {
		h.gap("platform", "feed msrc-cvrf not configured or unavailable")
		return
	}
	missed, prod, ok := windowsMissed(h.plat, c.in.msrc)
	if !ok {
		h.gap("platform", "product "+reprOrNone(prod)+" not found in the MSRC documents")
		return
	}
	h.parts.Set("platform", "ok")
	for _, m := range missed {
		c.windowsFinding(h, prod, m)
	}
}

func reprOrNone(prod string) string {
	if prod == "" {
		return "None"
	}
	return pyjson.Repr(prod)
}

func (c *collector) windowsFinding(h *hostRun, prod string, m missedUpdate) {
	var cves, exploited, kbs, builds []string
	crit := 0
	for _, it := range m.items {
		if pyjson.Truthy(it.CVE) {
			cves = append(cves, pystr(it.CVE))
		}
		if it.Exploited {
			exploited = append(exploited, pystr(it.CVE))
		}
		if it.Severity == "critical" {
			crit++
		}
		kbs, builds = append(kbs, it.KB), append(builds, it.FixedBuild)
	}
	cves = sortedSet(cves)
	kevC := sortedSet(append(c.kevOf(cves), exploited...))
	sev := "medium"
	switch {
	case len(kevC) > 0 && pyjson.Truthy(h.meta.exposed):
		sev = "critical"
	case len(kevC) > 0 || crit > 0:
		sev = "high"
	}
	key := h.asset + "|" + m.release
	c.evidence.Set(key, pyjson.ObjectOf("build", get(h.plat, "os_build"), "product", prod, "release", m.release, "cves", list(cves),
		"kev_or_exploited", list(kevC), "kbs", list(sortedSet(kbs)), "fixed_builds", list(sortedSet(builds))))
	c.doc.AddFinding(&rundoc.Finding{Layer: "host", Asset: h.asset, Check: "platform.windows_update." + strings.ToLower(m.release),
		Title: m.release + " security update not installed (build " + pystr(get(h.plat, "os_build")) + "): " + itoa(len(cves)) +
			" CVEs (" + itoa(crit) + " critical" + kevSuffix(", exploited ", kevC) + ")", Severity: sev,
		Evidence: "raw/vuln-intel/matches.json#" + key, Remediation: "run Windows Update (cumulative update)", NeedsHuman: true,
		Kind: "vulnerability", Refs: list(firstN(kevC, 10)), Attributes: pyjson.ObjectOf("advisory", "msrc-"+m.release,
			"cve", first(kevC), "kev", len(kevC) > 0, "alertable", len(kevC) > 0, "exposed", h.meta.exposed,
			"published_at", m.date, "base_severity", baseSeverity(crit), "matcher", "msrc-cvrf")})
}

// firmware: KEV entries of the firmware's vendor added after its build date are CANDIDATES for a human.
func (c *collector) firmware(h *hostRun) {
	fw := oget(h.plat, "firmware")
	if !truthy(fw, "vendor") {
		return
	}
	h.parts.Set("firmware-kev", "ok")
	vendor := pystr(get(fw, "vendor"))
	names := []string{vendor}
	if v, ok := getOKMap(c.cfg.Value("firmware_vendors"), vendor); ok {
		names = rundoc.Strings(v)
	}
	for _, k := range vendorKEV(h.plat, c.in.kev, names) {
		cve := sget(k, "cve")
		key := h.asset + "|" + cve
		c.evidence.Set(key, pyjson.ObjectOf("firmware", fw, "kev", k))
		sev := "high"
		if pyjson.Truthy(h.meta.exposed) {
			sev = "critical"
		}
		c.doc.AddFinding(&rundoc.Finding{Layer: "host", Asset: h.asset, Check: "vuln." + strings.ToLower(cve),
			Title: cve + " (KEV, " + pystr(get(k, "vendor")) + " " + pystr(get(k, "product")) + ") added " +
				pystr(get(k, "date_added")) + " after the firmware build " + pystr(get(fw, "build_date")) +
				": CANDIDATE - verify the model/version against the vendor advisory", Severity: sev,
			Evidence: "raw/vuln-intel/matches.json#" + key, NeedsHuman: true, Kind: "vulnerability",
			Remediation: "check the vendor advisory for this model; update firmware or isolate", Refs: []pyjson.Value{cve},
			Attributes: pyjson.ObjectOf("cve", cve, "kev", true, "kev_added", get(k, "date_added"), "published_at",
				get(k, "date_added"), "alertable", true, "exposed", h.meta.exposed, "candidate", true, "matcher", "kev-vendor")})
	}
}

// sortedKeys of a string-keyed count map.
func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
