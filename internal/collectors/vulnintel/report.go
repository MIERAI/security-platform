package vulnintel

import (
	"path/filepath"
	"strings"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

const maxSBOM = 512 << 20

func getOKMap(v any, key string) (any, bool) {
	m := rundoc.Map(v)
	if m == nil {
		return nil, false
	}
	return m.Get(key)
}

// osvMatches is the second, independent matcher: SBOM components against the OSV export; findings only for KEV
// aliases or critical advisories.
func (c *collector) osvMatches(targets []sbomTarget) {
	if len(c.in.osv) == 0 {
		return
	}
	hits := 0
	for _, t := range targets {
		data, err := rundoc.ReadLimited(filepath.Join(c.dataDir, t.rel), maxSBOM)
		if err != nil {
			continue // as the Python collector: an unreadable SBOM is skipped here (its trivy match decided coverage)
		}
		v, err := pyjson.Decode(data)
		if err != nil || obj(v) == nil {
			continue
		}
		for _, h := range osvMatch(components(obj(v)), c.in.osv) {
			hits++
			c.osvFinding(t, h)
		}
	}
	c.doc.Metric("security_vuln_osv_matches", float64(hits), "Component x advisory matches found by the OSV matcher", nil)
}

func (c *collector) osvFinding(t sbomTarget, h osvHit) {
	var cves []string
	for _, a := range h.adv.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			cves = append(cves, a)
		}
	}
	kevC := c.kevOf(cves)
	if len(kevC) == 0 && h.adv.Severity != "critical" {
		return
	}
	vid := h.adv.ID
	if len(cves) > 0 {
		vid = cves[0]
	}
	exposed := t.meta.exposed
	prio := "high"
	if pyjson.Truthy(exposed) {
		prio = "critical"
	}
	fixed := fixedVersion(h.adv)
	attrs := pyjson.ObjectOf("cve", vid, "osv_id", h.adv.ID, "package", h.comp.name, "installed", h.comp.version, "fixed", fixed,
		"base_severity", or(h.adv.Severity, "unknown"), "published_at", cut(h.adv.Published, 10), "kev", len(kevC) > 0,
		"kev_added", c.firstKEVAdded(cves), "epss", c.maxEPSS(cves), "exposed", exposed, "prod", t.meta.prod,
		"clusters", list(sortedCopy(t.meta.clusters)), "target", h.comp.eco, "matcher", "osv")
	attrs.Set("alertable", len(kevC) > 0 || (h.adv.Severity == "critical" && pyjson.Truthy(exposed)))
	key := t.asset + "|" + vid
	c.evidence.Set(key, attrs)
	title := vid + " in " + h.comp.name + " " + h.comp.version
	rem := "mitigate (reduce exposure) / watch for a fix"
	if fixed != "" {
		title += " (fix " + fixed + ")"
		rem = "update " + h.comp.name + " to " + fixed
	} else {
		title += " (no fix yet)"
	}
	if len(kevC) > 0 {
		title += " [KEV]"
	}
	c.doc.AddFinding(&rundoc.Finding{Layer: "supply-chain", Asset: t.asset, Check: "vuln." + strings.ToLower(vid),
		Title: title + " [OSV]", Severity: prio, Evidence: "raw/vuln-intel/matches.json#" + key, Remediation: rem,
		Kind: "vulnerability", Refs: []pyjson.Value{vid, h.adv.ID}, Attributes: attrs})
}

func (c *collector) firstKEVAdded(cves []string) pyjson.Value {
	for _, x := range cves {
		if c.in.kev.has(x) {
			return c.kevAdded(x)
		}
	}
	return nil
}

// maxEPSS is max(epss of the aliases, 0) or None, as the Python expression.
func (c *collector) maxEPSS(cves []string) pyjson.Value {
	var best pyjson.Value = int64(0)
	bf := 0.0
	for _, x := range cves {
		if f, ok := c.in.epss[x]; ok && f != 0 && f > bf {
			best, bf = f, f
		}
	}
	if !pyjson.Truthy(best) {
		return nil
	}
	return best
}

// finish writes the evidence and the run's metrics.
func (c *collector) finish(imgs *imageSet) error {
	for _, k := range sortedKeys(c.unmatched) {
		c.doc.Metric("security_sbom_unmatched_packages", float64(c.unmatched[k]),
			"Inventoried host packages without a structured advisory source", map[string]string{"kind": k})
	}
	images := pyjson.NewObject()
	sboms := 0
	for _, ref := range imgs.order {
		im := imgs.byRef[ref]
		images.Set(ref, im.json())
		if nonEmpty(im.report) {
			sboms++
		}
	}
	for _, f := range []struct {
		name string
		v    pyjson.Value
	}{{"matches.json", c.evidence}, {"high-aggregate.json", c.high}, {"images.json", images}} {
		if _, err := c.doc.Raw(c.runDir, f.name, f.v); err != nil {
			return err
		}
	}
	if c.rawErr != nil {
		return c.rawErr
	}
	c.metrics(sboms)
	return nil
}

func (c *collector) metrics(sboms int) {
	m := c.doc.Metric
	m("security_vuln_oldest_fixable_critical_days", pyvalue.Round(c.tally.oldestFixableCrit, 1),
		"Age (since publication) of the oldest CRITICAL CVE with a fix, in running images/repos", nil)
	m("security_vuln_matches", float64(c.tally.critical), "Vulnerability matches", map[string]string{"severity": "critical"})
	m("security_vuln_matches", float64(c.tally.high), "Vulnerability matches", map[string]string{"severity": "high"})
	m("security_vuln_kev_matches", float64(c.tally.kev), "Matches that are in CISA KEV", nil)
	m("security_sbom_images", float64(sboms), "Images with an SBOM", nil)
	alertable := 0
	for _, f := range c.doc.Findings() {
		if truthy(oget(f, "attributes"), "alertable") {
			alertable++
		}
	}
	m("security_vuln_alertable_matches", float64(alertable),
		"Matches that affect our assets AND (KEV OR critical+exposed): the only class that pages", nil)
}
