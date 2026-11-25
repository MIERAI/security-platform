package vulnintel

import (
	"math"
	"sort"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
)

// matchMeta is what an asset adds to a match: exposure, production, clusters (the attribute values as the
// inventory gave them).
type matchMeta struct {
	exposed, prod pyjson.Value
	clusters      []string
}

// tally is the run's counters over every match.
type tally struct {
	critical, high, kev int
	oldestFixableCrit   float64
}

// score is the first CVSS v3 score of nvd, ghsa, redhat that is set.
func score(v *pyjson.Object) pyjson.Value {
	for _, src := range []string{"nvd", "ghsa", "redhat"} {
		if s := get(oget(oget(v, "CVSS"), src), "V3Score"); pyjson.Truthy(s) {
			return s
		}
	}
	return nil
}

type vulnRow struct {
	target string
	v      *pyjson.Object
}

func vulns(rep *pyjson.Object) []vulnRow {
	var out []vulnRow
	for _, r := range lget(rep, "Results") {
		for _, v := range lget(obj(r), "Vulnerabilities") {
			out = append(out, vulnRow{pystr(getOr(obj(r), "Target", "")), obj(v)})
		}
	}
	return out
}

// handle is the Python collector's handle(): every match of one asset's report, prioritised by intel x exposure.
func (c *collector) handle(asset string, m *matchMeta, rep *pyjson.Object) {
	var highFixable []string
	for _, row := range vulns(rep) {
		v := row.v
		cve := pystr(get(v, "VulnerabilityID"))
		sev := strings.ToLower(pystr(getOr(v, "Severity", "UNKNOWN")))
		fixed := pystr(or(get(v, "FixedVersion"), ""))
		c.count(sev, fixed, pystr(or(get(v, "PublishedDate"), "")), c.in.kev.has(cve))
		attrs := c.trivyAttrs(row, m, sev, fixed)
		if c.in.kev.has(cve) || sev == "critical" {
			c.vulnFinding(asset, v, attrs)
		} else if sev == "high" && fixed != "" {
			highFixable = append(highFixable, cve)
		}
	}
	if len(highFixable) == 0 {
		return
	}
	set := sortedSet(highFixable)
	sev := "low"
	if pyjson.Truthy(m.exposed) {
		sev = "medium"
	}
	c.doc.AddFinding(&rundoc.Finding{Layer: "supply-chain", Asset: asset, Check: "vuln.high_fixable_aggregate",
		Title: itoa(len(set)) + " HIGH CVEs with available fixes", Severity: sev,
		Evidence: "raw/vuln-intel/high-aggregate.json#" + asset, Remediation: "rebuild on a patched base / bump dependencies",
		Kind: "vulnerability", Attributes: pyjson.ObjectOf("count", int64(len(set)))})
	c.high.Set(asset, list(set))
}

func (c *collector) count(sev, fixed, pub string, inKEV bool) {
	switch sev {
	case "critical":
		c.tally.critical++
	case "high":
		c.tally.high++
	}
	if inKEV {
		c.tally.kev++
	}
	if sev != "critical" || fixed == "" || pub == "" {
		return
	}
	if t, err := time.Parse("2006-01-02", cut(pub, 10)); err == nil {
		c.tally.oldestFixableCrit = math.Max(c.tally.oldestFixableCrit, (c.nowEpoch-float64(t.Unix()))/86400)
	}
}

func (c *collector) epssOf(cve string) (float64, bool) {
	f, ok := c.in.epss[cve]
	return f, ok
}

func (c *collector) kevAdded(cve string) pyjson.Value {
	if !c.in.kev.has(cve) {
		return nil
	}
	return get(c.in.kev.byCVE[cve].obj, "date_added")
}

func (c *collector) trivyAttrs(row vulnRow, m *matchMeta, sev, fixed string) *pyjson.Object {
	v := row.v
	cve := pystr(get(v, "VulnerabilityID"))
	var ep pyjson.Value
	if f, ok := c.epssOf(cve); ok {
		ep = f
	}
	in := c.in.kev.has(cve)
	a := pyjson.ObjectOf("cve", cve, "package", get(v, "PkgName"), "installed", get(v, "InstalledVersion"), "fixed", fixed,
		"cvss", score(v), "base_severity", sev, "published_at", cut(pystr(or(get(v, "PublishedDate"), "")), 10), "kev", in,
		"kev_added", c.kevAdded(cve), "epss", ep, "exposed", m.exposed, "prod", m.prod, "clusters", list(sortedCopy(m.clusters)),
		"target", row.target, "matcher", "trivy")
	a.Set("alertable", in || (sev == "critical" && pyjson.Truthy(m.exposed)))
	return a
}

func sortedCopy(ss []string) []string {
	out := append([]string(nil), ss...)
	sort.Strings(out)
	return out
}

// priority: KEV -> critical when exposed; critical -> critical when exposed and fixable; EPSS >= 0.5 one step up;
// outside production at most high (unless KEV).
func (c *collector) priority(cve, sev string, attrs *pyjson.Object) string {
	in := c.in.kev.has(cve)
	exposed := truthy(attrs, "exposed")
	prio := "high"
	if (in && exposed) || (!in && exposed && truthy(attrs, "fixed")) {
		prio = "critical"
	}
	if ep, ok := c.epssOf(cve); ok && ep >= 0.5 {
		prio = rundoc.Bump(prio, 1)
	}
	if !truthy(attrs, "prod") && prio == "critical" && !in {
		prio = "high"
	}
	_ = sev // the base severity decided that there is a finding at all
	return prio
}

func (c *collector) vulnFinding(asset string, v, attrs *pyjson.Object) {
	cve := pystr(get(v, "VulnerabilityID"))
	fixed := sget(attrs, "fixed")
	pkg, inst := pystr(get(v, "PkgName")), pystr(get(v, "InstalledVersion"))
	key := asset + "|" + cve
	c.evidence.Set(key, attrs)
	title := cve + " in " + pkg + " " + inst
	rem := "mitigate (reduce exposure) / watch for a fix"
	if fixed != "" {
		title += " (fix " + fixed + ")"
		rem = "update " + pkg + " to " + fixed
	} else {
		title += " (no fix yet)"
	}
	if c.in.kev.has(cve) {
		title += " [KEV]"
	}
	c.doc.AddFinding(&rundoc.Finding{Layer: "supply-chain", Asset: asset, Check: "vuln." + strings.ToLower(cve), Title: title,
		Severity: c.priority(cve, sget(attrs, "base_severity"), attrs), Evidence: "raw/vuln-intel/matches.json#" + key,
		Remediation: rem, Kind: "vulnerability", Refs: []pyjson.Value{cve}, Attributes: attrs})
}
