package cloud

import (
	"sort"
	"strings"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
)

// emit turns the merged pool into findings, in (asset, check) order.
func (c *collector) emit() {
	for _, f := range c.pool.Sorted() {
		short := f.Asset
		if strings.Count(f.Asset, "/") >= 3 {
			short = strings.SplitN(f.Asset, "/", 4)[3]
		}
		engineSet := map[string]bool{}
		for _, s := range f.Sources {
			engineSet[s.Source] = true
		}
		engs := make([]string, 0, len(engineSet))
		for e := range engineSet {
			engs = append(engs, e)
		}
		sort.Strings(engs)
		c.doc.AddFinding(finding(&Finding{Layer: f.Layer, Asset: f.Asset, Check: f.Check, Title: f.Title + ": " + short,
			Severity: f.Severity, Evidence: "raw/" + c.doc.Name + "/" + f.Provider + "-" + f.Account + ".json#" + f.Asset,
			Remediation: f.Remediation, Refs: f.Refs, Attributes: map[string]any{"pillar": f.Pillar, "provider": f.Provider,
				"account": f.Account, "sources": sourcesJSON(f.Sources), "engines": engs, "source_count": len(engs),
				"cis_benchmark": f.CISBenchmark}}))
	}
}

func sourcesJSON(srcs []Source) []any {
	out := make([]any, len(srcs))
	for i, s := range srcs {
		out[i] = map[string]any{"source": s.Source, "check": s.Check, "detail": s.Detail}
	}
	return out
}

// write writes the evidence, the metrics and the document.
func (c *collector) write(runDir string) error {
	keys := make([]evKey, 0, len(c.evidence))
	for k := range c.evidence {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].provider != keys[j].provider {
			return keys[i].provider < keys[j].provider
		}
		return keys[i].account < keys[j].account
	})
	for _, k := range keys {
		if _, err := c.doc.Raw(runDir, k.provider+"-"+k.account+".json", rundoc.JSON(c.evidenceJSON(k))); err != nil {
			return err
		}
	}
	c.metrics()
	return c.doc.Write(runDir, c.stderr)
}

func (c *collector) evidenceJSON(k evKey) map[string]any {
	ev := c.evidence[k]
	m := map[string]any{"engines": ev.engines, "imports": ev.imports}
	if ev.identity != nil {
		m["identity"] = ev.identity
	}
	if ev.selfCheck != nil {
		m["self_check"] = ev.selfCheck
	}
	findings := map[string]any{}
	for _, f := range c.pool.Items() {
		if f.Provider == k.provider && f.Account == k.account {
			findings[f.Asset] = map[string]any{"check": f.Check, "pillar": f.Pillar, "sources": sourcesJSON(f.Sources)}
		}
	}
	m["findings"] = findings
	return m
}

func (c *collector) metrics() {
	for _, st := range []struct {
		state string
		n     int
	}{{"scanned", c.stats.scanned}, {"gap", c.stats.gap}, {"refused", c.stats.refused}} {
		c.doc.Metric("security_cloud_accounts", float64(st.n), "Cloud accounts/projects/subscriptions by scan state",
			map[string]string{"state": st.state})
	}
	runs := make([][2]string, 0, len(c.stats.engines))
	for k := range c.stats.engines {
		runs = append(runs, k)
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i][0]+"\x00"+runs[i][1] < runs[j][0]+"\x00"+runs[j][1] })
	for _, k := range runs {
		c.doc.Metric("security_cloud_engine_runs", float64(c.stats.engines[k]), "Check-engine runs in this collector run",
			map[string]string{"source": k[0], "result": k[1]})
	}
	pillars := map[string]int{}
	for _, f := range c.pool.Items() {
		pillars[f.Pillar]++
	}
	for _, p := range []string{"network", "device", "people", "software"} {
		c.doc.Metric("security_cloud_findings", float64(pillars[p]), "Cloud findings (merged across engines) by pillar",
			map[string]string{"pillar": p})
	}
}
