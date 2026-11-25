package rundoc

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/pyvalue"
)

type series struct {
	name   string
	labels map[string]string
	value  string
	help   string
}

// prom is the Prometheus text of the document (spsdk.to_prom): the generic per-collector series, then the
// collector's own metrics with the label collector=<name>.
func (d *Document) prom(finished time.Time) string {
	counts := map[[2]string]int{}
	for _, f := range d.findings {
		counts[[2]string{f.Str("layer"), f.Str("severity")}]++
	}
	keys := make([][2]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i][0]+"\x00"+keys[i][1] < keys[j][0]+"\x00"+keys[j][1] })
	out := make([]series, 0, len(keys)+4+len(d.metrics))
	for _, k := range keys {
		out = append(out, series{"security_collector_findings", map[string]string{"collector": d.Name, "layer": k[0],
			"severity": k[1]}, strconv.Itoa(counts[k]), "Findings reported by the latest run of a collector"})
	}
	one := map[string]string{"collector": d.Name}
	out = append(out,
		series{"security_collector_gaps", one, strconv.Itoa(d.Gaps()), "Assets the collector could not cover"},
		series{"security_collector_assets", one, strconv.Itoa(d.coverage.Len()), "Assets in scope of the run"},
		series{"security_collector_last_run_timestamp_seconds", one, strconv.FormatInt(finished.Unix(), 10),
			"Heartbeat: when the collector last finished (no findings != secure)"})
	for _, m := range d.metrics {
		labels := map[string]string{}
		for k, v := range m.labels {
			labels[k] = v
		}
		labels["collector"] = d.Name
		out = append(out, series{m.name, labels, pyvalue.FormatG(m.value), m.help})
	}
	return render(out)
}

func render(all []series) string {
	var lines []string
	seen := map[string]bool{}
	for _, s := range all {
		if !seen[s.name] {
			seen[s.name] = true
			if s.help != "" {
				lines = append(lines, "# HELP "+s.name+" "+s.help)
			}
			typ := "gauge"
			if strings.HasSuffix(s.name, "_total") {
				typ = "counter"
			}
			lines = append(lines, "# TYPE "+s.name+" "+typ)
		}
		lines = append(lines, s.name+labelText(s.labels)+" "+s.value)
	}
	return strings.Join(lines, "\n") + "\n"
}

func labelText(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	esc := strings.NewReplacer(`\`, "/", `"`, "'", "\n", " ")
	for i, k := range keys {
		parts[i] = k + `="` + esc.Replace(labels[k]) + `"`
	}
	return "{" + strings.Join(parts, ",") + "}"
}
