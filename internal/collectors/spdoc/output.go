package spdoc

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/ledger/fileio"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// Doc is the findings document as a JSON value, finished at `finished`.
func (d *Document) Doc(finished time.Time) map[string]any {
	cov := make([]any, len(d.covOrder))
	for i, k := range d.covOrder {
		c := d.coverage[k]
		m := map[string]any{"asset": c.asset, "status": c.status}
		if c.status == "gap" {
			m["reason"] = c.reason
		}
		if c.checks != nil {
			m["checks"] = c.checks
		}
		cov[i] = m
	}
	findings := make([]any, len(d.findings))
	for i := range d.findings {
		findings[i] = d.findings[i].json()
	}
	metrics := make([]any, len(d.metrics))
	for i, m := range d.metrics {
		labels := m.labels
		if labels == nil {
			labels = map[string]string{}
		}
		metrics[i] = map[string]any{"name": m.name, "value": m.value, "labels": labels, "help": m.help}
	}
	return map[string]any{"schema_version": schemaVersion,
		"collector": map[string]any{"name": d.name, "version": d.version, "tools": map[string]any{}},
		"run":       map[string]any{"started_at": iso(d.started), "finished_at": iso(finished), "instance": d.instance},
		"coverage":  cov, "findings": findings, "metrics": metrics}
}

func (f *finding) json() map[string]any {
	owner := "platform"
	if f.NeedsHuman {
		owner = "human"
	}
	return map[string]any{"id": f.id, "check": f.Check, "layer": f.Layer, "asset": f.Asset, "title": f.Title,
		"severity": f.Severity, "evidence": f.Evidence, "remediation": f.Remediation, "needs_human": f.NeedsHuman,
		"owner": owner, "observed_at": f.observed, "kind": "compliance"}
}

// Write writes <name>.findings.json and <name>.prom into dir, each in one step (a private temporary file, then a
// rename), mode 0600.
func (d *Document) Write(dir string) error {
	finished := d.now()
	data, err := Marshal(d.Doc(finished), 1, true)
	if err != nil {
		return fmt.Errorf("encode findings: %w", err)
	}
	if err := fileio.Write(filepath.Join(dir, d.name+".findings.json"), data); err != nil {
		return fmt.Errorf("write findings: %w", err)
	}
	if err := fileio.Write(filepath.Join(dir, d.name+".prom"), []byte(d.prom(finished))); err != nil {
		return fmt.Errorf("write metrics: %w", err)
	}
	return nil
}

// Raw stores evidence (already filtered: never a secret value) as raw/<name>/<file> in dir, JSON as the Python SDK
// writes it (indent 1, keys sorted), and returns the evidence pointer "raw/<name>/<file>".
func (d *Document) Raw(dir, file string, v any) (string, error) {
	data, err := Marshal(v, 1, true)
	if err != nil {
		return "", fmt.Errorf("encode evidence: %w", err)
	}
	rd := filepath.Join(dir, "raw", d.name)
	if err := os.MkdirAll(rd, 0o700); err != nil {
		return "", fmt.Errorf("create evidence directory: %w", err)
	}
	if err := fileio.Write(filepath.Join(rd, file), data); err != nil {
		return "", fmt.Errorf("write evidence: %w", err)
	}
	return "raw/" + d.name + "/" + file, nil
}

type series struct {
	name, value, help string
	labels            map[string]string
}

// prom is the Prometheus text of the document: the generic per-collector series, then the collector's own.
func (d *Document) prom(finished time.Time) string {
	counts := map[[2]string]int{}
	for i := range d.findings {
		counts[[2]string{d.findings[i].Layer, d.findings[i].Severity}]++
	}
	keys := make([][2]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i][0] != keys[j][0] {
			return keys[i][0] < keys[j][0]
		}
		return keys[i][1] < keys[j][1]
	})
	var out []series
	for _, k := range keys {
		out = append(out, series{"security_collector_findings", strconv.Itoa(counts[k]),
			"Findings reported by the latest run of a collector",
			map[string]string{"collector": d.name, "layer": k[0], "severity": k[1]}})
	}
	gaps := 0
	for _, c := range d.coverage {
		if c.status == "gap" {
			gaps++
		}
	}
	one := map[string]string{"collector": d.name}
	out = append(out,
		series{"security_collector_gaps", strconv.Itoa(gaps), "Assets the collector could not cover", one},
		series{"security_collector_assets", strconv.Itoa(len(d.coverage)), "Assets in scope of the run", one},
		series{"security_collector_last_run_timestamp_seconds", strconv.FormatInt(finished.Unix(), 10),
			"Heartbeat: when the collector last finished (no findings != secure)", one})
	for _, m := range d.metrics {
		labels := map[string]string{}
		for k, v := range m.labels {
			labels[k] = v
		}
		labels["collector"] = d.name
		out = append(out, series{m.name, pyvalue.FormatG(m.value), m.help, labels})
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
	keys := sortedKeys(labels)
	parts := make([]string, len(keys))
	esc := strings.NewReplacer(`\`, "/", `"`, "'", "\n", " ")
	for i, k := range keys {
		parts[i] = k + `="` + esc.Replace(labels[k]) + `"`
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// WriteFile writes a JSON value into dir/<file> (an inventory document) as Python's json.dump(v, f, indent=indent)
// without sort_keys: insertion order of *pyvalue.Map values.
func WriteFile(dir, file string, v any, indent int) error {
	data, err := Marshal(v, indent, false)
	if err != nil {
		return fmt.Errorf("encode %s: %w", file, err)
	}
	if err := fileio.Write(filepath.Join(dir, file), data); err != nil {
		return fmt.Errorf("write %s: %w", file, err)
	}
	return nil
}
