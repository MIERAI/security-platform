package cloud

import (
	"crypto/sha1" // #nosec G505 -- the finding id is sha1 by contract (collector-protocol §6), not a security use
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/cloud/dyn"
	"github.com/MIERAI/security-platform/internal/collectors/cloud/pyjson"
)

const schemaVersion = "1.2"

// FindingID is sha1("<layer>|<asset>|<check>")[:12] (collector-protocol §6).
func FindingID(layer, asset, check string) string {
	sum := sha1.Sum([]byte(layer + "|" + asset + "|" + check)) // #nosec G401 -- see the import
	return hex.EncodeToString(sum[:])[:12]
}

// Finding is one finding of the document (findings/v1).
type Finding struct {
	Layer, Asset, Check, Title, Severity, Evidence, Remediation string
	NeedsHuman                                                  bool
	Refs                                                        []string
	Attributes                                                  map[string]any
}

type metric struct {
	name, help string
	value      float64
	labels     map[string]string
}

// Document builds the findings document of one run (what sdk/spsdk.Collector does for Python collectors).
type Document struct {
	Name, Version, Instance string
	Started                 time.Time
	now                     func() time.Time
	findings                []map[string]any
	ids                     map[string]bool
	covKeys                 []string
	coverage                map[string]map[string]any
	metrics                 []metric
	Tools                   map[string]string
}

// NewDocument starts a document.
func NewDocument(name, version, instance string, now func() time.Time) *Document {
	return &Document{Name: name, Version: version, Instance: instance, Started: now(), now: now,
		ids: map[string]bool{}, coverage: map[string]map[string]any{}, Tools: map[string]string{}}
}

func isoUTC(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

// AddFinding records a finding once per (layer, asset, check).
func (d *Document) AddFinding(f *Finding) {
	id := FindingID(f.Layer, f.Asset, f.Check)
	if d.ids[id] {
		return
	}
	d.ids[id] = true
	owner := "platform"
	if f.NeedsHuman {
		owner = "human"
	}
	m := map[string]any{"id": id, "check": f.Check, "layer": f.Layer, "asset": f.Asset, "title": dyn.Cut(f.Title, 300),
		"severity": f.Severity, "evidence": f.Evidence, "remediation": f.Remediation, "needs_human": f.NeedsHuman,
		"owner": owner, "observed_at": isoUTC(d.now()), "kind": "compliance"}
	if len(f.Refs) > 0 {
		m["refs"] = f.Refs
	}
	if len(f.Attributes) > 0 {
		m["attributes"] = f.Attributes
	}
	d.findings = append(d.findings, m)
}

// OK marks an asset covered (a gap recorded before stays a gap).
func (d *Document) OK(asset string) {
	if _, ok := d.coverage[asset]; !ok {
		d.covKeys = append(d.covKeys, asset)
		d.coverage[asset] = map[string]any{"asset": asset, "status": "ok"}
	}
}

// Gap marks an asset not covered, with its reason.
func (d *Document) Gap(asset, reason string) {
	if _, ok := d.coverage[asset]; !ok {
		d.covKeys = append(d.covKeys, asset)
	}
	d.coverage[asset] = map[string]any{"asset": asset, "status": "gap", "reason": dyn.Cut(reason, 300)}
}

// Metric adds one series.
func (d *Document) Metric(name string, value float64, help string, labels map[string]string) {
	d.metrics = append(d.metrics, metric{name: name, value: value, help: help, labels: labels})
}

// Gaps counts the assets that are gaps.
func (d *Document) Gaps() int {
	n := 0
	for _, c := range d.coverage {
		if c["status"] == "gap" {
			n++
		}
	}
	return n
}

// Findings is the number of findings so far.
func (d *Document) Findings() int { return len(d.findings) }

// Assets is the number of assets in the coverage.
func (d *Document) Assets() int { return len(d.coverage) }

// Doc is the findings document as a JSON value.
func (d *Document) Doc(finished time.Time) map[string]any {
	cov := make([]any, len(d.covKeys))
	for i, k := range d.covKeys {
		cov[i] = d.coverage[k]
	}
	findings := make([]any, len(d.findings))
	for i, f := range d.findings {
		findings[i] = f
	}
	metrics := make([]any, len(d.metrics))
	for i, m := range d.metrics {
		labels := map[string]any{}
		for k, v := range m.labels {
			labels[k] = v
		}
		metrics[i] = map[string]any{"name": m.name, "value": m.value, "labels": labels, "help": m.help}
	}
	tools := map[string]any{}
	for k, v := range d.Tools {
		tools[k] = v
	}
	return map[string]any{"schema_version": schemaVersion,
		"collector": map[string]any{"name": d.Name, "version": d.Version, "tools": tools},
		"run":       map[string]any{"started_at": isoUTC(d.Started), "finished_at": isoUTC(finished), "instance": d.Instance},
		"coverage":  cov, "findings": findings, "metrics": metrics}
}

// Write writes <name>.findings.json (in one step: a temporary file, then a rename) and <name>.prom into dir.
func (d *Document) Write(dir string) error {
	finished := d.now()
	data, err := pyjson.Marshal(d.Doc(finished), 1)
	if err != nil {
		return fmt.Errorf("encode findings: %w", err)
	}
	if err := writeAtomic(filepath.Join(dir, d.Name+".findings.json"), data); err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, d.Name+".prom"), []byte(d.prom(finished)))
}

// WriteRaw stores evidence (already filtered: never a secret) as raw/<name>/<file>.
func (d *Document) WriteRaw(dir, file string, v any) error {
	data, err := pyjson.Marshal(v, 1)
	if err != nil {
		return fmt.Errorf("encode evidence: %w", err)
	}
	rd := filepath.Join(dir, "raw", d.Name)
	if err := os.MkdirAll(rd, 0o750); err != nil {
		return fmt.Errorf("create evidence directory: %w", err)
	}
	return writeAtomic(filepath.Join(rd, file), data)
}

func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename %s: %w", filepath.Base(path), err)
	}
	return nil
}

type series struct {
	name   string
	labels map[string]string
	value  string
	help   string
}

// prom is the Prometheus text of the document: the generic per-collector series, then the collector's own.
func (d *Document) prom(finished time.Time) string {
	counts := map[[2]string]int{}
	for _, f := range d.findings {
		counts[[2]string{dyn.Str(f["layer"]), dyn.Str(f["severity"])}]++
	}
	keys := make([][2]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i][0]+"\x00"+keys[i][1] < keys[j][0]+"\x00"+keys[j][1] })
	var out []series
	for _, k := range keys {
		out = append(out, series{"security_collector_findings", map[string]string{"collector": d.Name, "layer": k[0], "severity": k[1]},
			strconv.Itoa(counts[k]), "Findings reported by the latest run of a collector"})
	}
	one := map[string]string{"collector": d.Name}
	out = append(out,
		series{"security_collector_gaps", one, strconv.Itoa(d.Gaps()), "Assets the collector could not cover"},
		series{"security_collector_assets", one, strconv.Itoa(d.Assets()), "Assets in scope of the run"},
		series{"security_collector_last_run_timestamp_seconds", one, strconv.FormatInt(finished.Unix(), 10),
			"Heartbeat: when the collector last finished (no findings != secure)"})
	for _, m := range d.metrics {
		labels := map[string]string{"collector": d.Name}
		for k, v := range m.labels {
			labels[k] = v
		}
		out = append(out, series{m.name, labels, strconv.FormatFloat(m.value, 'g', 6, 64), m.help})
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
