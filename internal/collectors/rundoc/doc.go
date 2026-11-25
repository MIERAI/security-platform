// Package rundoc is the findings document of one collector run (contracts/collector-protocol, contracts/findings):
// what sdk/spsdk.Collector is for the Python collectors. Coverage, findings, metrics and evidence are written
// byte for byte as the Python SDK writes them (json.dumps(indent=1, sort_keys=True), the same Prometheus text), so a
// collector moved to Go keeps its ledger entries, dashboards and evidence pointers.
//
// Shared by the Go collectors exposure, codehost-github, codehost-gitea, agent-claude-code and detection.
package rundoc

import (
	"crypto/sha1" // #nosec G505 -- the finding id is sha1 by contract (collector-protocol §6), not a security use
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/MIERAI/security-platform/internal/collectors/cloud/pyjson"
)

// SchemaVersion is the findings schema version the documents declare.
const SchemaVersion = "1.2"

// Kinds of finding (findings/1.2).
const (
	KindCompliance = "compliance"
	KindDetection  = "detection"
)

// maxTitle and maxReason are the SDK's cuts (in characters, as Python slices text).
const (
	maxTitle  = 300
	maxReason = 300
)

// FindingID is sha1("<layer>|<asset>|<check>")[:12] (collector-protocol §6).
func FindingID(layer, asset, check string) string {
	sum := sha1.Sum([]byte(layer + "|" + asset + "|" + check)) // #nosec G401 -- see the import
	return hex.EncodeToString(sum[:])[:12]
}

// Finding is one finding. Kind "" is compliance.
type Finding struct {
	Layer, Asset, Check, Title, Severity, Evidence, Remediation, Kind string
	NeedsHuman                                                        bool
	Attributes                                                        map[string]any
}

type metric struct {
	name, help string
	value      float64
	labels     [][2]string
}

// Document builds the findings document of one run.
type Document struct {
	Name, Version, Instance string
	Tools                   map[string]string
	started                 time.Time
	now                     func() time.Time
	runDir                  string
	findings                []map[string]any
	layerSev                [][2]string
	ids                     map[string]bool
	covKeys                 []string
	coverage                map[string]map[string]any
	metrics                 []metric
}

// New starts a document; evidence and the document go into runDir.
func New(name, version, instance, runDir string, now func() time.Time) *Document {
	return &Document{Name: name, Version: version, Instance: instance, Tools: map[string]string{}, started: now(),
		now: now, runDir: runDir, ids: map[string]bool{}, coverage: map[string]map[string]any{}}
}

func isoUTC(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

// Cut is Python's s[:n] on text: at most n characters.
func Cut(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	i := 0
	for j := range s {
		if i == n {
			return s[:j]
		}
		i++
	}
	return s
}

// Add records a finding once per (layer, asset, check), as the SDK does.
func (d *Document) Add(f *Finding) {
	id := FindingID(f.Layer, f.Asset, f.Check)
	if d.ids[id] {
		return
	}
	d.ids[id] = true
	owner, kind := "platform", f.Kind
	if f.NeedsHuman {
		owner = "human"
	}
	if kind == "" {
		kind = KindCompliance
	}
	m := map[string]any{"id": id, "check": f.Check, "layer": f.Layer, "asset": f.Asset, "title": Cut(f.Title, maxTitle),
		"severity": f.Severity, "evidence": f.Evidence, "remediation": f.Remediation, "needs_human": f.NeedsHuman,
		"owner": owner, "observed_at": isoUTC(d.now()), "kind": kind}
	if len(f.Attributes) > 0 {
		m["attributes"] = f.Attributes
	}
	d.findings = append(d.findings, m)
	d.layerSev = append(d.layerSev, [2]string{f.Layer, f.Severity})
}

// OK marks an asset covered; a gap recorded before stays a gap.
func (d *Document) OK(asset string) {
	if _, ok := d.coverage[asset]; !ok {
		d.covKeys = append(d.covKeys, asset)
		d.coverage[asset] = map[string]any{"asset": asset, "status": "ok"}
	}
}

// Gap marks an asset not covered, with its reason (it replaces an earlier ok, keeping its position).
func (d *Document) Gap(asset, reason string) {
	if _, ok := d.coverage[asset]; !ok {
		d.covKeys = append(d.covKeys, asset)
	}
	d.coverage[asset] = map[string]any{"asset": asset, "status": "gap", "reason": Cut(reason, maxReason)}
}

// Metric adds one series; labels are name/value pairs.
func (d *Document) Metric(name string, value float64, help string, labels ...[2]string) {
	d.metrics = append(d.metrics, metric{name: name, value: value, help: help, labels: labels})
}

// Raw stores evidence (already filtered: never a secret value) as raw/<name>/<file> and returns its pointer.
// v is a JSON value of the kinds JSON accepts (see Loose for documents read with pyvalue).
func (d *Document) Raw(file string, v any) (string, error) {
	data, err := pyjson.Marshal(v, 1)
	if err != nil {
		return "", fmt.Errorf("encode evidence %s: %w", file, err)
	}
	dir := filepath.Join(d.runDir, "raw", d.Name)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", fmt.Errorf("create the evidence directory: %w", err)
	}
	if err := writeAtomic(filepath.Join(dir, file), data); err != nil {
		return "", err
	}
	return "raw/" + d.Name + "/" + file, nil
}

// Counts returns the number of findings, assets and gaps.
func (d *Document) Counts() (findings, assets, gaps int) {
	for _, c := range d.coverage {
		if c["status"] == "gap" {
			gaps++
		}
	}
	return len(d.findings), len(d.coverage), gaps
}

// Value is the findings document as a JSON value, finished at the given time.
func (d *Document) Value(finished time.Time) map[string]any {
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
		for _, kv := range m.labels {
			labels[kv[0]] = kv[1]
		}
		metrics[i] = map[string]any{"name": m.name, "value": m.value, "labels": labels, "help": m.help}
	}
	tools := map[string]any{}
	for k, v := range d.Tools {
		tools[k] = v
	}
	return map[string]any{"schema_version": SchemaVersion,
		"collector": map[string]any{"name": d.Name, "version": d.Version, "tools": tools},
		"run":       map[string]any{"started_at": isoUTC(d.started), "finished_at": isoUTC(finished), "instance": d.Instance},
		"coverage":  cov, "findings": findings, "metrics": metrics}
}

// Write writes <name>.findings.json (a temporary file, then a rename) and <name>.prom into the run directory.
func (d *Document) Write() error {
	finished := d.now()
	data, err := pyjson.Marshal(d.Value(finished), 1)
	if err != nil {
		return fmt.Errorf("encode the findings document: %w", err)
	}
	if err := writeAtomic(filepath.Join(d.runDir, d.Name+".findings.json"), data); err != nil {
		return err
	}
	return writeAtomic(filepath.Join(d.runDir, d.Name+".prom"), []byte(d.prom(finished)))
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
	name, value, help string
	labels            map[string]string
}

// prom is the SDK's to_prom: the generic per-collector series, then the collector's own.
func (d *Document) prom(finished time.Time) string {
	counts := map[[2]string]int{}
	for _, k := range d.layerSev {
		counts[k]++
	}
	keys := make([][2]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i][0]+"\x00"+keys[i][1] < keys[j][0]+"\x00"+keys[j][1] })
	var out []series
	for _, k := range keys {
		out = append(out, series{"security_collector_findings", fmt.Sprint(counts[k]),
			"Findings reported by the latest run of a collector",
			map[string]string{"collector": d.Name, "layer": k[0], "severity": k[1]}})
	}
	_, assets, gaps := d.Counts()
	one := map[string]string{"collector": d.Name}
	out = append(out,
		series{"security_collector_gaps", fmt.Sprint(gaps), "Assets the collector could not cover", one},
		series{"security_collector_assets", fmt.Sprint(assets), "Assets in scope of the run", one},
		series{"security_collector_last_run_timestamp_seconds", fmt.Sprint(finished.Unix()),
			"Heartbeat: when the collector last finished (no findings != secure)", one})
	for _, m := range d.metrics {
		labels := map[string]string{}
		for _, kv := range m.labels {
			labels[kv[0]] = kv[1]
		}
		labels["collector"] = d.Name
		out = append(out, series{m.name, FormatG(m.value), m.help, labels})
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
