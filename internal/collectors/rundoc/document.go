// Package rundoc is what sdk/spsdk is for the Python collectors: one findings document per run (findings/v1),
// its evidence files and its Prometheus text, written byte for byte as the Python SDK writes them (json.dump with
// indent=1, sort_keys=True, ensure_ascii=True; the same metric text), so a collector rewritten in Go keeps its
// ledger entries and its documents compare equal. It also holds what every Go collector needs from its process:
// the collector-protocol environment, the instance config, bounded file reads, private writes and child processes.
package rundoc

import (
	"crypto/sha1" // #nosec G505 -- the finding id is sha1 by contract (collector-protocol §6), not a security use
	"encoding/hex"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
)

// SchemaVersion is the findings contract minor the Go collectors write (1.2: gap `checks`).
const SchemaVersion = "1.2"

// maxTitle is the length (characters) a title is cut to, as the Python SDK does.
const (
	maxTitle  = 300
	maxReason = 300
)

// FindingID is sha1("<layer>|<asset>|<check>")[:12] (collector-protocol §6).
func FindingID(layer, asset, check string) string {
	sum := sha1.Sum([]byte(layer + "|" + asset + "|" + check)) // #nosec G401 -- see the import
	return hex.EncodeToString(sum[:])[:12]
}

// Finding is one finding before it is added to a document. Kind "" is "compliance" (the SDK's default); Owner ""
// is "human" when NeedsHuman, else "platform". Attributes may be nil.
type Finding struct {
	Layer, Asset, Check, Title, Severity, Evidence, Remediation string
	Kind, Owner                                                 string
	NeedsHuman                                                  bool
	Refs                                                        []pyjson.Value
	Attributes                                                  *pyjson.Object
}

type metric struct {
	name, help string
	value      float64
	labels     map[string]string
}

// Document builds the findings document of one run.
type Document struct {
	Name, Version, Instance string
	Started                 time.Time
	Tools                   *pyjson.Object // tool -> version, as the collector reports them
	now                     func() time.Time
	findings                []*pyjson.Object
	ids                     map[string]bool
	coverage                *pyjson.Object // asset -> entry, in first-recorded order
	metrics                 []metric
}

// New starts a document. now is the clock of the run (time.Now in production).
func New(name, version, instance string, now func() time.Time) *Document {
	return &Document{Name: name, Version: version, Instance: instance, Started: now(), Tools: pyjson.NewObject(),
		now: now, ids: map[string]bool{}, coverage: pyjson.NewObject()}
}

// ISO is t as the documents write times: RFC 3339, UTC, seconds.
func ISO(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

// Cut returns the first n characters (code points) of s, as Python's s[:n].
func Cut(s string, n int) string {
	i := 0
	for pos := range s {
		if i == n {
			return s[:pos]
		}
		i++
	}
	return s
}

// Has reports whether a finding with this (layer, asset, check) was already added.
func (d *Document) Has(layer, asset, check string) bool { return d.ids[FindingID(layer, asset, check)] }

// AddFinding records f once per (layer, asset, check); a repeated one is ignored, as in the SDK.
func (d *Document) AddFinding(f *Finding) {
	id := FindingID(f.Layer, f.Asset, f.Check)
	if d.ids[id] {
		return
	}
	d.ids[id] = true
	owner, kind := f.Owner, f.Kind
	if owner == "" {
		owner = "platform"
		if f.NeedsHuman {
			owner = "human"
		}
	}
	if kind == "" {
		kind = "compliance"
	}
	m := pyjson.NewObject()
	for _, kv := range []struct {
		k string
		v pyjson.Value
	}{{"id", id}, {"check", f.Check}, {"layer", f.Layer}, {"asset", f.Asset}, {"title", Cut(f.Title, maxTitle)},
		{"severity", f.Severity}, {"evidence", f.Evidence}, {"remediation", f.Remediation}, {"needs_human", f.NeedsHuman},
		{"owner", owner}, {"observed_at", ISO(d.now())}, {"kind", kind}} {
		m.Set(kv.k, kv.v)
	}
	if len(f.Refs) > 0 {
		m.Set("refs", f.Refs)
	}
	if f.Attributes != nil && f.Attributes.Len() > 0 {
		m.Set("attributes", f.Attributes)
	}
	d.findings = append(d.findings, m)
}

// OK marks an asset covered; a gap recorded before stays a gap. completeScope (may be "") is an asset prefix the
// run inventoried completely and authoritatively (findings 1.1), kept only on an ok entry.
func (d *Document) OK(asset, completeScope string) {
	e, ok := d.coverage.Get(asset)
	if !ok {
		entry := pyjson.NewObject()
		entry.Set("asset", asset)
		entry.Set("status", "ok")
		d.coverage.Set(asset, entry)
		e = entry
	}
	entry, isObj := e.(*pyjson.Object)
	if isObj && completeScope != "" && entry.Str("status") == "ok" {
		entry.Set("complete_scope", completeScope)
	}
}

// Gap marks an asset not covered (it replaces an ok entry). checks (may be nil) make it a narrow gap: only these
// checks (fnmatch patterns) could not be evaluated on the asset this one is a part of (`<asset>/<part>`).
func (d *Document) Gap(asset, reason string, checks []string) {
	entry := pyjson.NewObject()
	entry.Set("asset", asset)
	entry.Set("status", "gap")
	entry.Set("reason", Cut(reason, maxReason))
	if len(checks) > 0 {
		sorted := append([]string(nil), checks...)
		sort.Strings(sorted)
		list := make([]pyjson.Value, len(sorted))
		for i, c := range sorted {
			list[i] = c
		}
		entry.Set("checks", list)
	}
	d.coverage.Set(asset, entry)
}

// Metric adds one series of the collector's own metrics.
func (d *Document) Metric(name string, value float64, help string, labels map[string]string) {
	d.metrics = append(d.metrics, metric{name: name, value: value, help: help, labels: labels})
}

// Mark is the number of findings so far, for DropSince.
func (d *Document) Mark() int { return len(d.findings) }

// DropSince removes the findings added after mark whose check matches drop (a finding of a part that turned out
// not to be checkable is a guess, not an observation); a dropped finding may be added again later.
func (d *Document) DropSince(mark int, drop func(check string) bool) {
	kept := d.findings[:mark]
	for _, f := range d.findings[mark:] {
		if drop(f.Str("check")) {
			delete(d.ids, f.Str("id"))
			continue
		}
		kept = append(kept, f)
	}
	d.findings = kept
}

// Findings returns the findings added so far (shared, do not modify).
func (d *Document) Findings() []*pyjson.Object { return d.findings }

// CoverageStatus is the status of an asset's coverage entry ("" when the asset has none).
func (d *Document) CoverageStatus(asset string) string {
	e, ok := d.coverage.Get(asset)
	if !ok {
		return ""
	}
	entry, _ := e.(*pyjson.Object) // every entry is an object (set above)
	return entry.Str("status")
}

// Gaps counts the assets that are gaps.
func (d *Document) Gaps() int {
	n := 0
	for _, k := range d.coverage.Keys() {
		if d.CoverageStatus(k) == "gap" {
			n++
		}
	}
	return n
}

// Raw stores evidence (already filtered: never a secret value) as raw/<name>/<file> in runDir, as the SDK does
// (json.dumps(indent=1, sort_keys=True); a string is written as is), and returns the evidence pointer.
func (d *Document) Raw(runDir, file string, v pyjson.Value) (string, error) {
	var data []byte
	if s, ok := v.(string); ok {
		data = []byte(s)
	} else {
		b, err := pyjson.Marshal(v, pyjson.Options{Indent: 1, SortKeys: true, EnsureASCII: true})
		if err != nil {
			return "", fmt.Errorf("encode evidence %s: %w", file, err)
		}
		data = b
	}
	dir := filepath.Join(runDir, "raw", d.Name)
	if err := MkdirPrivate(dir); err != nil {
		return "", err
	}
	if err := WriteFile(filepath.Join(dir, file), data); err != nil {
		return "", err
	}
	return "raw/" + d.Name + "/" + file, nil
}

// Doc is the findings document as a JSON value, finished at the given time.
func (d *Document) Doc(finished time.Time) *pyjson.Object {
	cov := make([]pyjson.Value, 0, d.coverage.Len())
	for _, k := range d.coverage.Keys() {
		v, _ := d.coverage.Get(k)
		cov = append(cov, v)
	}
	findings := make([]pyjson.Value, len(d.findings))
	for i, f := range d.findings {
		findings[i] = f
	}
	metrics := make([]pyjson.Value, len(d.metrics))
	for i, m := range d.metrics {
		o := pyjson.NewObject()
		o.Set("name", m.name)
		o.Set("value", m.value)
		o.Set("labels", stringObject(m.labels))
		o.Set("help", m.help)
		metrics[i] = o
	}
	col := pyjson.NewObject()
	col.Set("name", d.Name)
	col.Set("version", d.Version)
	col.Set("tools", d.Tools)
	run := pyjson.NewObject()
	run.Set("started_at", ISO(d.Started))
	run.Set("finished_at", ISO(finished))
	run.Set("instance", d.Instance)
	doc := pyjson.NewObject()
	doc.Set("schema_version", SchemaVersion)
	doc.Set("collector", col)
	doc.Set("run", run)
	doc.Set("coverage", cov)
	doc.Set("findings", findings)
	doc.Set("metrics", metrics)
	return doc
}

func stringObject(m map[string]string) *pyjson.Object {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	o := pyjson.NewObject()
	for _, k := range keys {
		o.Set(k, m[k])
	}
	return o
}

// Write writes <name>.findings.json (in one step: a temporary file, then a rename) and <name>.prom into runDir
// (both private to the user) and prints the SDK's summary line to stderr.
func (d *Document) Write(runDir string, stderr io.Writer) error {
	finished := d.now()
	data, err := pyjson.Marshal(d.Doc(finished), pyjson.Options{Indent: 1, SortKeys: true, EnsureASCII: true})
	if err != nil {
		return fmt.Errorf("encode findings: %w", err)
	}
	if err := WriteFile(filepath.Join(runDir, d.Name+".findings.json"), data); err != nil {
		return err
	}
	if err := WriteFile(filepath.Join(runDir, d.Name+".prom"), []byte(d.prom(finished))); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stderr, "[%s %s] findings=%d assets=%d gaps=%d\n", d.Name, d.Version, len(d.findings),
		d.coverage.Len(), d.Gaps()) // informational; the document is the result
	return nil
}

// Bump raises a severity by n steps (at most critical).
func Bump(sev string, n int) string {
	severityOrder := [...]string{"info", "low", "medium", "high", "critical"}
	for i, s := range severityOrder {
		if s == sev {
			return severityOrder[min(len(severityOrder)-1, i+n)]
		}
	}
	return sev
}

// Lower is strings.ToLower for the ASCII identifiers the collectors compare.
func Lower(s string) string { return strings.ToLower(s) }
