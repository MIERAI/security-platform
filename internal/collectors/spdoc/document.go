// Package spdoc builds the findings document of one collector run (contracts/collector-protocol, findings/v1),
// its Prometheus text and its evidence files exactly as the Python SDK (sdk/spsdk) writes them: the same key
// order, number formatting, truncation and metric rendering, so that a document written by a Go collector and
// one written by its Python counterpart compare equal apart from times.
package spdoc

import (
	"crypto/sha1" // #nosec G505 -- the finding id is sha1 by contract (collector-protocol §6), not a security use
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/MIERAI/security-platform/internal/collectors/pytext"
)

const (
	schemaVersion = "1.2"
	maxText       = 300 // code points kept of a title or a gap reason
)

// ErrInvalidFinding is a finding with a layer or severity the schema does not have (a programming error).
var ErrInvalidFinding = errors.New("invalid finding")

// FindingID is sha1("<layer>|<asset>|<check>")[:12] (collector-protocol §6).
func FindingID(layer, asset, check string) string {
	sum := sha1.Sum([]byte(layer + "|" + asset + "|" + check)) // #nosec G401 -- see the import
	return hex.EncodeToString(sum[:])[:12]
}

// Finding is one finding as a collector reports it.
type Finding struct {
	Layer, Asset, Check, Title, Severity, Evidence, Remediation string
	NeedsHuman                                                  bool
}

type finding struct {
	Finding
	id, observed string
}

type coverage struct {
	asset, status, reason string
	checks                []string
}

type metric struct {
	name, help string
	value      float64
	labels     map[string]string
}

// Document is the findings document of one run.
type Document struct {
	name, version, instance string
	started                 time.Time
	now                     func() time.Time
	findings                []finding
	covOrder                []string
	coverage                map[string]*coverage
	metrics                 []metric
}

// New starts the document of collector `name` (SP_COLLECTOR_NAME when set, the collector's own name otherwise).
func New(name, version, instance string, now func() time.Time) *Document {
	return &Document{name: name, version: version, instance: instance, started: now(), now: now,
		coverage: map[string]*coverage{}}
}

// Name is the collector name the document reports under.
func (d *Document) Name() string { return d.name }

func iso(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

func validLayer(s string) bool {
	switch s {
	case "identity", "network", "host", "workload", "supply-chain", "data-secrets", "ai-agents", "detection":
		return true
	}
	return false
}

func validSeverity(s string) bool {
	switch s {
	case "critical", "high", "medium", "low", "info":
		return true
	}
	return false
}

// Add records a finding, once per (layer, asset, check): a second report of the same finding is ignored.
func (d *Document) Add(f *Finding) error {
	if !validLayer(f.Layer) || !validSeverity(f.Severity) {
		return fmt.Errorf("%w: layer %q severity %q", ErrInvalidFinding, f.Layer, f.Severity)
	}
	id := FindingID(f.Layer, f.Asset, f.Check)
	for i := range d.findings {
		if d.findings[i].id == id {
			return nil
		}
	}
	g := *f
	g.Title = pytext.Head(g.Title, maxText)
	d.findings = append(d.findings, finding{Finding: g, id: id, observed: iso(d.now())})
	return nil
}

// Count is the number of findings so far (a mark for DropSince).
func (d *Document) Count() int { return len(d.findings) }

// DropSince removes the findings added after mark whose check matches drop.
func (d *Document) DropSince(mark int, drop func(check string) bool) {
	kept := d.findings[:mark]
	for i := mark; i < len(d.findings); i++ {
		if !drop(d.findings[i].Check) {
			kept = append(kept, d.findings[i])
		}
	}
	d.findings = kept
}

// OK marks an asset covered; an asset already recorded (a gap) keeps its entry.
func (d *Document) OK(asset string) {
	if _, ok := d.coverage[asset]; !ok {
		d.covOrder = append(d.covOrder, asset)
		d.coverage[asset] = &coverage{asset: asset, status: "ok"}
	}
}

// Gap marks an asset not covered, with its reason; checks (fnmatch patterns) make it a narrow gap
// (`<asset>/<part>`: only these checks could not be evaluated). It replaces an earlier entry in place.
func (d *Document) Gap(asset, reason string, checks []string) {
	if _, ok := d.coverage[asset]; !ok {
		d.covOrder = append(d.covOrder, asset)
	}
	c := &coverage{asset: asset, status: "gap", reason: pytext.Head(reason, maxText)}
	if len(checks) > 0 {
		c.checks = append([]string(nil), checks...)
		sort.Strings(c.checks)
	}
	d.coverage[asset] = c
}

// Metric adds one series of the collector's own (the label `collector` is added when the text is written).
func (d *Document) Metric(name string, value float64, help string, labels map[string]string) {
	d.metrics = append(d.metrics, metric{name: name, value: value, help: help, labels: labels})
}

// Summary is the customary stderr line: "[name version] findings=N assets=N gaps=N".
func (d *Document) Summary() string {
	gaps := 0
	for _, c := range d.coverage {
		if c.status == "gap" {
			gaps++
		}
	}
	return "[" + d.name + " " + d.version + "] findings=" + strconv.Itoa(len(d.findings)) + " assets=" +
		strconv.Itoa(len(d.coverage)) + " gaps=" + strconv.Itoa(gaps)
}
