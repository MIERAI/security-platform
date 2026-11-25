// Package ledger is the Go implementation of the ledger merge (contracts/ledger/SPEC.md §1-§6): it merges the
// findings documents of one run into DATA/ledger.json, applies the human-approved exceptions, computes the
// SLIs and writes the metrics, the OCSF export and the private summary. It reads and writes the same files as
// the reference (core/ledger.py), byte for byte where the contract fixes them, and implements the TARGET
// behaviour of the known deviations LEDGER-D1..D5:
//
//   - D1: a finding without `kind` is merged as kind "compliance";
//   - D2: an entry gets `due_at` (remediation SLO) when it is first recorded or reopened;
//   - D3: a gap protects the assets it would cover (§3 matching), not every asset containing its name;
//   - D4: all time arithmetic is on UTC instants (package instant);
//   - D5: an accepted entry without a valid exception is open again.
package ledger

import (
	_ "embed" // the component version
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/MIERAI/security-platform/internal/ledger/findings"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
	"github.com/MIERAI/security-platform/internal/remediation"
)

// Schema is the ledger file's schema name.
const Schema = "security-platform/ledger/v1"

// Options are the inputs of one merge.
type Options struct {
	Run, Data, Latest string         // Latest may be ""
	Remediation       *pyjson.Object // the instance's `remediation:` section (SLO overrides for D2); nil: defaults
	Now               float64        // epoch seconds: exception expiry, updated_at, 30-day windows
	Version           string         // this implementation's version, recorded in runs[].core
	Stderr            io.Writer      // warnings and the one-line summary
	// Reference reproduces the reference's behaviour for these known deviations instead of the target
	// (DeviationDueDate, DeviationGapSubstring, DeviationRemovedException). Diagnostic only: it lets a shadow
	// comparison attribute every difference to a deviation (docs/contracts.md); never use it in production.
	Reference map[string]bool
}

// Known deviations that Options.Reference can switch back to the reference behaviour.
const (
	DeviationDueDate          = "LEDGER-D2"
	DeviationGapSubstring     = "LEDGER-D3"
	DeviationRemovedException = "LEDGER-D5"
)

// ReferenceDeviations lists the deviations Options.Reference accepts.
func ReferenceDeviations() []string {
	return []string{DeviationDueDate, DeviationGapSubstring, DeviationRemovedException}
}

// merger holds the state of one merge.
type merger struct {
	opt       Options
	ledger    *pyjson.Object
	entries   *pyjson.Object
	slo       map[string]int64
	validator *findings.Validator
}

// Merge runs one merge. On error nothing has been written to DATA/ledger.json.
func Merge(opt Options) error {
	m, err := newMerger(opt)
	if err != nil {
		return err
	}
	docs, invalid, err := m.loadDocuments(opt.Run)
	if err != nil {
		return err
	}
	for _, d := range docs {
		m.applyDocument(d)
	}
	excFile, err := loadYAMLObject(filepath.Join(opt.Data, "exceptions.yaml"), m.warn)
	if err != nil {
		return err
	}
	expired := m.applyExceptions(excFile.Obj("exceptions"))
	cur := docs
	if opt.Latest != "" {
		if cur, _, err = m.loadDocuments(opt.Latest); err != nil {
			return err
		}
	}
	gaps := m.countGaps(cur, excFile.Obj("coverage_exceptions"))
	m.updateCollectors(docs)
	s, err := m.computeSLIs(cur, gaps)
	if err != nil {
		return err
	}
	series := m.series(s, gaps, expired, invalid.Len())
	return m.write(docs, invalid, s, series)
}

func newMerger(opt Options) (*merger, error) {
	v, err := findings.NewValidator()
	if err != nil {
		return nil, err
	}
	slo, err := remediation.SLOSeconds(opt.Remediation)
	if err != nil {
		return nil, err
	}
	led, err := loadLedger(filepath.Join(opt.Data, "ledger.json"))
	if err != nil {
		return nil, err
	}
	m := &merger{opt: opt, ledger: led, slo: slo, validator: v}
	m.entries = led.GetOrCreateObj("entries")
	led.GetOrCreateObj("coverage_seen")
	return m, nil
}

func (m *merger) warn(format string, args ...any) {
	_, _ = fmt.Fprintf(m.opt.Stderr, "ledger: warning: "+format+"\n", args...) // stderr is best effort
}

//go:embed VERSION
var versionFile string // never written after initialisation (go:embed)

// Version is the version of the Go ledger component (internal/ledger/VERSION): merge and track.
func Version() string {
	return strings.TrimSpace(versionFile)
}
