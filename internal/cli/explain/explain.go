// Package explain holds the plain-language texts of `sp explain`, `sp status` and `sp digest`: what a check found,
// why it matters, how to fix and verify it, and the words for layers and severities. The texts are data,
// explanations.json in this directory, embedded in the binary and read by the Python implementation
// (cli/explanations.py) from the same file, so every wording lives in one place.
package explain

import (
	_ "embed" // the texts are embedded data
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Schema identifies the data file's format.
const Schema = "security-platform/explanations/v1"

// nextScanToken stands for the next-scan sentence in the data file.
const nextScanToken = "{next_scan}"

//go:embed explanations.json
var data []byte

// Entry is the explanation of one check. Empty fields are unknown.
type Entry struct {
	What   string `json:"what"`
	Why    string `json:"why"`
	Fix    string `json:"fix"`
	Verify string `json:"verify"`
}

type family struct {
	Prefix string `json:"prefix"`
	Entry
}

// Texts are the explanations, as Load returns them.
type Texts struct {
	NextScan   string
	checks     map[string]Entry
	families   []family
	layers     map[string]string
	severities map[string]string
}

type document struct {
	Schema     string            `json:"schema"`
	NextScan   string            `json:"next_scan"`
	Checks     map[string]Entry  `json:"checks"`
	Families   []family          `json:"families"`
	Layers     map[string]string `json:"layers"`
	Severities map[string]string `json:"severities"`
}

// ErrData is returned for a data file that is not an explanations document.
var ErrData = errors.New("explanations: malformed data")

// Load returns the embedded texts.
func Load() (*Texts, error) {
	return Parse(data)
}

// Parse reads an explanations document.
func Parse(b []byte) (*Texts, error) {
	var d document
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrData, err)
	}
	if d.Schema != Schema || d.NextScan == "" {
		return nil, fmt.Errorf("%w: schema %q", ErrData, d.Schema)
	}
	t := &Texts{NextScan: d.NextScan, checks: map[string]Entry{}, layers: d.Layers, severities: d.Severities}
	for k, e := range d.Checks {
		t.checks[k] = t.expand(e)
	}
	for _, f := range d.Families {
		f.Entry = t.expand(f.Entry)
		t.families = append(t.families, f)
	}
	return t, nil
}

func (t *Texts) expand(e Entry) Entry {
	r := strings.NewReplacer(nextScanToken, t.NextScan)
	return Entry{What: r.Replace(e.What), Why: r.Replace(e.Why), Fix: r.Replace(e.Fix), Verify: r.Replace(e.Verify)}
}

// Explain returns the explanation of a check: its own entry, else the first family whose prefix it starts with
// (verified by the next scan), else an empty entry that only says how to verify.
func (t *Texts) Explain(check string) Entry {
	if e, ok := t.checks[check]; ok {
		return e
	}
	for _, f := range t.families {
		if strings.HasPrefix(check, f.Prefix) {
			e := f.Entry
			e.Verify = t.NextScan
			return e
		}
	}
	return Entry{Verify: t.NextScan}
}

// Headline is one short plain-language line for a check (digests, dashboards): its "what", else fallback. It never
// contains asset details.
func (t *Texts) Headline(check, fallback string) string {
	if w := t.Explain(check).What; w != "" {
		return w
	}
	return fallback
}

// Layer is the plain words for a layer ("" when unknown).
func (t *Texts) Layer(layer string) string {
	return t.layers[layer]
}

// Severity is the plain words for a severity ("" when unknown).
func (t *Texts) Severity(sev string) string {
	return t.severities[sev]
}

// Checks returns the names of the checks with an entry of their own.
func (t *Texts) Checks() []string {
	out := make([]string, 0, len(t.checks))
	for k := range t.checks {
		out = append(out, k)
	}
	return out
}
