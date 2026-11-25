// Package cloud is the Go implementation of the `cloud` collector (collectors/cloud): cloud security posture of AWS
// accounts, GCP projects and Azure subscriptions, READ-ONLY, behind the collector protocol
// (contracts/collector-protocol). Per account it authenticates with short-lived credentials (internal/cloud),
// verifies its own permissions (refuse to scan when over-privileged), runs the configured check engines (Prowler,
// Steampipe, ScoutSuite) as external processes, reads exports of the providers' own posture services (Security Hub,
// Security Command Center, Defender for Cloud), maps every verdict onto a generic control and merges the same
// (resource, control) into ONE finding with N sources. Every failure is a coverage gap with its reason.
// Its findings document is byte-for-byte the Python implementation's, apart from times.
package cloud

import (
	"github.com/MIERAI/security-platform/internal/cloud/dyn"
)

// Result is one (resource, check) verdict of one engine or import, in a tool-neutral shape.
type Result struct {
	Source, Provider, Account, Service, Region string
	Resource                                   string // canonical id: ARN / resource name / resource id
	Name                                       string
	Check                                      string // the tool's own check id
	Control                                    string // generic control id, "" when none
	Status                                     string // FAIL | PASS
	Severity                                   string // critical | high | medium | low | info
	Title                                      string
	Detail                                     string
	Refs                                       []string
	Remediation                                string
	CoverageOnly                               bool // a PASS that only says "this service was looked at"
}

// Run is the outcome of one engine run.
type Run struct {
	Engine  string
	Results []Result
	Errors  *orderedErrors // per service, in the order they occurred
	Scope   map[string]bool
	OK      bool
	Reason  string
	Version string
}

func newRun(engine string) *Run {
	return &Run{Engine: engine, Errors: &orderedErrors{m: map[string][]string{}}, Scope: map[string]bool{}}
}

func (r *Run) error(service, msg string) { r.Errors.add(service, dyn.Cut(msg, 200)) }

// gapServices are services that had errors AND gave no verdict at all: the listing itself failed (an error on a
// secondary call of a service that still returned verdicts is evidence, not a gap).
func (r *Run) gapServices() map[string][]string {
	seen := map[string]bool{}
	for i := range r.Results {
		seen[r.Results[i].Service] = true
	}
	out := map[string][]string{}
	for _, s := range r.Errors.keys {
		if !seen[s] && (len(r.Scope) == 0 || r.Scope[s]) {
			out[s] = r.Errors.m[s]
		}
	}
	return out
}

// orderedErrors is a map of service -> messages that remembers insertion order.
type orderedErrors struct {
	keys []string
	m    map[string][]string
}

func (o *orderedErrors) add(service, msg string) {
	if _, ok := o.m[service]; !ok {
		o.keys = append(o.keys, service)
	}
	o.m[service] = append(o.m[service], msg)
}

func (o *orderedErrors) has(service string) bool {
	_, ok := o.m[service]
	return ok
}

// sev maps a tool's severity word onto the platform's ("medium" when unknown).
func sev(word string) string {
	m := map[string]string{"critical": "critical", "high": "high", "medium": "medium", "low": "low",
		"informational": "info", "info": "info", "danger": "high", "warning": "medium", "moderate": "medium"}
	if v, ok := m[dyn.Lower(word)]; ok {
		return v
	}
	return "medium"
}
