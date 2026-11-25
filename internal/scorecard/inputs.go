package scorecard

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	pv "github.com/MIERAI/security-platform/internal/scorecard/pyvalue"
)

// coverage is one coverage entry of a collector's newest document.
type coverage struct {
	collector, asset, status any
}

// inputs are the data the evaluators read (SPEC §2): the ledger, the published metrics, the coverage of the
// newest documents and the runner's job states.
type inputs struct {
	ledger   *pv.Map
	metrics  []sample
	coverage []coverage
	jobs     map[string]any
}

func loadInputs(data string) (*inputs, error) {
	l := readJSONFile(filepath.Join(data, "ledger.json"), pv.NewMap())
	ledger, ok := l.(*pv.Map)
	if !ok {
		return nil, configErr("ledger.json is not an object")
	}
	in := &inputs{ledger: ledger, jobs: map[string]any{}}
	var err error
	if in.metrics, err = loadMetrics(filepath.Join(data, "metrics", "security-platform.prom")); err != nil {
		return nil, err
	}
	if in.coverage, err = loadCoverage(filepath.Join(data, "latest")); err != nil {
		return nil, err
	}
	if err := in.loadJobs(data); err != nil {
		return nil, err
	}
	return in, nil
}

// loadMetrics reads the last published metrics without the scorecard's own series (security_score*); a
// malformed file counts as none.
func loadMetrics(path string) ([]sample, error) {
	if !fileExists(path) {
		return nil, nil
	}
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}
	if !utf8.Valid(data) {
		return nil, nil
	}
	all, ok := parseProm(string(data))
	if !ok {
		return nil, nil
	}
	out := all[:0]
	for _, s := range all {
		if !strings.HasPrefix(s.name, "security_score") {
			out = append(out, s)
		}
	}
	return out, nil
}

func loadCoverage(dir string) ([]coverage, error) {
	var out []coverage
	for _, p := range jsonFiles(dir, ".findings.json") {
		v := readJSONFile(p, pv.NewMap())
		d, ok := v.(*pv.Map)
		if !ok {
			return nil, configErr("%s is not an object", p)
		}
		col, ok := orEmpty(d.Value("collector"))
		if !ok {
			return nil, configErr("%s: collector is not an object", p)
		}
		entries, err := covEntries(p, d.Value("coverage"))
		if err != nil {
			return nil, err
		}
		for _, g := range entries {
			out = append(out, coverage{collector: col.GetOr("name", ""), asset: g.GetOr("asset", ""),
				status: g.Value("status")})
		}
	}
	return out, nil
}

func covEntries(path string, v any) ([]*pv.Map, error) {
	if !pv.Truthy(v) {
		return nil, nil
	}
	list, ok := v.([]any)
	if !ok {
		return nil, configErr("%s: coverage is not a list", path)
	}
	out := make([]*pv.Map, 0, len(list))
	for _, x := range list {
		g, ok := x.(*pv.Map)
		if !ok {
			return nil, configErr("%s: a coverage entry is not an object", path)
		}
		out = append(out, g)
	}
	return out, nil
}

// loadJobs reads <data>/state/runner/<job>.json (sinks.json is not a job), then the jobs of
// <data>/state/sites/*.json that the runner does not have (the first site file in name order wins).
func (in *inputs) loadJobs(data string) error {
	for _, p := range jsonFiles(filepath.Join(data, "state", "runner"), ".json") {
		name := strings.TrimSuffix(filepath.Base(p), ".json")
		if name != "sinks" {
			in.jobs[name] = readJSONFile(p, pv.NewMap())
		}
	}
	for _, p := range jsonFiles(filepath.Join(data, "state", "sites"), ".json") {
		v := readJSONFile(p, pv.NewMap())
		d, ok := v.(*pv.Map)
		if !ok {
			return configErr("%s is not an object", p)
		}
		jobs, ok := orEmpty(d.Value("jobs"))
		if !ok {
			return configErr("%s: jobs is not an object", p)
		}
		for _, n := range jobs.Keys() {
			if _, seen := in.jobs[n]; !seen {
				in.jobs[n] = jobs.Value(n)
			}
		}
	}
	return nil
}

func (in *inputs) jobNames() []string {
	names := make([]string, 0, len(in.jobs))
	for n := range in.jobs {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// ledgerSection is ledger[key] as a mapping (`ledger.get(key) or {}`).
func (in *inputs) ledgerSection(key string) (*pv.Map, error) {
	m, ok := orEmpty(in.ledger.Value(key))
	if !ok {
		return nil, pv.AttributeError(in.ledger.Value(key), "get")
	}
	return m, nil
}

// loadAttestations reads <data>/attestations.yaml: {attestations: {<control id>: {...}}}; none when absent.
func loadAttestations(data string) (*pv.Map, error) {
	p := filepath.Join(data, "attestations.yaml")
	if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
		return pv.NewMap(), nil
	}
	v, err := readYAMLFile(p)
	if err != nil {
		return nil, err
	}
	doc, ok := orEmpty(v)
	if !ok {
		return nil, configErr("attestations.yaml is not a mapping")
	}
	att, ok := orEmpty(doc.Value("attestations"))
	if !ok {
		return nil, configErr("attestations.yaml: attestations is not a mapping")
	}
	return att, nil
}
