package cloud

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/MIERAI/security-platform/internal/cloud/dyn"
)

// golden is testdata/golden.json: the Python implementation's answers on the shared fixtures
// (testdata/gen_golden.py; tests/test_cloud.py keeps it current).
type golden struct {
	Parsers         map[string]json.RawMessage `json:"parsers"`
	ScoutsuiteBlind []string                   `json:"scoutsuite_blind"`
	ProwlerLog      struct {
		Text   string              `json:"text"`
		Errors map[string][]string `json:"errors"`
	} `json:"prowler_log"`
	Pools          map[string]json.RawMessage     `json:"pools"`
	Controls       map[string][]json.RawMessage   `json:"controls"`
	Maps           map[string]map[string]string   `json:"maps"`
	PillarByPrefix [][2]string                    `json:"pillar_by_prefix"`
	CISVersions    map[string]string              `json:"cis_versions"`
	Steampipe      map[string][]map[string]string `json:"steampipe"`
	Version        string                         `json:"version"`
}

func loadGolden(t *testing.T) golden {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	var g golden
	if err := json.Unmarshal(data, &g); err != nil {
		t.Fatal(err)
	}
	return g
}

func fixture(tb testing.TB, name string) any {
	tb.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "fixtures", "cloud", name))
	if err != nil {
		tb.Fatal(err)
	}
	v, err := dyn.Decode(data)
	if err != nil {
		tb.Fatal(err)
	}
	return v
}

func resultJSON(r *Result) map[string]any {
	refs := r.Refs
	if refs == nil {
		refs = []string{}
	}
	return map[string]any{"source": r.Source, "provider": r.Provider, "account": r.Account, "service": r.Service,
		"region": r.Region, "resource": r.Resource, "name": r.Name, "check": r.Check, "control": r.Control,
		"status": r.Status, "severity": r.Severity, "title": r.Title, "detail": r.Detail, "refs": refs,
		"remediation": r.Remediation, "coverage_only": r.CoverageOnly}
}

func mergedJSON(f *Merged) map[string]any {
	return map[string]any{"asset": f.Asset, "check": f.Check, "pillar": f.Pillar, "layer": f.Layer,
		"severity": f.Severity, "title": f.Title, "remediation": f.Remediation, "refs": f.Refs,
		"sources": sourcesJSON(f.Sources), "provider": f.Provider, "account": f.Account, "resource": f.Resource,
		"cis_benchmark": f.CISBenchmark}
}

// sameJSON compares a Go value with the golden JSON after a round trip through encoding/json.
func sameJSON(t *testing.T, got any, want json.RawMessage) {
	t.Helper()
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var g, w any
	if err := json.Unmarshal(data, &g); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(want, &w); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(g, w) {
		t.Fatalf("differs from the Python implementation\n got: %s\nwant: %s", data, want)
	}
}

func results(rs []Result) []any {
	out := make([]any, len(rs))
	for i := range rs {
		out[i] = resultJSON(&rs[i])
	}
	return out
}

func TestParsersMatchPython(t *testing.T) {
	t.Parallel()
	g := loadGolden(t)
	tests := []struct {
		name  string
		parse func() []Result
	}{
		{"prowler-aws", func() []Result { return ParseProwlerOCSF(fixture(t, "prowler-aws.ocsf.json"), "aws") }},
		{"prowler-gcp", func() []Result { return ParseProwlerOCSF(fixture(t, "prowler-gcp.ocsf.json"), "") }},
		{"prowler-azure", func() []Result { return ParseProwlerOCSF(fixture(t, "prowler-azure.ocsf.json"), "") }},
		{"scoutsuite-aws", func() []Result {
			return ParseScoutSuite(dyn.Map(fixture(t, "scoutsuite-aws.json")), "aws", "000000000000")
		}},
		{"securityhub", func() []Result { return ParseSecurityHub(fixture(t, "securityhub-asff.json")) }},
		{"scc", func() []Result { return ParseSCC(fixture(t, "scc-findings.json")) }},
		{"defender", func() []Result { return ParseDefender(fixture(t, "defender-assessments.json")) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sameJSON(t, results(tc.parse()), g.Parsers[tc.name])
		})
	}
}

func TestScoutBlindAndProwlerLogMatchPython(t *testing.T) {
	t.Parallel()
	g := loadGolden(t)
	if got := ScoutBlindServices(dyn.Map(fixture(t, "scoutsuite-aws.json"))); !reflect.DeepEqual(got, g.ScoutsuiteBlind) {
		t.Fatalf("blind services %v, want %v", got, g.ScoutsuiteBlind)
	}
	errs := ProwlerErrors(g.ProwlerLog.Text)
	if !reflect.DeepEqual(errs.m, g.ProwlerLog.Errors) {
		t.Fatalf("prowler log errors %v, want %v", errs.m, g.ProwlerLog.Errors)
	}
}

func TestPoolsMatchPython(t *testing.T) {
	t.Parallel()
	g := loadGolden(t)
	aws := append(append(ParseProwlerOCSF(fixture(t, "prowler-aws.ocsf.json"), "aws"),
		ParseScoutSuite(dyn.Map(fixture(t, "scoutsuite-aws.json")), "aws", "000000000000")...),
		ParseSecurityHub(fixture(t, "securityhub-asff.json"))...)
	tests := []struct {
		name, provider, account string
		results                 []Result
	}{
		{"aws", "aws", "000000000000", aws},
		{"gcp", "gcp", "", append(ParseProwlerOCSF(fixture(t, "prowler-gcp.ocsf.json"), ""), ParseSCC(fixture(t, "scc-findings.json"))...)},
		{"azure", "azure", "", append(ParseProwlerOCSF(fixture(t, "prowler-azure.ocsf.json"), ""),
			ParseDefender(fixture(t, "defender-assessments.json"))...)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := NewPool()
			for i := range tc.results {
				r := &tc.results[i]
				p.Add(tc.provider, dyn.Or(r.Account, tc.account), r)
			}
			var got []any
			for _, f := range p.Items() {
				got = append(got, mergedJSON(f))
			}
			sameJSON(t, got, g.Pools[tc.name])
		})
	}
}

func TestControlTablesMatchPython(t *testing.T) {
	t.Parallel()
	g := loadGolden(t)
	ctls := map[string][]any{}
	for id, c := range Controls() {
		cis := c.CIS
		if cis == nil {
			cis = map[string][]string{}
		}
		ctls[id] = []any{c.Pillar, c.Layer, c.Title, c.Remediation, cis}
	}
	data, err := json.Marshal(g.Controls)
	if err != nil {
		t.Fatal(err)
	}
	sameJSON(t, ctls, data)
	for source, want := range g.Maps {
		if got := controlTable(source); !reflect.DeepEqual(got, want) {
			t.Errorf("%s map differs from the Python implementation", source)
		}
	}
	if got := pillarByPrefix(); !reflect.DeepEqual(got, g.PillarByPrefix) {
		t.Errorf("pillar prefixes differ: %v", got)
	}
	if !reflect.DeepEqual(CISVersions(), g.CISVersions) {
		t.Errorf("CIS versions differ")
	}
	var qs []map[string]string
	for _, q := range steampipeQueries()["aws"] {
		qs = append(qs, map[string]string{"id": q.ID, "control": q.Control, "service": q.Service, "severity": q.Severity, "sql": q.SQL})
	}
	if !reflect.DeepEqual(qs, g.Steampipe["aws"]) || len(g.Steampipe) != len(steampipeQueries()) {
		t.Errorf("steampipe query pack differs from the Python implementation")
	}
}

func TestEveryMappingNamesAControl(t *testing.T) {
	t.Parallel()
	ctls := Controls()
	for _, source := range []string{"prowler", "scoutsuite", "securityhub", "scc", "defender"} {
		for check, ctl := range controlTable(source) {
			if _, ok := ctls[ctl]; !ok {
				t.Errorf("%s %s -> unknown control %s", source, check, ctl)
			}
		}
	}
	for _, q := range steampipeQueries()["aws"] {
		if _, ok := ctls[q.Control]; !ok {
			t.Errorf("steampipe %s -> unknown control %s", q.ID, q.Control)
		}
	}
}

func TestVersionMatchesTree(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "collectors", "cloud", "VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(data)); got != Version || loadGolden(t).Version != Version {
		t.Fatalf("collectors/cloud/VERSION %s, golden %s, Go %s", got, loadGolden(t).Version, Version)
	}
}
