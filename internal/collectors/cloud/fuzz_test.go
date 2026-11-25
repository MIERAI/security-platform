package cloud

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MIERAI/security-platform/internal/cloud/dyn"
	"github.com/MIERAI/security-platform/internal/collectors/cloud/pyjson"
)

// Every parser of engine output and provider exports is fuzzed: whatever the bytes, it returns verdicts in the
// documented shape (or none) and the merge and the document accept them. Seeds are the shared fixtures.

func seedFixtures(f *testing.F, names ...string) {
	f.Helper()
	for _, n := range names {
		data, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "fixtures", "cloud", n))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	f.Add([]byte(`[]`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`[{"status_code":"FAIL","resources":[null],"cloud":"x","finding_info":{"title":null}}]`))
}

// checkResults is the contract every parser output meets, and it must survive merging and emitting.
func checkResults(t *testing.T, provider string, rs []Result) {
	t.Helper()
	pool := NewPool()
	for i := range rs {
		checkResult(t, &rs[i])
		pool.Add(provider, dyn.Or(rs[i].Account, "acct"), &rs[i])
	}
	c := &collector{doc: NewDocument("cloud", Version, "", time.Now), pool: pool}
	c.emit()
	if _, err := pyjson.Marshal(c.doc.Doc(time.Now()), 1); err != nil {
		t.Fatal(err)
	}
	for _, f := range c.doc.findings {
		if !strings.HasPrefix(dyn.Str(f["asset"]), "cloud:"+provider+"/") && !strings.HasPrefix(dyn.Str(f["asset"]), "cloud:aws/") {
			t.Fatalf("asset %v outside the provider", f["asset"])
		}
	}
}

func checkResult(t *testing.T, r *Result) {
	t.Helper()
	if r.Status != "FAIL" && r.Status != "PASS" {
		t.Fatalf("status %q", r.Status)
	}
	if sevOrder(r.Severity) < 0 {
		t.Fatalf("severity %q", r.Severity)
	}
	if _, ok := Controls()[r.Control]; r.Control != "" && !ok {
		t.Fatalf("control %q", r.Control)
	}
}

func fuzzJSON(f *testing.F, provider string, parse func(any) []Result) {
	f.Helper()
	f.Fuzz(func(t *testing.T, data []byte) {
		doc, err := dyn.Decode(data)
		if err != nil {
			return
		}
		checkResults(t, provider, parse(doc))
	})
}

func FuzzParseProwlerOCSF(f *testing.F) {
	seedFixtures(f, "prowler-aws.ocsf.json", "prowler-gcp.ocsf.json", "prowler-azure.ocsf.json")
	fuzzJSON(f, "gcp", func(doc any) []Result { return ParseProwlerOCSF(doc, "gcp") })
}

func FuzzParseScoutSuite(f *testing.F) {
	seedFixtures(f, "scoutsuite-aws.json")
	fuzzJSON(f, "aws", func(doc any) []Result {
		ScoutBlindServices(dyn.Map(doc))
		return ParseScoutSuite(dyn.Map(doc), "aws", "000000000000")
	})
}

func FuzzParseSecurityHub(f *testing.F) {
	seedFixtures(f, "securityhub-asff.json")
	fuzzJSON(f, "aws", ParseSecurityHub)
}

func FuzzParseSCC(f *testing.F) {
	seedFixtures(f, "scc-findings.json")
	fuzzJSON(f, "gcp", ParseSCC)
}

func FuzzParseDefender(f *testing.F) {
	seedFixtures(f, "defender-assessments.json")
	fuzzJSON(f, "azure", ParseDefender)
}

func FuzzProwlerErrors(f *testing.F) {
	f.Add(`{"level":"ERROR","module":"s3_service","message":"a  b"}` + "\n" + `x` + "\n" + `{"level":"ERROR"}`)
	f.Fuzz(func(t *testing.T, log string) {
		errs := ProwlerErrors(log)
		if len(errs.keys) != len(errs.m) {
			t.Fatalf("order and map disagree: %v %v", errs.keys, errs.m)
		}
		for _, msgs := range errs.m {
			for _, m := range msgs {
				if strings.ContainsAny(m, "\n\t") || len([]rune(m)) > 200 {
					t.Fatalf("message not one short line: %q", m)
				}
			}
		}
	})
}

func FuzzSteampipeRows(f *testing.F) {
	f.Add(`{"rows":[{"arn":"a"}]}`)
	f.Add("Warning: x\n{\"rows\": null}")
	f.Add(`{"rows":`)
	f.Fuzz(func(t *testing.T, out string) {
		rows, ok := steampipeRows(out)
		if !ok && rows != nil {
			t.Fatal("rows from a failed parse")
		}
	})
}

func FuzzObjectKeys(f *testing.F) {
	f.Add([]byte(`{"cloud":{"engines":{"b":1,"a":{"x":[1,2]}}}}`))
	f.Add([]byte(`{"cloud":[1]}`))
	f.Add([]byte(`{"cloud":{"engines":`))
	f.Fuzz(func(t *testing.T, data []byte) {
		keys, err := objectKeys(data, "cloud", "engines")
		if err != nil {
			return
		}
		v, derr := dyn.Decode(data)
		if derr != nil {
			return
		}
		engines := dyn.Map(dyn.Map(dyn.Map(v)["cloud"])["engines"])
		for _, k := range keys {
			if _, ok := engines[k]; !ok {
				t.Fatalf("key %q not in the decoded object", k)
			}
		}
	})
}
