package ledger

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
)

// baseLedger is the ledger after one merge with one open entry, built once per fuzz target.
func baseLedger(f *testing.F) []byte {
	f.Helper()
	data := filepath.Join(f.TempDir(), "data")
	prev := filepath.Join(data, "runs", "r0")
	if err := os.MkdirAll(prev, 0o700); err != nil {
		f.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(prev, "host.findings.json"), doc("host", t0, []coverage{okWeb()}, []finding{sshCheck()}), 0o600); err != nil {
		f.Fatal(err)
	}
	if err := Merge(Options{Run: prev, Data: data, Now: t0, Stderr: &bytes.Buffer{}}); err != nil {
		f.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(data, "ledger.json"))
	if err != nil {
		f.Fatal(err)
	}
	return b
}

// fuzzSandbox is a data dir holding the base ledger, and an empty run dir.
func fuzzSandbox(t *testing.T, base []byte) (data, run string) {
	t.Helper()
	data = filepath.Join(t.TempDir(), "data")
	run = filepath.Join(data, "runs", "r1")
	if err := os.MkdirAll(run, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "ledger.json"), base, 0o600); err != nil {
		t.Fatal(err)
	}
	return data, run
}

func checkLedger(t *testing.T, data string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(data, "ledger.json"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := pyjson.Decode(b)
	if err != nil {
		t.Fatalf("ledger.json does not parse: %v", err)
	}
	o, _ := v.(*pyjson.Object)
	if o == nil || o.Str("schema") != Schema || o.Obj("entries") == nil || o.List("runs") == nil {
		t.Fatalf("ledger.json lost its structure: %s", b)
	}
}

// FuzzMergeDocument: whatever a collector writes, the merge records or merges it and writes a valid ledger.
func FuzzMergeDocument(f *testing.F) {
	f.Add(doc("host", t0+day, []coverage{okWeb()}, nil))
	f.Add(doc("host", t0+day, []coverage{gapWeb(), {asset: "host:web/x", status: "gap", checks: []string{"ssh.[!a]*"}}}, []finding{sshCheck()}))
	f.Add(doc("vuln", t0, []coverage{okImage()}, []finding{{asset: "image:registry.example/web:1", check: "v.x", severity: "high",
		kind: "vulnerability", attrs: map[string]any{"cve": "x", "published_at": "garbage", "kev_added": "2026-01-01"}}}))
	f.Add([]byte(`{"schema_version": "1.9", "collector": {"name": "host", "version": "1.0.0"}, "run": {"started_at": "2026-01-01T00:00:00Z",
		"finished_at": "2026-01-01T00:00:00+05:00"}, "coverage": [{"asset": "host:web", "status": "ok", "complete_scope": "host:"}],
		"findings": [], "metrics": [{"name": "security_secrets_older_than_90d", "value": 1e308}]}`))
	f.Add([]byte("[]"))
	base := baseLedger(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		dir, run := fuzzSandbox(t, base)
		if err := os.WriteFile(filepath.Join(run, "host.findings.json"), data, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := Merge(Options{Run: run, Data: dir, Now: t0 + 2*day, Stderr: &bytes.Buffer{}}); err != nil {
			t.Fatalf("Merge failed on a document: %v", err)
		}
		checkLedger(t, dir)
	})
}

// FuzzMergeExceptions: whatever a human writes in exceptions.yaml, the merge either applies it or stops
// without changing the ledger.
func FuzzMergeExceptions(f *testing.F) {
	for _, s := range []string{validExc(), expiredExc(), "exceptions:\n", "exceptions: [1, 2]\ncoverage_exceptions: 5\n",
		"exceptions: {" + fid(sshCheck().asset, sshCheck().check) + ": {approved_by: yes, expires: 2027-01-01T00:00:00+09:00}}\n",
		"coverage_exceptions:\n  host|host:web: &a {approved_by: x, expires: '2999-01-01'}\n  host:web: *a\n", "- a\n", "a: [\n"} {
		f.Add(s)
	}
	base := baseLedger(f)
	f.Fuzz(func(t *testing.T, exc string) {
		dir, run := fuzzSandbox(t, base)
		if err := os.WriteFile(filepath.Join(dir, "exceptions.yaml"), []byte(exc), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(run, "host.findings.json"), doc("host", t0+day, []coverage{okWeb(), gapWeb()}, []finding{sshCheck()}), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := Merge(Options{Run: run, Data: dir, Now: t0 + 2*day, Stderr: &bytes.Buffer{}}); err != nil {
			after, rerr := os.ReadFile(filepath.Join(dir, "ledger.json"))
			if rerr != nil || !bytes.Equal(after, base) {
				t.Fatalf("a failed merge changed ledger.json: %v", err)
			}
			return
		}
		checkLedger(t, dir)
	})
}
