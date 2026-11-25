package ledger

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
)

// step is one merge of a scenario: documents, an exceptions.yaml to put in place first ("" = leave it), and
// what the given entry must look like afterwards.
type step struct {
	docs       map[string][]byte
	exceptions string
	at         float64
	want       map[string]any // entry field -> value (Repr compared)
}

func sshCheck() finding {
	return finding{asset: "host:web", check: "ssh.password_auth_enabled", severity: "critical", kind: "compliance"}
}

func imageVuln() finding {
	return finding{asset: "image:registry.example/web:1", check: "vuln.cve-2026-0001", severity: "high", kind: "vulnerability"}
}

func okWeb() coverage   { return coverage{asset: "host:web", status: "ok"} }
func gapWeb() coverage  { return coverage{asset: "host:web", status: "gap"} }
func okImage() coverage { return coverage{asset: "image:registry.example/web:1", status: "ok"} }

func exceptionFor(expires string) string {
	return "exceptions:\n  " + fid(sshCheck().asset, sshCheck().check) + ": {approved_by: reviewer, reason: lab, expires: '" + expires + "'}\n"
}

func validExc() string   { return exceptionFor("2099-01-01") }
func expiredExc() string { return exceptionFor("2000-01-01") }

// lifecycleCase is a sequence of merges and what the entry id looks like after each one.
type lifecycleCase struct {
	name  string
	id    string
	ref   map[string]bool
	steps []step
}

// lifecycleCases: §4 and LEDGER-D1/D2, with the reference behaviour of D2.
func lifecycleCases() []lifecycleCase {
	sshID := fid(sshCheck().asset, sshCheck().check)
	return []lifecycleCase{
		{"first sight opens with a due date (D2)", sshID, nil, []step{
			{docs: map[string][]byte{"host.findings.json": doc("host", t0, []coverage{okWeb()}, []finding{sshCheck()})}, at: t0,
				want: map[string]any{"status": "open", "due_at": "2026-11-08T08:00:00Z", "reopened_count": int64(0), "kind": "compliance"}}}},
		{"reference behaviour: no due date", sshID, map[string]bool{DeviationDueDate: true}, []step{
			{docs: map[string][]byte{"host.findings.json": doc("host", t0, []coverage{okWeb()}, []finding{sshCheck()})}, at: t0,
				want: map[string]any{"status": "open", "due_at": absent{}}}}},
		{"no kind is compliance (D1)", fid("host:web", "x.y"), nil, []step{
			{docs: map[string][]byte{"host.findings.json": doc("host", t0, []coverage{okWeb()},
				[]finding{{asset: "host:web", check: "x.y", severity: "low"}})}, at: t0, want: map[string]any{"kind": "compliance"}}}},
		{"covered and gone: fixed, then regression", sshID, nil, []step{
			{docs: map[string][]byte{"host.findings.json": doc("host", t0, []coverage{okWeb()}, []finding{sshCheck()})}, at: t0},
			{docs: map[string][]byte{"host.findings.json": doc("host", t0+14*day, []coverage{okWeb()}, nil)}, at: t0 + 14*day,
				want: map[string]any{"status": "fixed", "fixed_reason": "not_observed", "time_to_fix_days": 14.0}},
			{docs: map[string][]byte{"host.findings.json": doc("host", t0+20*day, []coverage{okWeb()}, []finding{sshCheck()})}, at: t0 + 20*day,
				want: map[string]any{"status": "open", "reopened_count": int64(1), "fixed_at": nil, "time_to_fix_days": nil,
					"due_at": "2026-11-28T08:00:00Z", "first_seen": "2026-11-01T08:00:00Z"}}}},
		{"a gap never fixes", sshID, nil, []step{
			{docs: map[string][]byte{"host.findings.json": doc("host", t0, []coverage{okWeb()}, []finding{sshCheck()})}, at: t0},
			{docs: map[string][]byte{"host.findings.json": doc("host", t0+day, []coverage{gapWeb()}, nil)}, at: t0 + day,
				want: map[string]any{"status": "open"}}}},
		{"a narrow gap keeps only its checks", sshID, nil, []step{
			{docs: map[string][]byte{"host.findings.json": doc("host", t0, []coverage{okWeb()}, []finding{sshCheck()})}, at: t0},
			{docs: map[string][]byte{"host.findings.json": doc("host", t0+day, []coverage{okWeb(),
				{asset: "host:web/sshd", status: "gap", checks: []string{"ssh.*"}}}, nil)}, at: t0 + day,
				want: map[string]any{"status": "open"}}}},
		{"another collector never fixes", sshID, nil, []step{
			{docs: map[string][]byte{"host.findings.json": doc("host", t0, []coverage{okWeb()}, []finding{sshCheck()})}, at: t0},
			{docs: map[string][]byte{"other.findings.json": doc("other", t0+day, []coverage{okWeb()}, nil)}, at: t0 + day,
				want: map[string]any{"status": "open"}}}},
	}
}

// deviationCases: LEDGER-D3 and D5, with the reference behaviour of each.
func deviationCases() []lifecycleCase {
	sshID := fid(sshCheck().asset, sshCheck().check)
	imgID := fid(imageVuln().asset, imageVuln().check)
	return []lifecycleCase{
		{"a gap on host:web does not protect an image (D3)", imgID, nil, []step{
			{docs: map[string][]byte{"vuln.findings.json": doc("vuln", t0, []coverage{okImage()}, []finding{imageVuln()})}, at: t0},
			{docs: map[string][]byte{"vuln.findings.json": doc("vuln", t0+day, []coverage{okImage(), gapWeb()}, nil)}, at: t0 + day,
				want: map[string]any{"status": "fixed"}}}},
		{"reference behaviour: substring gap protects the image", imgID, map[string]bool{DeviationGapSubstring: true}, []step{
			{docs: map[string][]byte{"vuln.findings.json": doc("vuln", t0, []coverage{okImage()}, []finding{imageVuln()})}, at: t0},
			{docs: map[string][]byte{"vuln.findings.json": doc("vuln", t0+day, []coverage{okImage(), gapWeb()}, nil)}, at: t0 + day,
				want: map[string]any{"status": "open"}}}},
		{"exception accepts, expiry reopens", sshID, nil, []step{
			{docs: map[string][]byte{"host.findings.json": doc("host", t0, []coverage{okWeb()}, []finding{sshCheck()})}, exceptions: validExc(), at: t0,
				want: map[string]any{"status": "accepted"}},
			{docs: map[string][]byte{"host.findings.json": doc("host", t0+day, []coverage{okWeb()}, []finding{sshCheck()})}, exceptions: expiredExc(),
				at: t0 + day, want: map[string]any{"status": "open"}}}},
		{"a removed exception reopens (D5)", sshID, nil, []step{
			{docs: map[string][]byte{"host.findings.json": doc("host", t0, []coverage{okWeb()}, []finding{sshCheck()})}, exceptions: validExc(), at: t0},
			{docs: map[string][]byte{"host.findings.json": doc("host", t0+day, []coverage{okWeb()}, []finding{sshCheck()})}, exceptions: "{}\n",
				at: t0 + day, want: map[string]any{"status": "open", "exception": absent{}}}}},
		{"reference behaviour: a removed exception stays accepted", sshID, map[string]bool{DeviationRemovedException: true}, []step{
			{docs: map[string][]byte{"host.findings.json": doc("host", t0, []coverage{okWeb()}, []finding{sshCheck()})}, exceptions: validExc(), at: t0},
			{docs: map[string][]byte{"host.findings.json": doc("host", t0+day, []coverage{okWeb()}, []finding{sshCheck()})}, exceptions: "{}\n",
				at: t0 + day, want: map[string]any{"status": "accepted"}}}},
	}
}

func TestMergeLifecycle(t *testing.T) {
	t.Parallel()
	for _, tc := range append(lifecycleCases(), deviationCases()...) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := newSandbox(t)
			for i, st := range tc.steps {
				if st.exceptions != "" {
					s.write("exceptions.yaml", []byte(st.exceptions))
				}
				l, _ := s.merge(st.at, Options{Reference: tc.ref}, st.docs)
				checkEntry(t, i, entry(l, tc.id), st.want)
			}
		})
	}
}

// absent marks a field that must not be there.
type absent struct{}

func checkEntry(t *testing.T, step int, e *pyjson.Object, want map[string]any) {
	t.Helper()
	if e == nil {
		t.Fatalf("step %d: no entry", step)
	}
	for k, w := range want {
		got, ok := e.Get(k)
		if _, mustBeAbsent := w.(absent); mustBeAbsent {
			if ok {
				t.Errorf("step %d: %s = %s, want absent", step, k, pyjson.Repr(got))
			}
			continue
		}
		if !ok || pyjson.Repr(got) != pyjson.Repr(w) {
			t.Errorf("step %d: %s = %s, want %s", step, k, pyjson.Repr(got), pyjson.Repr(w))
		}
	}
}

func TestMergeSLOFromInstance(t *testing.T) {
	t.Parallel()
	s := newSandbox(t)
	rem := pyjson.ObjectOf("slo", pyjson.ObjectOf("critical", "2d"))
	l, _ := s.merge(t0, Options{Remediation: rem}, map[string][]byte{"host.findings.json": doc("host", t0, []coverage{okWeb()}, []finding{sshCheck()})})
	checkEntry(t, 0, entry(l, fid(sshCheck().asset, sshCheck().check)), map[string]any{"due_at": "2026-11-03T08:00:00Z"})
}

func TestMergeRecordsInvalidDocuments(t *testing.T) {
	t.Parallel()
	s := newSandbox(t)
	l, _ := s.merge(t0, Options{}, map[string][]byte{
		"a.findings.json":       []byte("{not json"),
		"b.findings.json":       []byte(`{"schema_version": "2.0"}`),
		"host.findings.json":    doc("host", t0, []coverage{okWeb()}, []finding{sshCheck()}),
		".hidden.findings.json": []byte("ignored"),
	})
	runs := l.List("runs")
	last, _ := runs[len(runs)-1].(*pyjson.Object)
	inv := last.Obj("invalid")
	if inv.Len() != 2 || !strings.Contains(pyjson.Repr(inv.List("a.findings.json")), "not a JSON document") ||
		pyjson.Repr(inv.List("b.findings.json")) != `["unsupported schema_version '2.0' (core accepts ['1'])"]` {
		t.Fatalf("invalid = %s", pyjson.Repr(inv))
	}
	if l.Obj("entries").Len() != 1 || last.Str("implementation") != "go" || last.Str("run_dir") != filepath.Join("runs", "rb") {
		t.Fatalf("runs[-1] = %s", pyjson.Repr(last))
	}
	prom, err := os.ReadFile(filepath.Join(s.data, "metrics", "ledger.prom"))
	if err != nil || !bytes.Contains(prom, []byte("\nsecurity_contract_invalid_documents 2\n")) {
		t.Fatalf("ledger.prom: %v\n%s", err, prom)
	}
}

func TestMergeFailsWithoutTouchingTheLedger(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, file, content string
	}{
		{"corrupt previous ledger", "ledger.json", "{"},
		{"previous ledger is a list", "ledger.json", "[]"},
		{"exceptions.yaml syntax error", "exceptions.yaml", "exceptions: [\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := newSandbox(t)
			s.write(tc.file, []byte(tc.content))
			run := filepath.Join(s.data, "runs", "x")
			s.write("runs/x/host.findings.json", doc("host", t0, []coverage{okWeb()}, []finding{sshCheck()}))
			err := Merge(Options{Run: run, Data: s.data, Now: t0, Stderr: &bytes.Buffer{}})
			if err == nil {
				t.Fatal("Merge succeeded")
			}
			if _, statErr := os.Stat(filepath.Join(run, "sli.prom")); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("outputs written after an input error: %v", statErr)
			}
		})
	}
}

func TestMergeOutputs(t *testing.T) {
	t.Parallel()
	s := newSandbox(t)
	s.write("catalog-review.yaml", []byte("last_reviewed: 2026-10-01\n"))
	vuln := finding{asset: "image:registry.example/web:1", check: "vuln.cve-2026-0001", severity: "critical", kind: "vulnerability",
		attrs: map[string]any{"cve": "CVE-2026-0001", "published_at": "2026-10-30T08:00:00Z", "kev": true, "cvss": 9.8,
			"base_severity": "critical", "fixed": "1.2.3", "package": "openssl"}}
	_, stderr := s.merge(t0, Options{}, map[string][]byte{"vuln.findings.json": doc("vuln", t0, []coverage{okImage()}, []finding{vuln})})
	run := filepath.Join(s.data, "runs", "rb")
	for _, f := range []string{"sli.prom", "all.prom", "ocsf.jsonl"} {
		if _, err := os.Stat(filepath.Join(run, f)); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
	ocsf, err := os.ReadFile(filepath.Join(run, "ocsf.jsonl"))
	if err != nil || !bytes.Contains(ocsf, []byte(`"class_uid": 2002`)) || !bytes.Contains(ocsf, []byte(`"is_exploit_available": true`)) {
		t.Fatalf("ocsf: %v %s", err, ocsf)
	}
	e := entry(s.ledger(), fid(vuln.asset, vuln.check))
	checkEntry(t, 0, e, map[string]any{"disclosed_at": "2026-10-30T08:00:00Z", "time_to_know_hours": 48.0, "ttk_counted": false})
	sli := s.ledger().Obj("sli")
	if v, _ := sli.Obj("check_catalog_age_days").Get("value"); pyjson.Repr(v) != "31.3" {
		t.Errorf("check_catalog_age_days = %s", pyjson.Repr(v))
	}
	if v, _ := sli.Obj("oldest_fixable_critical_cve_days").Get("value"); pyjson.Repr(v) != "2.0" {
		t.Errorf("oldest_fixable_critical_cve_days = %s", pyjson.Repr(v))
	}
	if !strings.Contains(stderr, "[ledger 0.0.0-test] entries=1 open=1 invalid_docs=0") {
		t.Errorf("summary: %s", stderr)
	}
	if info, err := os.Stat(filepath.Join(s.data, "ledger.json")); err != nil || (info.Mode().Perm() != 0o600 && os.PathSeparator == '/') {
		t.Errorf("ledger.json mode: %v %v", info.Mode(), err)
	}
}

func TestBundledCatalogIsTheGeneratorsCopy(t *testing.T) {
	t.Parallel()
	want, err := os.ReadFile(filepath.Join("..", "..", "generators", "sli-catalog.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, sliCatalog) {
		t.Fatal("internal/ledger/sli-catalog.yaml differs from generators/sli-catalog.yaml: copy it")
	}
	if _, err := loadCatalog(); err != nil {
		t.Fatal(err)
	}
}
