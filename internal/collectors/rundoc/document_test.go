package rundoc

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
)

// TestGoldenDocument: the same calls as testdata's generator made on sdk/spsdk (CPython 3.12) give the same bytes:
// findings document, Prometheus text and evidence.
func TestGoldenDocument(t *testing.T) {
	t.Parallel()
	now := time.Unix(1795000000, 0)
	d := New("golden", "1.2.3", "golden", func() time.Time { return now })
	dir := t.TempDir()
	goldenCalls(t, d, dir)
	now = now.Add(5 * time.Second)
	var stderr bytes.Buffer
	if err := d.Write(dir, &stderr); err != nil {
		t.Fatal(err)
	}
	for got, want := range map[string]string{"golden.findings.json": "golden.findings.json", "golden.prom": "golden.prom",
		filepath.Join("raw", "golden", "ev.json"): "golden.raw.json"} {
		assertSameFile(t, filepath.Join(dir, got), filepath.Join("testdata", want))
	}
	if stderr.String() != "[golden 1.2.3] findings=3 assets=4 gaps=2\n" {
		t.Errorf("summary line %q", stderr.String())
	}
}

func assertSameFile(t *testing.T, got, want string) {
	t.Helper()
	g, err := os.ReadFile(got)
	if err != nil {
		t.Fatal(err)
	}
	w, err := os.ReadFile(want)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(g, w) {
		t.Errorf("%s differs from the Python SDK's\n got: %s\nwant: %s", got, g, w)
	}
	if fi, err := os.Stat(got); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("%s: mode %v, want 0600 (%v)", got, fi.Mode().Perm(), err)
	}
}

// goldenCalls makes the calls testdata's generator made on the Python SDK.
func goldenCalls(t *testing.T, d *Document, dir string) {
	t.Helper()
	d.Tools.Set("tool", "9.9")
	d.OK("host:a", "")
	d.OK("inventory:container-image", "image:")
	d.Gap("host:b", "unreachable: été "+strings.Repeat("x", 400), nil)
	d.OK("host:b", "")
	d.Gap("host:a/probe", "timed out", []string{"host.z*", "host.a*"})
	d.AddFinding(&Finding{Layer: "host", Asset: "host:a", Check: "x.one", Title: "Títle \U0001F600 " + strings.Repeat("y", 400),
		Severity: "high", Evidence: "raw/golden/e.json#k", Remediation: "fix it"})
	d.AddFinding(&Finding{Layer: "host", Asset: "host:a", Check: "x.one", Title: "dup", Severity: "low", Evidence: "e", Remediation: "r"})
	attrs := pyjson.NewObject()
	for _, kv := range []struct {
		k string
		v pyjson.Value
	}{{"cve", "CVE-1"}, {"cvss", 9.8}, {"epss", 0.00012}, {"count", int64(3)}, {"kev", false}, {"kev_added", nil},
		{"clusters", []pyjson.Value{"b", "a"}}, {"exposed", true}} {
		attrs.Set(kv.k, kv.v)
	}
	d.AddFinding(&Finding{Layer: "supply-chain", Asset: "image:r/a:1", Check: "vuln.cve-1", Title: "CVE", Severity: "critical",
		Evidence: "raw/golden/m.json", Remediation: "update", NeedsHuman: true, Kind: "vulnerability",
		Refs: []pyjson.Value{"CVE-1", "GHSA-x"}, Attributes: attrs})
	d.AddFinding(&Finding{Layer: "identity", Asset: "k8s-identity:c/User:x", Check: "k8s.rbac.wildcard", Title: "w",
		Severity: "medium", Evidence: "e", Remediation: "r", Owner: "team-a"})
	d.Metric("security_x_total", 3, "A counter", map[string]string{"a": "1", "b": "q\"\\\nz"})
	d.Metric("security_y", 1e6, "Big", nil)
	tenth := 0.1
	d.Metric("security_y", tenth+0.2, "", map[string]string{"kind": "f"})
	d.Metric("security_z", 12345678.9, "", nil)
	ev := pyjson.NewObject()
	inner := pyjson.NewObject()
	inner.Set("z", int64(1))
	inner.Set("y", []pyjson.Value{})
	ev.Set("b", []pyjson.Value{int64(1), 2.5, nil, true, "é"})
	ev.Set("a", inner)
	if p, err := d.Raw(dir, "ev.json", ev); err != nil || p != "raw/golden/ev.json" {
		t.Fatalf("Raw = %q, %v", p, err)
	}
}

func TestBumpAndCut(t *testing.T) {
	t.Parallel()
	tests := []struct {
		sev  string
		n    int
		want string
	}{{"info", 1, "low"}, {"high", 1, "critical"}, {"critical", 1, "critical"}, {"low", 2, "high"}, {"odd", 1, "odd"}}
	for _, tc := range tests {
		if got := Bump(tc.sev, tc.n); got != tc.want {
			t.Errorf("Bump(%q, %d) = %q, want %q", tc.sev, tc.n, got, tc.want)
		}
	}
	if Cut("aé€😀b", 4) != "aé€😀" || Cut("ab", 5) != "ab" || Cut("ab", 0) != "" {
		t.Error("Cut does not count characters")
	}
}
