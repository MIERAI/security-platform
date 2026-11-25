package spdoc

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixedNow() time.Time { return time.Date(2026, 11, 25, 9, 30, 0, 0, time.UTC) }

func TestFindingID(t *testing.T) {
	t.Parallel()
	// sha1("host|host:m|patch.pending")[:12], as spsdk.fid computes it
	if got := FindingID("host", "host:m", "patch.pending"); got != "081280847434" {
		t.Fatalf("FindingID = %s", got)
	}
}

func TestDocument(t *testing.T) {
	t.Parallel()
	d := New("host", "1.0.0", "lab", fixedNow)
	mustAdd(t, d, &Finding{Layer: "host", Asset: "host:a", Check: "x.one", Title: strings.Repeat("t", 400), Severity: "low",
		Evidence: "raw/host/a.json", Remediation: "fix"})
	mustAdd(t, d, &Finding{Layer: "host", Asset: "host:a", Check: "x.one", Title: "again", Severity: "high"})
	mustAdd(t, d, &Finding{Layer: "network", Asset: "host:a", Check: "x.two", Title: "two", Severity: "high", NeedsHuman: true})
	if err := d.Add(&Finding{Layer: "nope", Severity: "low"}); err == nil {
		t.Fatal("an unknown layer was accepted")
	}
	d.Gap("host:b", strings.Repeat("r", 400), nil)
	d.OK("host:b") // a gap stays a gap
	d.OK("host:a")
	d.Gap("host:a/part", "why", []string{"z.*", "a.b"})
	mark := d.Count()
	mustAdd(t, d, &Finding{Layer: "host", Asset: "host:a", Check: "z.dropped", Title: "z", Severity: "low"})
	mustAdd(t, d, &Finding{Layer: "host", Asset: "host:a", Check: "y.kept", Title: "y", Severity: "low"})
	d.DropSince(mark, func(c string) bool { return strings.HasPrefix(c, "z.") })
	d.Metric("security_x", 3, "X", map[string]string{"host": `a"b\c`})
	doc := d.Doc(fixedNow())
	cov, _ := doc["coverage"].([]any)
	findings, _ := doc["findings"].([]any)
	if len(cov) != 3 || len(findings) != 3 {
		t.Fatalf("coverage %v findings %v", cov, findings)
	}
	b, _ := cov[0].(map[string]any)
	if reason, _ := b["reason"].(string); b["status"] != "gap" || len([]rune(reason)) != 300 {
		t.Errorf("gap entry %v", b)
	}
	part, _ := cov[2].(map[string]any)
	if got, _ := part["checks"].([]string); strings.Join(got, ",") != "a.b,z.*" {
		t.Errorf("narrow gap checks %v", part["checks"])
	}
	f0, _ := findings[0].(map[string]any)
	f1, _ := findings[1].(map[string]any)
	if title, _ := f0["title"].(string); len([]rune(title)) != 300 || f0["severity"] != "low" || f1["owner"] != "human" {
		t.Errorf("findings %v %v", f0, f1)
	}
	if got := d.Summary(); got != "[host 1.0.0] findings=3 assets=3 gaps=2" {
		t.Errorf("summary %q", got)
	}
	if got := d.prom(fixedNow()); !strings.Contains(got, `security_x{collector="host",host="a'b/c"} 3`+"\n") {
		t.Errorf("label escaping (as spsdk.render):\n%s", got)
	}
}

func assertPrivate(t *testing.T, dir string, files ...string) {
	t.Helper()
	for _, f := range files {
		st, err := os.Stat(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		if p := st.Mode().Perm(); p&0o077 != 0 && os.PathSeparator == '/' {
			t.Errorf("%s has mode %o, want private (0600)", f, p)
		}
	}
}

func mustAdd(t *testing.T, d *Document, f *Finding) {
	t.Helper()
	if err := d.Add(f); err != nil {
		t.Fatal(err)
	}
}

func TestWrite(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	d := New("host", "1.0.0", "", fixedNow)
	mustAdd(t, d, &Finding{Layer: "host", Asset: "host:a", Check: "c", Title: "t", Severity: "medium"})
	d.OK("host:a")
	d.Metric("security_host_wildcard_listeners", 2, "Sockets", map[string]string{"host": "a"})
	ptr, err := d.Raw(dir, "a.json", map[string]any{"b": 1, "a": "x"})
	if err != nil || ptr != "raw/host/a.json" {
		t.Fatalf("Raw = %q, %v", ptr, err)
	}
	if werr := d.Write(dir); werr != nil {
		t.Fatal(werr)
	}
	prom, err := os.ReadFile(filepath.Join(dir, "host.prom"))
	if err != nil {
		t.Fatal(err)
	}
	want := `# HELP security_collector_findings Findings reported by the latest run of a collector
# TYPE security_collector_findings gauge
security_collector_findings{collector="host",layer="host",severity="medium"} 1
# HELP security_collector_gaps Assets the collector could not cover
# TYPE security_collector_gaps gauge
security_collector_gaps{collector="host"} 0
# HELP security_collector_assets Assets in scope of the run
# TYPE security_collector_assets gauge
security_collector_assets{collector="host"} 1
# HELP security_collector_last_run_timestamp_seconds Heartbeat: when the collector last finished (no findings != secure)
# TYPE security_collector_last_run_timestamp_seconds gauge
security_collector_last_run_timestamp_seconds{collector="host"} 1795599000
# HELP security_host_wildcard_listeners Sockets
# TYPE security_host_wildcard_listeners gauge
security_host_wildcard_listeners{collector="host",host="a"} 2
`
	if string(prom) != want {
		t.Errorf("prom:\n%s\nwant:\n%s", prom, want)
	}
	assertPrivate(t, dir, "host.findings.json", "host.prom", filepath.Join("raw", "host", "a.json"))
	var doc map[string]any
	data, err := os.ReadFile(filepath.Join(dir, "host.findings.json"))
	if err != nil || json.Unmarshal(data, &doc) != nil {
		t.Fatalf("document: %v", err)
	}
	if doc["schema_version"] != "1.2" {
		t.Errorf("schema_version %v", doc["schema_version"])
	}
}
