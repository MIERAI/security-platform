package rundoc

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixedNow() time.Time { return time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC) }

func demoDocument(dir string) *Document {
	d := New("demo", "1.0.0", "lab", dir, fixedNow)
	d.Tools["nmap"] = "Nmap version 7.95"
	d.OK("host:a")
	d.Gap("host:b", strings.Repeat("r", 310))
	d.OK("host:b") // a gap stays a gap
	d.Add(&Finding{Layer: "network", Asset: "host:a", Check: "x.y", Title: "t\u00e9", Severity: "high", Evidence: "raw/demo/e.json",
		Remediation: "fix", NeedsHuman: true, Kind: KindDetection, Attributes: map[string]any{"n": 1}})
	d.Add(&Finding{Layer: "network", Asset: "host:a", Check: "x.y", Title: "duplicate", Severity: "low"})
	d.Metric("security_demo", 3, "Demo", [2]string{"kind", `a"b\c`})
	d.Metric("security_demo_total", 0.5, "")
	return d
}

// TestDocumentBytes pins the bytes the SDK writes for the same calls (sdk/spsdk: json.dump(indent=1,
// sort_keys=True), to_prom).
func TestDocumentBytes(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := demoDocument(dir).Write(); err != nil {
		t.Fatal(err)
	}
	doc, err := os.ReadFile(filepath.Join(dir, "demo.findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"title": "t\u00e9"`, `"kind": "detection"`, `"owner": "human"`, `"value": 3.0`,
		`"reason": "` + strings.Repeat("r", 300) + `"`, `"id": "` + FindingID("network", "host:a", "x.y") + `"`} {
		if !strings.Contains(string(doc), want) {
			t.Errorf("document lacks %s:\n%s", want, doc)
		}
	}
	if strings.Contains(string(doc), "duplicate") {
		t.Error("a second finding with the same id was kept")
	}
	prom, err := os.ReadFile(filepath.Join(dir, "demo.prom"))
	if err != nil {
		t.Fatal(err)
	}
	want := `# HELP security_collector_findings Findings reported by the latest run of a collector
# TYPE security_collector_findings gauge
security_collector_findings{collector="demo",layer="network",severity="high"} 1
# HELP security_collector_gaps Assets the collector could not cover
# TYPE security_collector_gaps gauge
security_collector_gaps{collector="demo"} 1
# HELP security_collector_assets Assets in scope of the run
# TYPE security_collector_assets gauge
security_collector_assets{collector="demo"} 2
# HELP security_collector_last_run_timestamp_seconds Heartbeat: when the collector last finished (no findings != secure)
# TYPE security_collector_last_run_timestamp_seconds gauge
security_collector_last_run_timestamp_seconds{collector="demo"} 1795608000
# HELP security_demo Demo
# TYPE security_demo gauge
security_demo{collector="demo",kind="a'b/c"} 3
# TYPE security_demo_total counter
security_demo_total{collector="demo"} 0.5
`
	if string(prom) != want {
		t.Errorf("prom:\n%s\nwant:\n%s", prom, want)
	}
}

func TestStartAndMain(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	inst := filepath.Join(dir, "instance.yaml")
	if err := os.WriteFile(inst, []byte("name: lab\nflag: yes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	vars := map[string]string{"SP_INSTANCE": inst, "SP_RUN_DIR": filepath.Join(dir, "run"), "SP_COLLECTOR_NAME": "renamed"}
	var stderr bytes.Buffer
	env := Env{Getenv: func(k string) string { return vars[k] }, Stderr: &stderr, Now: fixedNow}
	code := Main(context.Background(), env, []string{"collect"}, "demo", func(_ context.Context, env Env) error {
		r, err := Start(env, "demo", "1.0.0")
		if err != nil {
			return err
		}
		if r.Instance.Value("flag") != true {
			t.Errorf("YAML 1.1 typing: flag = %v", r.Instance.Value("flag"))
		}
		return r.Finish()
	})
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "run", "renamed.findings.json")); err != nil {
		t.Error("SP_COLLECTOR_NAME names the document")
	}
	if !strings.Contains(stderr.String(), "[renamed 1.0.0] findings=0 assets=0 gaps=0") {
		t.Errorf("summary line: %q", stderr.String())
	}
	failing := func(context.Context, Env) error { return errors.New("boom\x1b[2J") }
	stderr.Reset()
	if code := Main(context.Background(), env, []string{"collect"}, "demo", failing); code != 1 ||
		strings.Contains(stderr.String(), "\x1b") {
		t.Errorf("failure: exit %d, stderr %q", code, stderr.String())
	}
	if code := Main(context.Background(), env, []string{"other"}, "demo", failing); code != 2 {
		t.Errorf("usage: exit %d", code)
	}
}

func TestCutAndExpand(t *testing.T) {
	t.Parallel()
	if got := Cut("äöü", 2); got != "äö" {
		t.Errorf("Cut = %q", got)
	}
	home := filepath.Join(string(filepath.Separator)+"home", "u")
	if got := ExpandUser("~/x", home); got != filepath.Join(home, "x") {
		t.Errorf("ExpandUser = %q", got)
	}
	if got := ExpandUser("~other/x", "/home/u"); got != "~other/x" {
		t.Errorf("ExpandUser(~other) = %q", got)
	}
}
