//go:build unix

package runner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSiteToHubThroughTheBridge runs the whole path with the Python parts the Go runner reuses: a site's collector
// job is validated, promoted and queued in its outbox with its state (role site); the site's forward moves the
// outbox to the hub's inbox; the hub's ingest job (Python, through the bridge) merges it into the ledger; the hub
// publishes to a textfile sink readable by an exporter.
func TestSiteToHubThroughTheBridge(t *testing.T) {
	t.Parallel()
	py := requirePython(t, "yaml") // the ledger reads YAML exceptions
	f := newFixture(t, nil)
	runSite(t, f, py)
	runHub(t, f, py)
}

func box(f *fixture, d string) map[string]any {
	return map[string]any{"type": "local", "dir": filepath.Join(f.dir, d)}
}

func runSite(t *testing.T, f *fixture, py string) {
	t.Helper()
	doc, err := os.ReadFile(filepath.Join(repoRoot(t), "tests", "fixtures", "host.findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(f.dir, "doc.json"), doc, 0o600); err != nil {
		t.Fatal(err)
	}
	emit := f.script(t, "emit.sh", `cp "`+filepath.Join(f.dir, "doc.json")+`" "$SP_RUN_DIR/host.findings.json"`+"\n")
	site := map[string]any{"site": "s1", "role": "site", "outbox": box(f, "outbox"), "state_outbox": box(f, "state"),
		"forward": []any{map[string]any{"from": box(f, "outbox"), "to": box(f, "inbox")}},
		"jobs":    map[string]any{"host": map[string]any{"type": "command", "argv": []string{emit}, "schedule": "0 * * * *"}}}
	writeTestJSON(t, f.instance, map[string]any{"name": "t", "runner": site})
	r := f.runner(t, epoch(t, "2030-01-07T12:30:00Z"))
	r.python = py
	r.Tick(context.Background(), nil)
	if st := r.LoadState("host"); st.Int("last_rc", -1) != 0 || st["last_note"] != "document to outbox" {
		t.Fatalf("site job: %v\n%s", st, f.log)
	}
	if fw := r.LoadState("forward-0"); fw["last_note"] != "delivered 1" || fw.Int("pending", -1) != 0 {
		t.Fatalf("forward: %v\n%s", fw, f.log)
	}
	for _, p := range []string{"data/latest/host.findings.json", "data/latest/host.prom", "state/host.json", "state/forward-0.json"} {
		if _, err := os.Stat(filepath.Join(f.dir, p)); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
}

func runHub(t *testing.T, f *fixture, py string) {
	t.Helper()
	hub := filepath.Join(f.dir, "hub.json")
	sink := filepath.Join(f.dir, "export", "sp.prom")
	writeTestJSON(t, hub, map[string]any{"name": "t", "scorecard": map[string]any{"enabled": false}, "runner": map[string]any{
		"sinks": []any{map[string]any{"type": "textfile", "path": sink}},
		"jobs": map[string]any{"ingest-s1": map[string]any{"type": "ingest", "schedule": "*/15 * * * *", "site": "s1",
			"source": box(f, "inbox"), "site_state": box(f, "state"), "site_collectors": map[string]any{"host": "0 * * * *"}}}}})
	hubData := filepath.Join(f.dir, "hubdata")
	h := (&fixture{dir: f.dir, instance: hub, data: hubData, log: f.log}).runner(t, epoch(t, "2030-01-07T12:45:00Z"))
	h.python = py
	h.Tick(context.Background(), nil)
	if st := h.LoadState("ingest-s1"); st.Int("last_rc", -1) != 0 {
		t.Fatalf("ingest: %v\n%s", st, f.log)
	}
	if _, err := os.Stat(filepath.Join(hubData, "ledger.json")); err != nil {
		t.Errorf("no ledger: %v", err)
	}
	text, err := os.ReadFile(sink)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`security_runner_job_runs_total{job="host",site="s1"} 1`,
		`security_collector_expected_interval_seconds{collector="host"} 3600`, `security_collector_last_run_timestamp_seconds{collector="host"}`} {
		if !strings.Contains(string(text), want) {
			t.Errorf("published metrics lack %s", want)
		}
	}
	if fi, err := os.Stat(sink); err != nil || fi.Mode().Perm() != publishedMode {
		t.Errorf("sink file mode %v (%v), want %o", fi.Mode(), err, publishedMode)
	}
}

// TestContractViolationIsNotPromoted: the bridge's findings validation rejects a bad document (65).
func TestContractViolationIsNotPromoted(t *testing.T) {
	t.Parallel()
	py := requirePython(t)
	f := newFixture(t, nil)
	bad := f.script(t, "bad.sh", `echo '{"schema_version": "9.0"}' > "$SP_RUN_DIR/host.findings.json"`+"\n")
	writeTestJSON(t, f.instance, map[string]any{"name": "t", "scorecard": map[string]any{"enabled": false},
		"runner": map[string]any{"jobs": map[string]any{"host": map[string]any{"type": "command", "argv": []string{bad},
			"schedule": "0 * * * *"}}}})
	r := f.runner(t, epoch(t, "2030-01-07T12:30:00Z"))
	r.python = py
	r.Tick(context.Background(), nil)
	st := r.LoadState("host")
	if note, _ := st["last_note"].(string); st.Int("last_rc", 0) != 65 || !strings.HasPrefix(note, "contract violation: [") {
		t.Errorf("state %v", st)
	}
	if _, err := os.Stat(filepath.Join(f.data, "latest", "host.findings.json")); !os.IsNotExist(err) {
		t.Error("an invalid document was promoted")
	}
}
