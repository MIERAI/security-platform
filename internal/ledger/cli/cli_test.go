package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const finding = `{"schema_version": "1.2", "collector": {"name": "host", "version": "1.0.0"},
 "run": {"started_at": "2026-11-01T08:00:00Z", "finished_at": "2026-11-01T08:00:00Z"},
 "coverage": [{"asset": "host:web", "status": "ok"}],
 "findings": [{"id": "4a8faf0efd8f", "check": "ssh.password_auth_enabled", "layer": "host", "asset": "host:web",
  "title": "t", "severity": "critical", "evidence": "raw/x", "remediation": "r", "needs_human": false,
  "owner": "platform", "observed_at": "2026-11-01T08:00:00Z"}]}`

func sandbox(t *testing.T) (data, run, instance string) {
	t.Helper()
	root := t.TempDir()
	data, run, instance = filepath.Join(root, "data"), filepath.Join(root, "data", "runs", "r1"), filepath.Join(root, "instance.yaml")
	files := map[string]string{filepath.Join(run, "host.findings.json"): finding,
		instance: "name: test\nremediation:\n  default_owner: oncall\n  slo: {critical: 2d}\n"}
	for p, c := range files {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return data, run, instance
}

// runCase is one command line and what it must do.
type runCase struct {
	name   string
	args   func(data, run, inst string) []string
	code   int
	stdout string // substring
	stderr string // substring
	file   string // must exist afterwards, relative to data
	inFile string // substring of that file
}

// runCases are the command lines TestRun checks.
func runCases() []runCase {
	return []runCase{
		{name: "no subcommand", args: func(_, _, _ string) []string { return nil }, code: ExitUsage, stderr: "a subcommand is required"},
		{name: "unknown", args: func(_, _, _ string) []string { return []string{"frobnicate"} }, code: ExitUsage, stderr: "unknown subcommand"},
		{name: "version", args: func(_, _, _ string) []string { return []string{"version"} }, stdout: "sp ledger "},
		{name: "help", args: func(_, _, _ string) []string { return []string{"--help"} }, stdout: "usage: sp ledger merge"},
		{name: "merge without --run", args: func(d, _, _ string) []string { return []string{"merge", "--data", d} }, code: ExitUsage},
		{name: "merge with extra argument", args: func(d, r, _ string) []string { return []string{"merge", "--data", d, "--run", r, "x"} }, code: ExitUsage},
		{name: "bad --now", args: func(d, r, _ string) []string { return []string{"merge", "--data", d, "--run", r, "--now", "soon"} }, code: ExitUsage},
		{name: "bad deviation", args: func(d, r, _ string) []string {
			return []string{"merge", "--data", d, "--run", r, "--reference-behaviour", "D4"}
		}, code: ExitUsage, stderr: "is not one of"},
		{name: "missing instance", args: func(d, r, _ string) []string {
			return []string{"merge", "--data", d, "--run", r, "--instance", "/nonexistent"}
		},
			code: ExitError, stderr: "instance config"},
		{name: "merge", args: func(d, r, i string) []string {
			return []string{"merge", "--data", d, "--run", r, "--instance", i, "--now", "1793520000"}
		}, stderr: "[ledger ", file: "ledger.json", inFile: `"due_at": "2026-11-03T08:00:00Z"`},
		{name: "merge, reference behaviour", args: func(d, r, _ string) []string {
			return []string{"merge", "--data", d, "--run", r, "--now", "1793520000", "--reference-behaviour", "D2, LEDGER-D3"}
		}, file: "ledger.json"},
		{name: "track without a ledger", args: func(d, _, _ string) []string { return []string{"track", "--data", d} }, code: ExitError},
	}
}

func TestRun(t *testing.T) {
	t.Parallel()
	tests := runCases()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			data, run, inst := sandbox(t)
			var out, errOut bytes.Buffer
			env := Env{Stdout: &out, Stderr: &errOut, Now: time.Now}
			if code := Run(context.Background(), env, tc.args(data, run, inst)); code != tc.code {
				t.Fatalf("exit %d, want %d\n%s", code, tc.code, errOut.String())
			}
			if !strings.Contains(out.String(), tc.stdout) || !strings.Contains(errOut.String(), tc.stderr) {
				t.Fatalf("stdout %q stderr %q", out.String(), errOut.String())
			}
			checkFile(t, data, tc.file, tc.inFile)
		})
	}
}

// checkFile: when file is set, data/file exists and contains want.
func checkFile(t *testing.T, data, file, want string) {
	t.Helper()
	if file == "" {
		return
	}
	b, err := os.ReadFile(filepath.Join(data, file))
	if err != nil || !strings.Contains(string(b), want) {
		t.Fatalf("%s: %v\n%s", file, err, b)
	}
}

func TestMergeThenTrack(t *testing.T) {
	t.Parallel()
	data, run, inst := sandbox(t)
	env := Env{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, Now: time.Now}
	if code := Run(context.Background(), env, []string{"merge", "--data", data, "--run", run, "--instance", inst}); code != ExitOK {
		t.Fatalf("merge exit %d", code)
	}
	args := []string{"track", "--data", data, "--instance", inst, "--now", "1793520000", "--no-external-sync"}
	if code := Run(context.Background(), env, args); code != ExitOK {
		t.Fatalf("track exit %d", code)
	}
	b, err := os.ReadFile(filepath.Join(data, "tracker", "items.json"))
	if err != nil || !strings.Contains(string(b), `"owner": "oncall"`) || !strings.Contains(string(b), `"due_at": "2026-11-03T08:00:00Z"`) {
		t.Fatalf("items.json: %v\n%s", err, b)
	}
}
