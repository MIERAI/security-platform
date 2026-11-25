package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// now is the fixed clock of these tests: 2026-11-25 12:00:00 UTC.
var testNow = time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC) //nolint:gochecknoglobals // a constant time value; time.Time has no const form

func writeFile(t *testing.T, path string, v any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	var b []byte
	if s, ok := v.(string); ok {
		b = []byte(s)
	} else {
		var err error
		if b, err = json.Marshal(v); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func entry(id, check, sev, status, first string) map[string]any {
	return map[string]any{"id": id, "check": check, "layer": "host", "asset": "host:secret-" + id[:3], "title": check + " title",
		"severity": sev, "status": status, "first_seen": first, "last_seen": "2026-11-25T11:00:00Z", "evidence": "raw/x.json#k",
		"remediation": "", "needs_human": false, "reopened_count": 0}
}

// fixture is a data directory: a ledger of four findings, a tracker, an instance with three jobs and their states.
func fixture(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "data")
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatal(err)
	}
	fixed := entry("ddd000000004", "patch.pending", "low", "fixed", "2026-11-01T00:00:00Z")
	fixed["fixed_at"] = "2026-11-25T10:00:00Z"
	writeFile(t, filepath.Join(d, "ledger.json"), map[string]any{"entries": map[string]any{
		"aaa000000001": entry("aaa000000001", "ssh.password_auth_enabled", "critical", "open", "2026-11-25T08:00:00Z"),
		"aab000000002": entry("aab000000002", "conformance.other", "high", "open", "2026-11-01T00:00:00Z"),
		"ccc000000003": entry("ccc000000003", "vuln.cve-1", "medium", "open", "2026-11-01T00:00:00Z"),
		"ddd000000004": fixed,
	}, "collectors": map[string]any{"host": map[string]any{}}})
	writeFile(t, filepath.Join(d, "tracker", "items.json"), map[string]any{"items": map[string]any{
		"aaa000000001": map[string]any{"id": "aaa000000001", "status": "open", "overdue": true, "owner": "ops"},
		"aab000000002": map[string]any{"id": "aab000000002", "status": "open", "due_at": "2026-12-01T00:00:00Z", "owner": "unassigned"}}})
	writeFile(t, filepath.Join(d, "instance.json"), map[string]any{"name": "unit", "runner": map[string]any{"jobs": map[string]any{
		"host": map[string]any{"schedule": "15 2 * * *"}, "late": map[string]any{"type": "remediation", "schedule": "*/10 * * * *"},
		"never": map[string]any{"schedule": "0 4 * * *"}}}})
	now := float64(testNow.Unix())
	writeFile(t, filepath.Join(d, "state", "runner", "host.json"), map[string]any{"runs_total": 2, "last_rc": 0, "last_success": now - 7200})
	writeFile(t, filepath.Join(d, "state", "runner", "late.json"), map[string]any{"runs_total": 2, "last_rc": 0,
		"last_success": now - 3000, "done_slot": now - 3000})
	return d
}

type result struct {
	code           int
	stdout, stderr string
}

func testEnv(vars map[string]string, out, errOut io.Writer) Env {
	return Env{Stdout: out, Stderr: errOut, Getenv: func(k string) string { return vars[k] },
		Now: func() time.Time { return testNow }, Loc: time.UTC, Hostname: "Lab-1.example", GOOS: "linux",
		TreeErr: errors.New("no tree in unit tests"),
		Python:  func() (string, error) { return "", errors.New("no python in unit tests") },
		Exec: func(context.Context, []string, io.Writer, io.Writer) (int, error) {
			return 0, errors.New("no runner in unit tests")
		},
		Probe: func(context.Context, []string) (int, error) { return 0, nil }}
}

func run(t *testing.T, env Env, args ...string) result {
	t.Helper()
	var out, errOut bytes.Buffer
	env.Stdout, env.Stderr = &out, &errOut
	code := Main(t.Context(), env, args)
	return result{code, out.String(), errOut.String()}
}

func sp(t *testing.T, vars map[string]string, args ...string) result {
	t.Helper()
	return run(t, testEnv(vars, nil, nil), args...)
}

func TestFindings(t *testing.T) {
	t.Parallel()
	d := fixture(t)
	D := []string{"--data", d}
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"findings", "--ids"}, "aaa000000001\naab000000002\nccc000000003\nddd000000004\n"},
		{[]string{"findings", "--open", "--severity", "high", "--ids"}, "aaa000000001\naab000000002\n"},
		{[]string{"findings", "--overdue", "--ids"}, "aaa000000001\n"},
		{[]string{"findings", "--check", "vuln.", "--ids"}, "ccc000000003\n"},
		{[]string{"findings", "--layer", "nope", "--ids"}, "\n"},
		{[]string{"findings", "--layer", "nope"}, "no matching findings\n"},
		{[]string{"findings", "--check", "vuln.", "--json"}, "[\n {\n  \"asset\": \"host:secret-ccc\",\n  \"check\": \"vuln.cve-1\",\n" +
			"  \"evidence\": \"raw/x.json#k\",\n  \"first_seen\": \"2026-11-01T00:00:00Z\",\n  \"id\": \"ccc000000003\",\n" +
			"  \"last_seen\": \"2026-11-25T11:00:00Z\",\n  \"layer\": \"host\",\n  \"needs_human\": false,\n  \"remediation\": \"\",\n" +
			"  \"reopened_count\": 0,\n  \"severity\": \"medium\",\n  \"status\": \"open\",\n  \"title\": \"vuln.cve-1 title\"\n }\n]\n"},
		{[]string{"findings", "--open", "--severity", "high"}, "ID           SEVERITY  STATUS   DUE         LAYER        ASSET                                 WHAT\n" +
			"aaa000000001 critical  open     OVERDUE     host         host:secret-aaa                       ssh.password_auth_enabled title\n" +
			"aab000000002 high      open     2026-12-01  host         host:secret-aab                       conformance.other title\n" +
			"\n2 finding(s). Details and how to fix: sp explain <ID>\n"},
	}
	for _, tc := range tests {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			t.Parallel()
			r := sp(t, nil, append(tc.args, D...)...)
			if r.code != 0 || r.stdout != tc.want {
				t.Fatalf("code %d stderr %q stdout:\n%s\nwant:\n%s", r.code, r.stderr, r.stdout, tc.want)
			}
		})
	}
}

func TestStatus(t *testing.T) {
	t.Parallel()
	d := fixture(t)
	r := sp(t, map[string]string{"SP_DATA": d}, "status")
	for _, line := range []string{"security-platform status - unit\n", "Open findings: critical 1, high 1, medium 1\n",
		"Overdue fixes: 1 (past", "Without an owner: 1 ", "Fixed in the last 7 days: 1\n",
		"  ok  host                 last good run 2h ago\n",
		"  LATE    late                 slot 2026-11-25 11:20 not run yet (40m late); last good run 50m ago\n",
		"  never   never\n", "Top risks (sp explain <id>):\n  aaa000000001  critical This server lets people log in over SSH with a password.\n"} {
		if !strings.Contains(r.stdout, line) {
			t.Errorf("status lacks %q:\n%s", line, r.stdout)
		}
	}
	empty := filepath.Join(t.TempDir(), "empty")
	writeFile(t, filepath.Join(empty, "instance.yaml"), "name: fresh\n")
	if r := sp(t, nil, "status", "--data", empty); r.code != 0 || r.stdout != "security-platform status - fresh\n  no scan yet: run `sp run`\n" {
		t.Errorf("before a scan: %+v", r)
	}
}

func TestExplain(t *testing.T) {
	t.Parallel()
	d := fixture(t)
	tests := []struct {
		id, wantOut, wantErr string
		code                 int
	}{
		{"aaa0", "id aaa000000001   check ssh.password_auth_enabled   critical (fix today", "", 0},
		{"aab000000002", "expires: '2027-02-23'", "", 0},
		{"a", "", "sp: a matches 2 findings: aaa000000001, aab000000002 (give more of the id)\n", 2},
		{"fff", "", "sp: no finding fff (list them with `sp findings`)\n", 2},
		{"", "", "sp: no finding  (list them with `sp findings`)\n", 2},
	}
	for _, tc := range tests {
		t.Run(tc.id, func(t *testing.T) {
			t.Parallel()
			r := sp(t, nil, "explain", tc.id, "--data", d)
			if r.code != tc.code || !strings.Contains(r.stdout, tc.wantOut) || r.stderr != tc.wantErr {
				t.Fatalf("explain %q: %+v", tc.id, r)
			}
		})
	}
	r := sp(t, nil, "explain", "ccc", "--data", d)
	for _, s := range []string{"What it means\n  A known vulnerability", "How to verify\n  The next scheduled scan",
		"OVERDUE", "owner:"} {
		if strings.Contains(r.stdout, s) != (s != "OVERDUE" && s != "owner:") {
			t.Errorf("explain ccc and %q:\n%s", s, r.stdout)
		}
	}
}

func TestDigestIsAggregatesOnly(t *testing.T) {
	t.Parallel()
	d := fixture(t)
	r := sp(t, nil, "digest", "--daily", "--data", d)
	want := "Security 2026-11-25 (unit)\nOpen: 1 critical, 1 high, 1 medium\ntoday: 1 new, 1 fixed\nOverdue fixes: 1\n" +
		"New and serious:\n- critical: This server lets people log in over SSH with a password.  [sp explain aaa000000001]\n"
	if r.code != 0 || r.stdout != want {
		t.Fatalf("digest:\n%s\nwant:\n%s", r.stdout, want)
	}
	if r := sp(t, nil, "digest", "--days", "30", "--data", d); strings.Contains(r.stdout, "secret-") ||
		!strings.Contains(r.stdout, "last 30 days: 3 new") {
		t.Fatalf("30 days: %s", r.stdout)
	}
}

func TestUsageErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		args    []string
		vars    map[string]string
		code    int
		stderr  string
		hasHelp bool
	}{
		{nil, nil, 2, "sp: error: the following arguments are required: cmd\n", false},
		{[]string{"nope"}, nil, 2, "sp: error: argument cmd: invalid choice: 'nope' (choose from init, doctor", false},
		{[]string{"--bogus"}, nil, 2, "sp: error: unrecognized arguments: --bogus\n", false},
		{[]string{"findings", "--bogus"}, nil, 2, "usage: sp [-h] [--version]\n", false},
		{[]string{"findings", "--days", "1"}, nil, 2, "sp: error: unrecognized arguments: --days", false},
		{[]string{"digest", "--days", "x"}, nil, 2, "sp digest: error: argument --days: invalid int value: 'x'\n", false},
		{[]string{"status"}, nil, 2, "sp: where is your data directory?", false},
		{[]string{"status", "--data", "/nonexistent/x"}, nil, 2, "sp: /nonexistent/x does not exist (create it with `sp init /nonexistent/x`)\n", false},
		{[]string{"--help"}, nil, 0, "", true},
		{[]string{"--he"}, nil, 0, "", true},
		{[]string{"findings", "-h"}, nil, 0, "", true},
	}
	for _, tc := range tests {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			t.Parallel()
			r := sp(t, tc.vars, tc.args...)
			if r.code != tc.code || !strings.Contains(r.stderr, tc.stderr) || strings.Contains(r.stdout, "usage:") != tc.hasHelp {
				t.Fatalf("%q: %+v", tc.args, r)
			}
		})
	}
}

// TestBadInputIsOneLine: CLI-D2, unreadable input is one `sp:` line naming the file, exit 2.
func TestBadInputIsOneLine(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, file, content, cmd, want string
	}{
		{"yaml", "instance.yaml", "name: [x\n", "status", "instance.yaml: not a valid YAML or JSON document"},
		{"list", "instance.json", "[1]", "doctor", "instance.json: the instance config must be a mapping, not a list"},
		{"ledger", "ledger.json", "{", "findings", "ledger.json: not valid JSON"},
		{"ledger root", "ledger.json", "[]", "findings", "ledger.json: not a ledger"},
		{"entry", "ledger.json", `{"entries": {"a": 1}}`, "findings", "ledger.json: entry a is not an object"},
		{"tracker", "tracker/items.json", "7", "findings", "items.json: not a tracker document"},
		{"too big", "instance.yaml", "name: " + strings.Repeat("x", maxInstance), "status", "larger than"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d := t.TempDir()
			if tc.file != "instance.yaml" && tc.file != "instance.json" {
				writeFile(t, filepath.Join(d, "instance.json"), "{}")
			}
			writeFile(t, filepath.Join(d, filepath.FromSlash(tc.file)), tc.content)
			r := sp(t, nil, tc.cmd, "--data", d)
			if r.code != 2 || !strings.HasPrefix(r.stderr, "sp: ") || !strings.Contains(r.stderr, tc.want) ||
				strings.Count(r.stderr, "\n") != 1 {
				t.Fatalf("%+v, want one line containing %q", r, tc.want)
			}
		})
	}
}

func TestInit(t *testing.T) {
	t.Parallel()
	d := filepath.Join(t.TempDir(), "new", "lab")
	r := sp(t, map[string]string{"HOME": t.TempDir()}, "init", d)
	if r.code != 0 || !strings.HasPrefix(r.stdout, "wrote "+filepath.Join(d, "instance.yaml")+"\n\nNext:\n") {
		t.Fatalf("init: %+v", r)
	}
	inst, err := os.ReadFile(filepath.Join(d, "instance.yaml")) // #nosec G304 -- test file
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"\nname: lab\n", "  - {name: lab-1, exec: {type: local}, profile: linux}\n"} {
		if !strings.Contains(string(inst), s) {
			t.Errorf("starter lacks %q", s)
		}
	}
	assertPrivate(t, d)
}

// assertPrivate: sp init made the directory 0700 and every file 0600.
func assertPrivate(t *testing.T, d string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	for name, want := range map[string]os.FileMode{"": 0o700, "instance.yaml": 0o600, "exceptions.yaml": 0o600, ".gitignore": 0o600} {
		if fi, err := os.Stat(filepath.Join(d, name)); err != nil || fi.Mode().Perm() != want {
			t.Errorf("%s: %v, want mode %v", name, err, want)
		}
	}
}

func TestInitKeepsOrForces(t *testing.T) {
	t.Parallel()
	d := t.TempDir()
	writeFile(t, filepath.Join(d, "instance.yaml"), "name: mine\n")
	if r := sp(t, nil, "init", d); !strings.HasSuffix(strings.SplitN(r.stdout, "\n", 2)[0], "exists: left as it is (--force overwrites)") {
		t.Fatalf("second init: %+v", r)
	}
	if b, _ := os.ReadFile(filepath.Join(d, "instance.yaml")); string(b) != "name: mine\n" { // #nosec G304 -- test file
		t.Fatalf("instance.yaml overwritten without --force: %q", b)
	}
	if r := sp(t, nil, "init", d, "--force", "--name", "it's: odd"); r.code != 0 {
		t.Fatalf("--force: %+v", r)
	}
	if b, _ := os.ReadFile(filepath.Join(d, "instance.yaml")); !strings.Contains(string(b), "\nname: 'it''s: odd'\n") { // #nosec G304 -- test file
		t.Fatalf("a name that is not plain YAML is quoted: %q", b)
	}
	file := filepath.Join(t.TempDir(), "file")
	writeFile(t, file, "x")
	if r := sp(t, nil, "init", file); r.code != 2 || !strings.Contains(r.stderr, "exists and is not a directory") {
		t.Fatalf("init onto a file: %+v", r)
	}
}

func TestInitDoesNotFollowSymlinks(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need privileges on Windows")
	}
	d, target := t.TempDir(), filepath.Join(t.TempDir(), "elsewhere")
	writeFile(t, target, "precious\n")
	if err := os.Symlink(target, filepath.Join(d, "instance.yaml")); err != nil {
		t.Fatal(err)
	}
	if r := sp(t, nil, "init", d, "--force"); r.code != 0 {
		t.Fatalf("%+v", r)
	}
	if b, _ := os.ReadFile(target); string(b) != "precious\n" { // #nosec G304 -- test file
		t.Fatal("init --force wrote through a symbolic link")
	}
}

func TestDoctor(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("file modes")
	}
	d := t.TempDir()
	tree := t.TempDir()
	writeFile(t, filepath.Join(tree, "collectors", "host", "collector.py"), "")
	canary := "unit-secret-canary-91"
	writeFile(t, filepath.Join(d, "tok"), canary)
	if err := os.Chmod(filepath.Join(d, "tok"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d, 0o750); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(d, "instance.yaml"), "name: doc\nrunner:\n  jobs:\n    host: {}\n    k8s: {}\n    x: {collector: ../../etc}\n"+
		"notify:\n  - {type: telegram, token_file: "+filepath.Join(d, "tok")+"}\n")
	env := testEnv(map[string]string{"PATH": t.TempDir()}, nil, nil)
	env.Tree = tree
	env.Python = func() (string, error) { return "/usr/bin/python3", nil }
	env.Probe = func(context.Context, []string) (int, error) { return 1, nil } // no PyYAML
	r := run(t, env, "doctor", "--data", d)
	for _, s := range []string{"  FIX   data directory is readable by others (mode 0o750)\n", "  FIX   job k8s: unknown collector k8s\n",
		"  FIX   job x: unknown collector ../../etc\n", "is readable by others\n        -> chmod 600 ",
		"  FIX   PyYAML is missing (needed for a YAML config)\n", "\n5 thing(s) to fix\n"} {
		if !strings.Contains(r.stdout, s) {
			t.Errorf("doctor lacks %q:\n%s", s, r.stdout)
		}
	}
	if r.code != 1 || strings.Contains(r.stdout+r.stderr, canary) {
		t.Fatalf("code %d, or a secret was printed", r.code)
	}
}

func TestRun(t *testing.T) {
	t.Parallel()
	d := fixture(t)
	var argv []string
	env := testEnv(nil, nil, nil)
	env.Tree = filepath.FromSlash("/tree")
	env.Python = func() (string, error) { return "/py", nil }
	env.Exec = func(_ context.Context, a []string, _, _ io.Writer) (int, error) {
		argv = a
		now := float64(testNow.Unix())
		writeFile(t, filepath.Join(d, "state", "runner", "host.json"), map[string]any{"runs_total": 3, "last_rc": 0,
			"last_success": now, "last_duration": 2.5})
		writeFile(t, filepath.Join(d, "state", "runner", "never.json"), map[string]any{"runs_total": 1, "last_rc": 3,
			"last_note": "collector exited rc=3", "last_duration": 3.5})
		return 3, nil
	}
	r := run(t, env, "run", "--data", d)
	wantArgv := []string{"/py", filepath.Join(env.Tree, "runner", "runner.py"), "run", "host", "never", "late", "--instance",
		filepath.Join(d, "instance.json"), "--data", d}
	if strings.Join(argv, "|") != strings.Join(wantArgv, "|") {
		t.Errorf("runner argv %q, want %q", argv, wantArgv)
	}
	want := "running 3 job(s): host, never, late  (each job's log: " + d + "/runs/<date>/)\n" +
		"  ok  host                      2s  \n  FAILED  never                     4s  collector exited rc=3\n" +
		"  FAILED  late                      0s  \nnext: sp status   |   sp findings --open --severity high\n"
	if r.code != 3 || r.stdout != want {
		t.Fatalf("code %d stdout:\n%q\nwant:\n%q", r.code, r.stdout, want)
	}
	if r := run(t, env, "run", "nope", "--data", d); r.code != 2 ||
		r.stderr != "sp: not in runner.jobs: nope (configured: host, late, never)\n" {
		t.Fatalf("unknown job: %+v", r)
	}
}

func TestLateSlotAndJitter(t *testing.T) {
	t.Parallel()
	// the runner's reference offsets (internal/runner/testdata/reference.json)
	for _, c := range []struct {
		job          string
		slot, jitter int64
		want         int64
	}{{"job-0", 1714493580, 3600, 727}, {"job-1", 1941466500, 86400, 67320}, {"x", 1, 0, 0}} {
		if got := jitterOffset(c.job, c.slot, c.jitter); got != c.want {
			t.Errorf("jitterOffset(%s) = %d, want %d", c.job, got, c.want)
		}
	}
	if got := ago(1000, 1000+3*86400+5); got != "3d ago" || ago(10, 9) != "just now" || ago(0, 119) != "1m ago" {
		t.Errorf("ago: %s", got)
	}
}

func TestTextHelpers(t *testing.T) {
	t.Parallel()
	if head("é日本x", 2) != "é日" || head("ab", 5) != "ab" || ljust("é", 3) != "é  " || rjust("7", 3) != "  7" {
		t.Error("code-point slicing and padding")
	}
	for in, want := range map[string]float64{"2026-11-01T08:00:00Z": 1793520000, "2026-11-01": 1793491200,
		"2026-11-01T08:00:00.123+02:00": 1793520000} {
		if got, err := ts(in); err != nil || got != want {
			t.Errorf("ts(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []any{"", "2026-13-01", "yesterday", nil, 7} {
		if _, err := ts(bad); err == nil {
			t.Errorf("ts(%v) accepted", bad)
		}
	}
	if expandUser("~/x", func(string) string { return "/h" }) != "/h/x" || expandUser("~x", func(string) string { return "/h" }) != "~x" {
		t.Error("expandUser")
	}
}

// FuzzDataFiles: whatever the ledger, tracker and instance hold, the commands that read them never panic and end
// with exit 0, 1 or 2.
func FuzzDataFiles(f *testing.F) {
	f.Add([]byte(`{"entries": {"a": {"id": "a", "severity": "high", "status": "open", "first_seen": "2026-11-01"}}}`),
		[]byte(`{"items": [{"id": "a", "overdue": true}]}`), []byte("name: x\nrunner: {jobs: {a: {schedule: '* * * * *'}}}\n"))
	f.Add([]byte(`{"entries": {"b": {"severity": 7, "fixed_at": "x", "status": "fixed"}}, "sli": {"s": 1}}`),
		[]byte(`[1, {"id": null}]`), []byte("notify: {type: stdout}\nrunner: {jobs: [1]}\n"))
	f.Fuzz(func(t *testing.T, ledger, items, instance []byte) {
		d := t.TempDir()
		writeFile(t, filepath.Join(d, "ledger.json"), string(ledger))
		writeFile(t, filepath.Join(d, "tracker", "items.json"), string(items))
		writeFile(t, filepath.Join(d, "instance.yaml"), string(instance))
		for _, args := range [][]string{{"status"}, {"findings"}, {"findings", "--json", "--overdue"}, {"explain", "a"},
			{"digest", "--days", "9"}, {"doctor"}, {"notify", "--dry-run"}} {
			r := sp(t, nil, append(args, "--data", d)...)
			if r.code < 0 || r.code > 2 {
				t.Fatalf("%v: exit %d", args, r.code)
			}
		}
	})
}

func FuzzTS(f *testing.F) {
	for _, s := range []string{"2026-11-01T08:00:00Z", "2026-11-01", "T", "9999-99-99T99:99:99", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if v, err := ts(s); err == nil && (math.IsNaN(v) || len(s) < 10) {
			t.Fatalf("ts(%q) = %v", s, v)
		}
	})
}
