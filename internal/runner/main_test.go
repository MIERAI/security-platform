//go:build unix

package runner

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

type mainResult struct {
	rc          int
	out, errOut string
}

func runMain(t *testing.T, args []string, environ ...string) mainResult {
	t.Helper()
	var out, errOut bytes.Buffer
	env := map[string]string{}
	for _, kv := range environ {
		k, v, _ := strings.Cut(kv, "=")
		env[k] = v
	}
	rc := Main(context.Background(), Env{Args: args, Stdout: &out, Stderr: &errOut, Getenv: func(k string) string { return env[k] },
		Environ: environ, Wall: time.Now})
	return mainResult{rc: rc, out: out.String(), errOut: errOut.String()}
}

func TestParseArgs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		args []string
		ok   bool
		cmd  string
		jobs string
	}{
		{[]string{"tick", "--instance", "i", "--data", "d", "--now", "1893987000", "a", "b"}, true, "tick", "a,b"},
		{[]string{"--data=d", "run", "--instance=i"}, true, "run", ""},
		{[]string{"tick", "--instance", "i", "--data", "d", "--", "--weird-job"}, true, "tick", "--weird-job"},
		{[]string{"status", "--instance", "i", "--data", "d"}, true, "status", ""},
		{[]string{"serve-metrics", "--dir", "x", "--port", "9999"}, true, "serve-metrics", ""},
		{[]string{"version"}, true, "version", ""},
		{[]string{"tick", "--instance", "i", "--data", "d", "--only", "a"}, false, "", ""}, // RUNNER-D3: no --only
		{[]string{"tick", "--data", "d"}, false, "", ""},
		{[]string{"status", "--instance", "i", "--data", "d", "a"}, false, "", ""},
		{[]string{"frobnicate"}, false, "", ""},
		{[]string{}, false, "", ""},
		{[]string{"tick", "--now", "soon", "--instance", "i", "--data", "d"}, false, "", ""},
		{[]string{"serve-metrics"}, false, "", ""},
		{[]string{"serve-metrics", "--dir", "x", "--port", "70000"}, false, "", ""},
		{[]string{"tick", "--instance"}, false, "", ""},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			t.Parallel()
			a, err := parseArgs(tt.args)
			if (err == nil) != tt.ok {
				t.Fatalf("err = %v, want ok=%v", err, tt.ok)
			}
			if tt.ok && (a.cmd != tt.cmd || strings.Join(a.jobs, ",") != tt.jobs) {
				t.Errorf("got %+v", a)
			}
		})
	}
}

func TestMainCommand(t *testing.T) {
	t.Parallel()
	f := newFixture(t, map[string]any{"jobs": map[string]any{"a": map[string]any{"type": "command",
		"argv": []string{"true"}, "schedule": "0 * * * *"}}})
	base := []string{"--instance", f.instance, "--data", f.data}
	path := "PATH=" + os.Getenv("PATH")
	tests := []struct {
		name   string
		args   []string
		rc     int
		stdout string
		stderr string
	}{
		{"version", []string{"version"}, 0, Version + "\n", ""},
		{"help", []string{"tick", "--help"}, 0, "usage: sp runner tick", ""},
		{"usage error", []string{"tick", "--only", "a"}, ExitUsage, "", "unknown option --only"},
		{"unknown job", append([]string{"tick", "nope"}, base...), ExitUsage, "", "not in runner.jobs: nope"},
		{"cannot start", []string{"tick", "--instance", filepath.Join(f.dir, "missing.json"), "--data", f.data},
			ExitNoConfig, "", "runner: cannot start: "},
		{"status", append([]string{"status", "--now", "1894019400"}, base...), 0, `"due": "due"`, ""},
		{"tick", append([]string{"tick", "--now", "1894019400"}, base...), 0, "", "a: rc=1 in 0s: collector exited rc=0, document=no"},
		{"run", append([]string{"run", "a"}, base...), 1, "", "a: start (command)"},
		{"metrics", append([]string{"metrics"}, base...), 0, "", ""},
	}
	for _, tt := range tests {
		res := runMain(t, tt.args, path, "HOME="+f.dir)
		if res.rc != tt.rc || !strings.Contains(res.out, tt.stdout) || !strings.Contains(res.errOut, tt.stderr) {
			t.Errorf("%s: %+v", tt.name, res)
		}
	}
	if _, err := os.Stat(filepath.Join(f.data, "metrics", "security-platform.prom")); err != nil {
		t.Errorf("metrics not published: %v", err)
	}
}

func TestLogLineFormat(t *testing.T) {
	t.Parallel()
	var b bytes.Buffer
	c := NewClock(1894019400, func() time.Time { return time.Unix(0, 0) })
	l := &Logger{w: &b, clock: c, loc: time.FixedZone("x", 3600)}
	l.Printf("job: line one\nforged line")
	want := "2030-01-07T13:30:00+0100 runner: \"job: line one\\nforged line\"\n"
	if b.String() != want {
		t.Errorf("log line %q, want %q", b.String(), want)
	}
}

func TestEnvFilter(t *testing.T) {
	t.Parallel()
	f := newEnvFilter([]string{"GH_TOKEN"})
	environ := []string{"PATH=/bin", "AWS_SECRET_ACCESS_KEY=s", "GH_TOKEN=t", "SP_PYTHON=p", "LC_ALL=C", "RANDOM_THING=x",
		"API_KEY=k", "noequals"}
	got := f.base(environ)
	if len(got) != 4 || got["GH_TOKEN"] != "t" || got["PATH"] != "/bin" || got["SP_PYTHON"] != "p" || got["LC_ALL"] != "C" {
		t.Errorf("base = %v", got)
	}
	if w := strings.Join(f.withheldCredentials(environ), ","); w != "API_KEY,AWS_SECRET_ACCESS_KEY" {
		t.Errorf("withheld = %s", w)
	}
}

func TestProgramChoice(t *testing.T) {
	t.Parallel()
	f := newFixture(t, map[string]any{"implementations": map[string]any{"ledger": "go", "scorecard": []string{"/opt/sc", "--x"},
		"digest": "rust", "export": "go"}})
	r := f.runner(t, 0)
	r.exe, r.python, r.tree = "/usr/local/bin/sp", "/usr/bin/python3", "/tree"
	tests := []struct {
		component, want string
		ok              bool
	}{
		{"ledger", "/usr/local/bin/sp ledger merge", true}, {"scorecard", "/opt/sc --x", true},
		{"remediation", "/usr/bin/python3 /tree/core/remediation.py", true},
		{"notify", "/usr/bin/python3 /tree/cli/sp.py notify", true},
		{"collectors/host", "/usr/bin/python3 /tree/collectors/host/collector.py", true},
		{"digest", "", false}, {"export", "", false}, {"nothing", "", false},
	}
	for _, tt := range tests {
		argv, err := r.program(tt.component)
		if (err == nil) != tt.ok || strings.Join(argv, " ") != tt.want {
			t.Errorf("program(%s) = %v, %v", tt.component, argv, err)
		}
	}
	r.tree = ""
	if _, err := r.program("remediation"); !errors.Is(err, errNoPython) {
		t.Errorf("no tree: %v", err)
	}
	if _, err := r.bridge(context.Background(), "job"); !errors.Is(err, errNoPython) {
		t.Errorf("bridge without a tree: %v", err)
	}
}

// TestVersionIsTheComponents: the Go runner reports the runner component's version (runner/VERSION).
func TestVersionIsTheComponents(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join(repoRoot(t), "runner", "VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(data)); got != Version {
		t.Errorf("runner/VERSION %s, Go runner %s", got, Version)
	}
}
