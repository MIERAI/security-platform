//go:build unix

package runner

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer is a log sink that tests read while nothing else writes.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// fixture is a sandbox: an instance file, a data directory and a log.
type fixture struct {
	dir, instance, data string
	log                 *syncBuffer
}

func newFixture(t *testing.T, runnerBlock map[string]any) *fixture {
	t.Helper()
	dir := t.TempDir()
	f := &fixture{dir: dir, instance: filepath.Join(dir, "instance.json"), data: filepath.Join(dir, "data"), log: &syncBuffer{}}
	inst := map[string]any{"name": "test", "scorecard": map[string]any{"enabled": false}, "runner": runnerBlock}
	writeTestJSON(t, f.instance, inst)
	return f
}

func writeTestJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// runner builds a Runner on the fixture with the clock at now (0 = wall clock).
func (f *fixture) runner(t *testing.T, now float64) *Runner {
	t.Helper()
	clock := NewClock(now, time.Now)
	tree := repoRoot(t)
	py, _ := exec.LookPath("python3") // absent: tests that need the bridge skip
	r, err := New(Options{Instance: f.instance, Data: f.data, Tree: tree, Python: py, Environ: []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + f.dir}, Clock: clock,
		Log: &Logger{w: f.log, clock: clock, loc: time.UTC}, Loc: time.UTC, Wall: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// script writes an executable shell script into the fixture and returns its path.
func (f *fixture) script(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(f.dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o700); err != nil { // #nosec G306 -- a test program
		t.Fatal(err)
	}
	return p
}

func epoch(t *testing.T, s string) float64 {
	t.Helper()
	v, err := time.Parse("2006-01-02T15:04:05Z", s)
	if err != nil {
		t.Fatal(err)
	}
	return float64(v.Unix())
}

func requirePython(t *testing.T, modules ...string) string {
	t.Helper()
	py := os.Getenv("SP_PYTHON")
	if py == "" {
		var err error
		if py, err = exec.LookPath("python3"); err != nil {
			t.Skip("python3 not found: the bridge to the Python implementation cannot run")
		}
	}
	check := "import sys; print(sys.version_info >= (3, 10))"
	for _, m := range modules {
		check = "import " + m + "; " + check
	}
	out, err := exec.Command(py, "-c", check).Output()
	if err != nil || strings.TrimSpace(string(out)) != "True" {
		t.Skipf("python3 >= 3.10 with %v not available (set SP_PYTHON)", modules)
	}
	return py
}
