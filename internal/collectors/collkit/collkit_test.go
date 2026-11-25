package collkit

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MIERAI/security-platform/internal/pyvalue"
)

func instance(t *testing.T, yaml string) *pyvalue.Map {
	t.Helper()
	v, err := pyvalue.DecodeYAML([]byte(yaml))
	m, ok := v.(*pyvalue.Map)
	if err != nil || !ok {
		t.Fatal(err)
	}
	return m
}

func TestInScope(t *testing.T) {
	t.Parallel()
	inst := instance(t, "scope: [{names: [a, b], scope: [k8s]}, {names: [a], scope: [host]}, x, {names: [c], scope: [host]}]")
	tests := []struct {
		name, collector string
		want            bool
	}{
		{"a", "host", false}, // the first matching entry decides
		{"a", "k8s", true},
		{"c", "host", true},
		{"c", "k8s", false},
		{"z", "host", true}, // no entry: every collector
	}
	for _, tt := range tests {
		if got := InScope(inst, tt.name, tt.collector); got != tt.want {
			t.Errorf("InScope(%s, %s) = %v", tt.name, tt.collector, got)
		}
	}
}

func TestSafeFileName(t *testing.T) {
	t.Parallel()
	for s, want := range map[string]bool{"lab": true, "host-1.lan": true, "": false, ".": false, "..": false,
		"../x": false, `a\b`: false, "a\x00": false} {
		if got := SafeFileName(s); got != want {
			t.Errorf("SafeFileName(%q) = %v", s, got)
		}
	}
}

func TestTargets(t *testing.T) {
	t.Parallel()
	if _, err := Targets(instance(t, "hosts: x"), "hosts", "name"); !errors.Is(err, ErrConfig) {
		t.Errorf("hosts not a list: %v", err)
	}
	if _, err := Targets(instance(t, "hosts: [{profile: linux}]"), "hosts", "name"); !errors.Is(err, ErrConfig) {
		t.Errorf("host without name: %v", err)
	}
	if got, err := Targets(instance(t, "other: 1"), "hosts", "name"); err != nil || len(got) != 0 {
		t.Errorf("no hosts: %v %v", got, err)
	}
}

// TestMain: exit 2 for configuration errors, 1 for a failed run, 0 with the document written (private).
func TestMainExitStatus(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	inst := filepath.Join(dir, "instance.yaml")
	if err := os.WriteFile(inst, []byte("name: lab\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run := filepath.Join(dir, "run")
	tests := []struct {
		vars map[string]string
		body error
		want int
	}{
		{map[string]string{"SP_INSTANCE": inst}, nil, ExitUsage},
		{map[string]string{"SP_RUN_DIR": run}, nil, ExitUsage},
		{map[string]string{"SP_RUN_DIR": run, "SP_INSTANCE": filepath.Join(dir, "missing")}, nil, ExitUsage},
		{map[string]string{"SP_RUN_DIR": run, "SP_INSTANCE": inst}, errors.New("boom"), ExitFailed},
		{map[string]string{"SP_RUN_DIR": run, "SP_INSTANCE": inst, "SP_COLLECTOR_NAME": "x-b"}, nil, ExitOK},
	}
	for _, tt := range tests {
		var stderr bytes.Buffer
		env := Env{Getenv: func(k string) string { return tt.vars[k] }, Stderr: &stderr, Now: time.Now}
		got := Main(context.Background(), env, "x", "1.0.0", func(context.Context, *Run) error { return tt.body })
		if got != tt.want {
			t.Errorf("%v: exit %d, want %d (%s)", tt.vars, got, tt.want, stderr.String())
		}
	}
	st, err := os.Stat(filepath.Join(run, "x-b.findings.json"))
	if err != nil || st.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Errorf("document: %v %v", st, err)
	}
	if s := ExpandUser("~/x", "/h"); filepath.ToSlash(s) != "/h/x" || ExpandUser("~x", "/h") != "~x" {
		t.Errorf("ExpandUser: %s", s)
	}
	if r, ok := AsGap(errors.Join(errors.New("a"), Gap("why"))); !ok || r != "why" || !strings.Contains(Gap("w").Error(), "w") {
		t.Error("AsGap")
	}
}
