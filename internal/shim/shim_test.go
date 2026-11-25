package shim

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/MIERAI/security-platform/internal/buildinfo"
	"github.com/MIERAI/security-platform/internal/delegate"
	"github.com/MIERAI/security-platform/internal/fakepython"
)

func TestMain(m *testing.M) {
	fakepython.Run()
	os.Exit(m.Run())
}

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

// fakeTree is an installed Python tree with a RELEASE file and a few components.
func fakeTree(t *testing.T, rel string) string {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "cli", "sp.py"), "# not run: the fake interpreter ignores it\n")
	writeFile(t, filepath.Join(dir, "cli", "VERSION"), "0.3.0\n")
	writeFile(t, filepath.Join(dir, "core", "VERSION"), "0.9.0\n")
	writeFile(t, filepath.Join(dir, "collectors", "host", "VERSION"), "0.3.0\n")
	if rel != "" {
		writeFile(t, filepath.Join(dir, "RELEASE"), rel)
	}
	return dir
}

type result struct {
	code           int
	stdout, stderr string
}

func run(t *testing.T, vars map[string]string, stdin string, args ...string) result {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	all := map[string]string{delegate.EnvPython: exe}
	for k, v := range vars {
		all[k] = v
	}
	var out, errOut bytes.Buffer
	env := Env{Args: args, Stdin: strings.NewReader(stdin), Stdout: &out, Stderr: &errOut,
		Getenv: func(k string) string { return all[k] }, Environ: fakepython.Environ(t.TempDir()),
		Build: buildinfo.Info{Release: "v0.4.0", GoVersion: "go1.27.4", Platform: "linux/amd64"},
		Exec:  delegate.Child}
	code := Main(t.Context(), env)
	return result{code, out.String(), errOut.String()}
}

func TestDelegatesArgvVerbatim(t *testing.T) {
	t.Parallel()
	tree := fakeTree(t, "")
	vars := map[string]string{"SP_PY_HOME": tree}
	script := filepath.Join(tree, "cli", "sp.py")
	for _, args := range [][]string{
		{"argv"},
		{"argv", "--data", "/d", "findings", "--open", "a b", "$(id)", ""},
		{"argv", "--help"},
		{"argv", "version"}, // "version" is only a Go subcommand in first position
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			r := run(t, vars, "", args...)
			var want strings.Builder
			for _, a := range append([]string{script}, args...) {
				want.WriteString(strconv.Quote(a) + "\n")
			}
			if r.code != 0 || r.stdout != want.String() {
				t.Fatalf("code %d stdout:\n%s\nwant:\n%s\nstderr: %s", r.code, r.stdout, want.String(), r.stderr)
			}
		})
	}
}

func TestExitCodeAndStreamsPassthrough(t *testing.T) {
	t.Parallel()
	vars := map[string]string{"SP_PY_HOME": fakeTree(t, "")}
	for _, code := range []int{0, 1, 2, 3, 127, 255} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			t.Parallel()
			r := run(t, vars, "", "exit", strconv.Itoa(code))
			if r.code != code || r.stdout != "out" || r.stderr != "err" {
				t.Fatalf("got %+v, want code %d with out/err", r, code)
			}
		})
	}
	if r := run(t, vars, "piped\x00data\n", "stdin"); r.code != 0 || r.stdout != "piped\x00data\n" {
		t.Fatalf("stdin passthrough: %+v", r)
	}
}

func TestDelegationFailures(t *testing.T) {
	t.Parallel()
	tree := fakeTree(t, "")
	tests := []struct {
		name     string
		vars     map[string]string
		exec     func(context.Context, delegate.Spec) (int, error)
		wantCode int
		wantErr  string
	}{
		{"no python tree", map[string]string{"HOME": t.TempDir()}, nil, ExitNotFound, "SP_PY_HOME"},
		{"wrong SP_PY_HOME", map[string]string{"SP_PY_HOME": t.TempDir()}, nil, ExitNotFound, "cli/sp.py"},
		{"no interpreter", map[string]string{"SP_PY_HOME": tree, delegate.EnvPython: "no-such-python-xyz"}, nil,
			ExitNotFound, "SP_PYTHON"},
		{"exec fails", map[string]string{"SP_PY_HOME": tree}, func(context.Context, delegate.Spec) (int, error) {
			return 0, errors.New("exec format error")
		}, ExitCannotRun, "exec format error"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var errOut bytes.Buffer
			env := Env{Args: []string{"status"}, Stdin: strings.NewReader(""), Stdout: &bytes.Buffer{},
				Stderr: &errOut, Getenv: func(k string) string { return tc.vars[k] }, Exec: tc.exec}
			if code := Main(t.Context(), env); code != tc.wantCode || !strings.Contains(errOut.String(), tc.wantErr) {
				t.Fatalf("code %d stderr %q; want %d containing %q", code, errOut.String(), tc.wantCode, tc.wantErr)
			}
		})
	}
}

func TestVersionText(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, release string
		args          []string
		wantLines     []string
	}{
		{"--version, installed tree", "version=v0.4.0\ncommit=abc\n", []string{"--version"},
			[]string{"sp 0.3.0 (security-platform v0.4.0)", "binary: v0.4.0, go1.27.4, linux/amd64",
				"go subcommands: cloud version", "go components: (none)", "python components: cli collectors/host core"}},
		{"version subcommand", "version=v0.4.0\n", []string{"version"}, []string{"sp 0.3.0 (security-platform v0.4.0)"}},
		{"mismatch is flagged", "version=v0.3.0\n", []string{"--version"},
			[]string{"warning: the sp binary is v0.4.0 but the Python tree is v0.3.0"}},
		{"hostile release file", "version=v1\x1b]0;owned\x07\n", []string{"--version"},
			[]string{`sp 0.3.0 (security-platform "v1\x1b]0;owned\a")`}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := run(t, map[string]string{"SP_PY_HOME": fakeTree(t, tc.release)}, "", tc.args...)
			if r.code != 0 {
				t.Fatalf("code %d, stderr %s", r.code, r.stderr)
			}
			for _, line := range tc.wantLines {
				if !strings.Contains(r.stdout, line+"\n") {
					t.Errorf("missing line %q in:\n%s", line, r.stdout)
				}
			}
			if strings.Contains(r.stdout, "\x1b") {
				t.Errorf("escape sequence reached the terminal: %q", r.stdout)
			}
		})
	}
}

func TestVersionJSON(t *testing.T) {
	t.Parallel()
	r := run(t, map[string]string{"SP_PY_HOME": fakeTree(t, "version=v0.4.0\n")}, "", "version", "--json")
	rep := decodeReport(t, r)
	py := rep.Python
	if rep.Schema != VersionSchema || rep.Release != "v0.4.0" || rep.ReleaseMismatch || py == nil ||
		py.CLIVersion != "0.3.0" || py.Source != "env" || len(rep.Components) != 3 ||
		rep.Components[0].Implementation != "python" || !slices.Contains(rep.GoSubcommands, "version") {
		t.Fatalf("unexpected report %+v", rep)
	}
}

func TestVersionJSONWithoutTree(t *testing.T) {
	t.Parallel()
	rep := decodeReport(t, run(t, map[string]string{"HOME": t.TempDir()}, "", "version", "--json"))
	if rep.Python != nil || rep.PythonError == "" || rep.Release != "v0.4.0" || rep.Components == nil {
		t.Fatalf("without a tree: %+v", rep)
	}
}

func decodeReport(t *testing.T, r result) Report {
	t.Helper()
	var rep Report
	if err := json.Unmarshal([]byte(r.stdout), &rep); err != nil || r.code != 0 {
		t.Fatalf("code %d, %v:\n%s", r.code, err, r.stdout)
	}
	return rep
}

func TestVersionUsage(t *testing.T) {
	t.Parallel()
	vars := map[string]string{"SP_PY_HOME": fakeTree(t, "")}
	for _, tc := range []struct {
		args []string
		want int
	}{
		{[]string{"version", "--bogus"}, ExitUsage},
		{[]string{"version", "extra"}, ExitUsage},
		{[]string{"version", "-h"}, ExitOK},
	} {
		if r := run(t, vars, "", tc.args...); r.code != tc.want {
			t.Errorf("%v: code %d, want %d (stderr %q)", tc.args, r.code, tc.want, r.stderr)
		}
	}
}
