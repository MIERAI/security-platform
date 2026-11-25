package parity

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/MIERAI/security-platform/internal/collectors/collkit"
	"github.com/MIERAI/security-platform/internal/collectors/host"
	"github.com/MIERAI/security-platform/internal/collectors/hostsbom"
	"github.com/MIERAI/security-platform/internal/collectors/secretsfiles"
)

// TestConformanceOutputsMatchReference replays every conformance case of the exec-adapter collectors that has no
// deviation (conformance/cases/collector-{host,host-sbom,secrets-files}) with the Go collector in this process,
// and compares every file it writes (document, metrics, evidence, inventories, and what the fake targets saw:
// argument vectors and scripts) with what the Python reference wrote for the same step (testdata/<component>/
// <case>/<step>), after normalisation: sandbox path, interpreter path, wall-clock times; for secrets-files, the
// staged files' mtime/uid and the order of the scan's directory walk (file-system dependent). The conformance suite
// checks the contract's subsets; this test pins the whole files.
//
// Regenerate the reference outputs (needs SP_PYTHON with PyYAML, and python3 on PATH for the local scans):
//
//	SP_UPDATE_GOLDEN=1 SP_PYTHON=python3 go test -run TestConformanceOutputsMatchReference ./internal/collectors/parity
//
// Not parallel: the cases write executables (the fake targets), and a program file being written while another
// goroutine forks cannot be executed ("text file busy").
func TestConformanceOutputsMatchReference(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake exec targets are POSIX sh scripts")
	}
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, comp := range []string{"collector-host", "collector-host-sbom", "collector-secrets-files"} {
		cases, err := filepath.Glob(filepath.Join(root, "conformance", "cases", comp, "*", "case.json"))
		if err != nil || len(cases) == 0 {
			t.Fatalf("%s: no cases: %v", comp, err)
		}
		for _, p := range cases {
			t.Run(comp+"/"+filepath.Base(filepath.Dir(p)), func(t *testing.T) {
				replay(t, root, comp, p)
			})
		}
	}
}

type confCase struct {
	Deviation string                     `json:"deviation"`
	Files     map[string]json.RawMessage `json:"files"`
	Steps     []struct {
		Remove []string `json:"remove"`
		Exec   struct {
			Env map[string]string `json:"env"`
		} `json:"exec"`
	} `json:"steps"`
}

func replay(t *testing.T, root, comp, casePath string) {
	t.Helper()
	c, sb := load(t, casePath)
	sb.stage(t, c.Files)
	golden := filepath.Join("testdata", comp, filepath.Base(sb.caseDir))
	for i, st := range c.Steps {
		for _, r := range st.Remove {
			if err := os.RemoveAll(filepath.Join(sb.dir, filepath.FromSlash(r))); err != nil {
				t.Fatal(err)
			}
		}
		env := map[string]string{"TZ": "UTC", "LC_ALL": "C", "HOME": filepath.Join(sb.dir, "home")}
		for k, v := range st.Exec.Env {
			env[k] = sb.render(v)
		}
		if err := os.MkdirAll(env["HOME"], 0o700); err != nil {
			t.Fatal(err)
		}
		code := run(t, root, comp, env)
		got := sb.outputs(t, comp)
		got["exit"] = strconv.Itoa(code)
		check(t, filepath.Join(golden, strconv.Itoa(i)), got)
	}
}

// load reads a case (skipping deviation cases: the reference has no output for them) and prepares its sandbox.
func load(t *testing.T, casePath string) (confCase, *sandbox) {
	t.Helper()
	data, err := os.ReadFile(casePath) // #nosec G304 -- a case file of this repository
	if err != nil {
		t.Fatal(err)
	}
	var c confCase
	if uerr := json.Unmarshal(data, &c); uerr != nil {
		t.Fatal(uerr)
	}
	if c.Deviation != "" {
		t.Skip("specifies a target behaviour the reference does not have (" + c.Deviation + ")")
	}
	python := ""
	if bytes.Contains(data, []byte("{python}")) {
		if python, err = exec.LookPath("python3"); err != nil {
			t.Skip("the case scans with the local python3, which is not installed")
		}
	}
	return c, &sandbox{dir: t.TempDir(), caseDir: filepath.Dir(casePath), python: python, epochs: map[string]string{}}
}

func run(t *testing.T, root, comp string, env map[string]string) int {
	t.Helper()
	environ := make([]string, 0, len(env))
	for k, v := range env {
		environ = append(environ, k+"="+v)
	}
	sort.Strings(environ)
	if os.Getenv("SP_UPDATE_GOLDEN") != "" {
		cmd := exec.Command(os.Getenv("SP_PYTHON"), filepath.Join(root, "collectors", strings.TrimPrefix(comp, "collector-"), "collector.py"))
		cmd.Env = environ
		if err := cmd.Run(); err != nil {
			if ee, ok := err.(*exec.ExitError); ok { //nolint:errorlint // exec returns it unwrapped
				return ee.ExitCode()
			}
			t.Fatal(err)
		}
		return 0
	}
	mains := map[string]func(context.Context, collkit.Env) int{"collector-host": host.Main,
		"collector-host-sbom": hostsbom.Main, "collector-secrets-files": secretsfiles.Main}
	return mains[comp](context.Background(), collkit.Env{Getenv: func(k string) string { return env[k] }, Environ: environ,
		Stderr: io.Discard, Now: time.Now})
}

// sandbox is one case's directory with the harness's staging rules (conformance/run.py Sandbox.stage).
type sandbox struct {
	dir, caseDir, python string
	epochs               map[string]string // rendered {epoch:N} value -> its template (normalised back)
}

var epochRe = regexp.MustCompile(`\{epoch:([+-]?\d+)\}`)

func (s *sandbox) render(v string) string {
	v = strings.ReplaceAll(strings.ReplaceAll(v, "{sandbox}", s.dir), "{python}", s.python)
	return epochRe.ReplaceAllStringFunc(v, func(m string) string {
		off, err := strconv.ParseInt(epochRe.FindStringSubmatch(m)[1], 10, 64)
		if err != nil {
			return m
		}
		v := strconv.FormatInt(time.Now().Unix()+off, 10)
		s.epochs[v] = m
		return v
	})
}

func (s *sandbox) stage(t *testing.T, files map[string]json.RawMessage) {
	t.Helper()
	for dst, raw := range files {
		var spec struct {
			Text *string         `json:"text"`
			JSON json.RawMessage `json:"json"`
			Raw  string          `json:"raw"`
			Mode string          `json:"mode"`
		}
		var src string
		var content []byte
		switch {
		case json.Unmarshal(raw, &src) == nil:
			b, err := os.ReadFile(filepath.Join(s.caseDir, src)) // #nosec G304 -- a case fixture
			if err != nil {
				t.Fatal(err)
			}
			content = []byte(s.render(string(b)))
		case json.Unmarshal(raw, &spec) != nil:
			t.Fatalf("file spec %s", raw)
		case spec.Text != nil:
			content = []byte(s.render(*spec.Text))
		case spec.JSON != nil:
			content = []byte(s.render(string(spec.JSON)))
		case spec.Raw != "":
			b, err := os.ReadFile(filepath.Join(s.caseDir, spec.Raw)) // #nosec G304 -- a case fixture
			if err != nil {
				t.Fatal(err)
			}
			content = b
		}
		write(t, filepath.Join(s.dir, filepath.FromSlash(dst)), content, spec.Mode)
	}
}

func write(t *testing.T, path string, content []byte, mode string) {
	t.Helper()
	perm := os.FileMode(0o644)
	if mode != "" {
		m, err := strconv.ParseUint(mode, 8, 32)
		if err != nil {
			t.Fatal(err)
		}
		perm = os.FileMode(m)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, perm); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, perm); err != nil { // the umask must not change the fixture's mode
		t.Fatal(err)
	}
}

var (
	timesRe = regexp.MustCompile(`"(started_at|finished_at|observed_at|generated_at)": "[^"]*"`)
	beatRe  = regexp.MustCompile(`(security_collector_last_run_timestamp_seconds\{[^}]*\}) \d+`)
	statRe  = regexp.MustCompile(`"(mtime|uid)": \d+`)
)

// outputs are the files under run/ and trace/ ("/" in their paths written as "__"), normalised.
func (s *sandbox) outputs(t *testing.T, comp string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, top := range []string{"run", "trace"} {
		base := filepath.Join(s.dir, top)
		err := filepath.WalkDir(base, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			b, err := os.ReadFile(p) // #nosec G304 -- the sandbox's own files
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(s.dir, p)
			if err != nil {
				return err
			}
			out[strings.ReplaceAll(filepath.ToSlash(rel), "/", "__")] = s.normalise(string(b), comp, rel)
			return nil
		})
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	return out
}

func (s *sandbox) normalise(text, comp, rel string) string {
	for _, v := range []string{s.dir, evalSymlinks(s.dir)} {
		text = strings.ReplaceAll(text, v, "{sandbox}")
	}
	if s.python != "" {
		text = strings.ReplaceAll(text, s.python, "{python}")
	}
	for v, tmpl := range s.epochs {
		text = strings.ReplaceAll(text, v, tmpl)
	}
	text = beatRe.ReplaceAllString(timesRe.ReplaceAllString(text, `"$1": "T"`), "$1 T")
	if comp == "collector-secrets-files" && s.python != "" && strings.HasPrefix(filepath.ToSlash(rel), "run/") &&
		strings.HasSuffix(rel, ".json") {
		lines := strings.Split(statRe.ReplaceAllString(text, `"$1": N`), "\n")
		sort.Strings(lines) // a local scan lists files in the file system's directory order
		text = strings.Join(lines, "\n")
	}
	return text
}

func evalSymlinks(p string) string {
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		return p
	}
	return r
}

func check(t *testing.T, dir string, got map[string]string) {
	t.Helper()
	if os.Getenv("SP_UPDATE_GOLDEN") != "" {
		writeGolden(t, dir, got)
		return
	}
	want := readGolden(t, dir)
	for name, w := range want {
		if g, ok := got[name]; !ok {
			t.Errorf("%s: the Go collector did not write it", name)
		} else if g != w {
			t.Errorf("%s differs from the reference:\n%s", name, firstDifference(w, g))
		}
	}
	for name := range got {
		if _, ok := want[name]; !ok {
			t.Errorf("%s: written by the Go collector only", name)
		}
	}
}

func writeGolden(t *testing.T, dir string, got map[string]string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	for name, text := range got {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func readGolden(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("no reference outputs in %s (regenerate them, see the test's comment): %v", dir, err)
	}
	want := map[string]string{}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name())) // #nosec G304 -- testdata
		if err != nil {
			t.Fatal(err)
		}
		want[e.Name()] = string(b)
	}
	return want
}

func firstDifference(want, got string) string {
	w, g := strings.Split(want, "\n"), strings.Split(got, "\n")
	for i := range max(len(w), len(g)) {
		var a, b string
		if i < len(w) {
			a = w[i]
		}
		if i < len(g) {
			b = g[i]
		}
		if a != b {
			return "line " + strconv.Itoa(i+1) + ":\n  want " + a + "\n  got  " + b
		}
	}
	return "(same lines)"
}
