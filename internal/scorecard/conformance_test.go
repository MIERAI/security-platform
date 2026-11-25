package scorecard

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestConformanceOutputsMatchReference replays every scorecard conformance case (conformance/cases/scorecard)
// and compares every output file of every step, byte for byte, with what the reference implementation wrote for
// the same step (testdata/conformance, sandbox paths normalised). The conformance suite checks the contract's
// subsets; this test pins the whole files, on every system CI runs.
//
// Regenerate the reference outputs (needs SP_PYTHON with PyYAML):
//
//	SP_UPDATE_GOLDEN=1 SP_PYTHON=python3 go test -run TestConformanceOutputsMatchReference ./internal/scorecard
func TestConformanceOutputsMatchReference(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	cases, err := filepath.Glob(filepath.Join(root, "conformance", "cases", "scorecard", "*", "case.json"))
	if err != nil || len(cases) == 0 {
		t.Fatalf("no cases: %v", err)
	}
	for _, p := range cases {
		name := filepath.Base(filepath.Dir(p))
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			replay(t, root, p)
		})
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

type confCase struct {
	Deviation string                     `json:"deviation"`
	Files     map[string]json.RawMessage `json:"files"`
	Steps     []struct {
		Files  map[string]json.RawMessage `json:"files"`
		Remove []string                   `json:"remove"`
		Exec   struct {
			Args []string          `json:"args"`
			Env  map[string]string `json:"env"`
		} `json:"exec"`
	} `json:"steps"`
}

func replay(t *testing.T, root, casePath string) {
	t.Helper()
	var c confCase
	data, err := os.ReadFile(casePath)
	if err != nil || json.Unmarshal(data, &c) != nil {
		t.Fatalf("read %s: %v", casePath, err)
	}
	if c.Deviation != "" {
		t.Skip("specifies a target behaviour the reference does not have yet (" + c.Deviation + ")")
	}
	if runtime.GOOS == "windows" && strings.Contains(string(data), `"mode":`) { // a fixture with a file mode
		t.Skip("file modes and data paths in details are system-specific; the reference ran on Unix")
	}
	sandbox := t.TempDir()
	caseDir := filepath.Dir(casePath)
	stage(t, sandbox, caseDir, c.Files)
	golden := filepath.Join("testdata", "conformance", filepath.Base(caseDir))
	for i, st := range c.Steps {
		stage(t, sandbox, caseDir, st.Files)
		for _, r := range st.Remove {
			if err := os.RemoveAll(filepath.Join(sandbox, filepath.FromSlash(r))); err != nil {
				t.Fatal(err)
			}
		}
		args := make([]string, len(st.Exec.Args))
		for j, a := range st.Exec.Args {
			args[j] = strings.ReplaceAll(a, "{sandbox}", sandbox)
		}
		got := runStep(t, root, sandbox, args, st.Exec.Env)
		checkStep(t, filepath.Join(golden, strconv.Itoa(i)), sandbox, got)
	}
}

// stage writes the case's files into the sandbox: a case file (with {sandbox} filled in), {"text": ...} or
// {"json": ...}, with an optional {"mode": "0644"}.
func stage(t *testing.T, sandbox, caseDir string, files map[string]json.RawMessage) {
	t.Helper()
	for dst, raw := range files {
		var spec struct {
			Text *string         `json:"text"`
			JSON json.RawMessage `json:"json"`
			Mode string          `json:"mode"`
		}
		var src string
		var content []byte
		if json.Unmarshal(raw, &src) == nil {
			b, err := os.ReadFile(filepath.Join(caseDir, filepath.FromSlash(src)))
			if err != nil {
				t.Fatal(err)
			}
			content = b
		} else if err := json.Unmarshal(raw, &spec); err != nil {
			t.Fatal(err)
		}
		if spec.Text != nil {
			content = []byte(*spec.Text)
		}
		if spec.JSON != nil {
			content = spec.JSON
		}
		writeStaged(t, filepath.Join(sandbox, filepath.FromSlash(dst)), sandbox, content, spec.Mode)
	}
}

func writeStaged(t *testing.T, path, sandbox string, content []byte, mode string) {
	t.Helper()
	slashSandbox := filepath.ToSlash(sandbox) // templates go into YAML/JSON text: no backslashes to escape
	content = bytes.ReplaceAll(content, []byte("{sandbox}"), []byte(slashSandbox))
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

// stepOutputs are a step's exit status (0 or 1: success or not) and output files, sandbox paths normalised.
type stepOutputs map[string]string

func outputFiles() map[string]string {
	return map[string]string{"scorecard.json": "data/reports/scorecard.json", "scorecard.md": "data/reports/scorecard.md",
		"scorecard.prom": "data/metrics/scorecard.prom", "state.json": "data/state/scorecard.json"}
}

func runStep(t *testing.T, root, sandbox string, args []string, env map[string]string) stepOutputs {
	t.Helper()
	var ok bool
	if os.Getenv("SP_UPDATE_GOLDEN") != "" {
		ok = runReference(t, root, args, env)
	} else {
		env := Env{Stdout: io.Discard, Stderr: io.Discard, Product: root, Now: time.Now,
			GitLog: func(context.Context, string, string) string { return "" },
			Attest: func(context.Context, []string) int { return 1 }}
		ok = Main(context.Background(), env, args) == ExitOK
	}
	out := stepOutputs{"exit": "1"}
	if ok {
		out["exit"] = "0"
	}
	for name, rel := range outputFiles() {
		if b, err := os.ReadFile(filepath.Join(sandbox, filepath.FromSlash(rel))); err == nil {
			out[name] = normalise(string(b), sandbox)
		}
	}
	return out
}

func normalise(text, sandbox string) string {
	for _, s := range []string{sandbox, filepath.ToSlash(sandbox), strings.ReplaceAll(sandbox, `\`, `\\`)} {
		text = strings.ReplaceAll(text, s, "{sandbox}")
	}
	return text
}

func runReference(t *testing.T, root string, args []string, env map[string]string) bool {
	t.Helper()
	cmd := exec.Command(os.Getenv("SP_PYTHON"), append([]string{filepath.Join(root, "scorecard", "scorecard.py")}, args...)...)
	cmd.Env = append(os.Environ(), "TZ=UTC", "LC_ALL=C")
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	return cmd.Run() == nil
}

func checkStep(t *testing.T, dir, sandbox string, got stepOutputs) {
	t.Helper()
	if os.Getenv("SP_UPDATE_GOLDEN") != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
		for name, text := range got {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("no reference outputs in %s (regenerate them, see the test's comment): %v", dir, err)
	}
	for _, e := range entries {
		want, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		// a checkout may turn LF into CRLF (Windows): the outputs themselves never contain a carriage return
		if w := strings.ReplaceAll(string(want), "\r\n", "\n"); got[e.Name()] != w {
			t.Errorf("%s/%s differs from the reference:\n%s", dir, e.Name(), firstDifference(w, got[e.Name()]))
		}
	}
	if len(entries) != len(got) {
		t.Errorf("%s: %d outputs, the reference wrote %d (sandbox %s)", dir, len(got), len(entries), sandbox)
	}
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
	return "(same lines, different line ends)"
}
