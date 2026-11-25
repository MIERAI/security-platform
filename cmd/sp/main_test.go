package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/MIERAI/security-platform/internal/fakepython"
)

// These tests build the real sp binary and run it as a user would, so that the Unix execve path (which replaces
// the process and cannot run inside a test) is covered too.

func TestMain(m *testing.M) {
	fakepython.Run()
	os.Exit(m.Run())
}

func buildSP(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("builds the binary")
	}
	bin := filepath.Join(t.TempDir(), "sp")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	cmd := exec.Command("go", "build", "-trimpath", "-o", bin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

// repoRoot is the checkout this test runs in (cmd/sp/../..).
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

type outcome struct {
	code           int
	stdout, stderr string
}

func runBin(t *testing.T, bin string, env []string, stdin string, args ...string) outcome {
	t.Helper()
	cmd := exec.Command(bin, args...) // #nosec G204 -- test binary, argument vector
	cmd.Env = env
	cmd.Stdin = strings.NewReader(stdin)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	var exitErr *exec.ExitError
	code := 0
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("run %s: %v", bin, err)
	}
	return outcome{code, out.String(), errOut.String()}
}

func fakeEnv(t *testing.T) []string {
	t.Helper()
	tree := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tree, "cli"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree, "cli", "sp.py"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return append(fakepython.Environ(t.TempDir()), "SP_PY_HOME="+tree, "SP_PYTHON="+exe)
}

func TestBinaryPassthrough(t *testing.T) {
	t.Parallel()
	bin, env := buildSP(t), fakeEnv(t)
	for _, code := range []int{0, 1, 2, 42, 255} {
		if o := runBin(t, bin, env, "", "exit", strconv.Itoa(code)); o.code != code || o.stdout != "out" ||
			o.stderr != "err" {
			t.Errorf("exit %d: got %+v", code, o)
		}
	}
	if o := runBin(t, bin, env, "a\nb\n", "stdin"); o.code != 0 || o.stdout != "a\nb\n" {
		t.Errorf("stdin: %+v", o)
	}
	if o := runBin(t, bin, env, "", "argv", "a b", "--json", ""); !strings.HasSuffix(o.stdout, "\"a b\"\n\"--json\"\n\"\"\n") {
		t.Errorf("argv: %+v", o)
	}
	if runtime.GOOS != "windows" {
		if o := runBin(t, bin, env, "", "kill"); o.code != -1 {
			t.Errorf("a signal ends sp itself (exec replaced it): got %+v", o)
		}
	}
}

func TestBinaryVersionJSON(t *testing.T) {
	t.Parallel()
	bin := buildSP(t)
	o := runBin(t, bin, append(os.Environ(), "SP_PY_HOME="+repoRoot(t)), "", "version", "--json")
	var rep struct {
		Release    string `json:"release"`
		Components []struct {
			Name, Implementation string
		} `json:"components"`
		Python *struct {
			CLIVersion string `json:"cli_version"`
		} `json:"python"`
	}
	if err := json.Unmarshal([]byte(o.stdout), &rep); err != nil || o.code != 0 {
		t.Fatalf("code %d, %v:\n%s%s", o.code, err, o.stdout, o.stderr)
	}
	if rep.Python == nil || rep.Python.CLIVersion == "unknown" || len(rep.Components) < 5 || rep.Release == "" {
		t.Fatalf("report of this checkout: %s", o.stdout)
	}
}

// TestSameAsPython runs the real cli/sp.py of this checkout directly and through the binary: output and exit
// status must be identical.
func TestSameAsPython(t *testing.T) {
	t.Parallel()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not installed")
	}
	bin, root := buildSP(t), repoRoot(t)
	env := append(os.Environ(), "SP_PY_HOME="+root, "SP_PYTHON="+python, "SP_DATA=", "NO_COLOR=1")
	for _, args := range [][]string{
		{"--help"},
		{},
		{"no-such-command"},
		{"findings", "--data", filepath.Join(t.TempDir(), "missing")},
		{"init"},
	} {
		direct := runBin(t, python, env, "", append([]string{filepath.Join(root, "cli", "sp.py")}, args...)...)
		shimmed := runBin(t, bin, env, "", args...)
		if direct != shimmed {
			t.Errorf("sp %q differs:\ndirect  %+v\nthrough %+v", args, direct, shimmed)
		}
	}
}
