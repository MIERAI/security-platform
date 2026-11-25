package delegate

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/MIERAI/security-platform/internal/fakepython"
)

func TestMain(m *testing.M) {
	fakepython.Run()
	os.Exit(m.Run())
}

func fakeSpec(t *testing.T, args ...string) Spec {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return Spec{Python: exe, Script: "/tree/cli/sp.py", Args: args,
		Env: fakepython.Environ(t.TempDir())}
}

func TestArgvIsVerbatim(t *testing.T) {
	t.Parallel()
	s := Spec{Python: "/usr/bin/python3", Script: "/t/cli/sp.py", Args: []string{"findings", "--open", "a b", "$(x)", ""}}
	want := []string{"/usr/bin/python3", "/t/cli/sp.py", "findings", "--open", "a b", "$(x)", ""}
	if got := s.Argv(); strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("Argv = %q, want %q", got, want)
	}
}

func TestChildExitCodes(t *testing.T) {
	t.Parallel()
	for _, code := range []int{0, 1, 2, 3, 42, 125, 126, 127, 255} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			t.Parallel()
			s := fakeSpec(t, "exit", strconv.Itoa(code))
			var out, errOut bytes.Buffer
			s.Stdout, s.Stderr = &out, &errOut
			got, err := Child(t.Context(), s)
			if err != nil || got != code {
				t.Fatalf("Child = %d, %v; want %d", got, err, code)
			}
			if out.String() != "out" || errOut.String() != "err" {
				t.Errorf("streams = %q / %q", out.String(), errOut.String())
			}
		})
	}
}

func TestChildArgvAndStdin(t *testing.T) {
	t.Parallel()
	args := []string{"argv", "--json", "a b", "'quoted'", "$HOME", "; rm -rf /", ""}
	s := fakeSpec(t, args...)
	var out bytes.Buffer
	s.Stdout, s.Stderr = &out, os.Stderr
	if code, err := Child(t.Context(), s); err != nil || code != 0 {
		t.Fatalf("Child = %d, %v", code, err)
	}
	var want strings.Builder
	for _, a := range append([]string{s.Script}, args...) {
		want.WriteString(strconv.Quote(a) + "\n")
	}
	if out.String() != want.String() {
		t.Fatalf("argv seen by python:\n%s\nwant:\n%s", out.String(), want.String())
	}
	s = fakeSpec(t, "stdin")
	out.Reset()
	s.Stdin, s.Stdout, s.Stderr = strings.NewReader("line 1\nline 2\n"), &out, os.Stderr
	if code, err := Child(t.Context(), s); err != nil || code != 0 || out.String() != "line 1\nline 2\n" {
		t.Fatalf("stdin passthrough: %d, %v, %q", code, err, out.String())
	}
}

func TestChildSignalled(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("no signals")
	}
	s := fakeSpec(t, "kill")
	if code, err := Child(t.Context(), s); err != nil || code != 128+9 {
		t.Fatalf("Child = %d, %v; want 137", code, err)
	}
}

func TestChildMissingInterpreter(t *testing.T) {
	t.Parallel()
	s := Spec{Python: filepath.Join(t.TempDir(), "nope"), Script: "x"}
	if _, err := Child(t.Context(), s); err == nil {
		t.Fatal("Child with a missing interpreter succeeded")
	}
}

func TestInterpreter(t *testing.T) {
	t.Parallel()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, env string
		wantErr   bool
	}{
		{"explicit path", exe, false},
		{"explicit missing", filepath.Join(t.TempDir(), "python9"), true},
		{"explicit name not on PATH", "no-such-python-xyz", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := Interpreter(onlyPython(tc.env))
			if tc.wantErr != errors.Is(err, ErrNoInterpreter) || tc.wantErr != (err != nil) {
				t.Fatalf("Interpreter = %q, %v", got, err)
			}
		})
	}
}

func onlyPython(value string) func(string) string {
	return func(k string) string {
		if k == EnvPython {
			return value
		}
		return ""
	}
}
