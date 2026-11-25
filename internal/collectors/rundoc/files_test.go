package rundoc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestExpandUser(t *testing.T) {
	t.Parallel()
	tests := []struct{ p, home, want string }{
		{"~", "/h", "/h"}, {"~/a/../b", "/h/", "/h/a/../b"}, {"~x/a", "/h", "~x/a"}, {"/abs", "/h", "/abs"},
		{"~/a", "", "~/a"}, {"~", "/", "/"}, {"~/a", "/", "/a"},
	}
	for _, tc := range tests {
		if got := ExpandUser(tc.p, tc.home); got != tc.want {
			t.Errorf("ExpandUser(%q, %q) = %q, want %q", tc.p, tc.home, got, tc.want)
		}
	}
}

func TestReadLimited(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := ReadLimited(p, 5); err != nil || string(b) != "12345" {
		t.Fatalf("ReadLimited = %q, %v", b, err)
	}
	if _, err := ReadLimited(p, 4); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("over the limit: %v", err)
	}
}

func TestEnvHelpers(t *testing.T) {
	t.Parallel()
	env := []string{"A=1", "PATH=/x", "A=2", "B=3"}
	if Lookup(env, "A") != "2" || Lookup(env, "C") != "" {
		t.Error("Lookup")
	}
	got := WithEnv(env, map[string]string{"B": "4", "C": "5"})
	if strings.Join(got, " ") != "A=1 PATH=/x A=2 B=4 C=5" {
		t.Errorf("WithEnv = %v", got)
	}
	if _, err := LookPath("no-such-tool-here", []string{"PATH=.:relative"}); err == nil {
		t.Error("a relative PATH entry was searched")
	}
}

func writeScript(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body), 0o700); err != nil { // #nosec G306 -- test program
		t.Fatal(err)
	}
}

func TestExec(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX sh test programs")
	}
	dir := t.TempDir()
	writeScript(t, dir, "ok", "cat; echo err >&2; exit 3\n")
	writeScript(t, dir, "slow", "sleep 30 & sleep 30\n")
	writeScript(t, dir, "big", "yes | head -c 100000\n")
	env := []string{"PATH=" + dir + ":/usr/bin:/bin"}
	tests := []struct {
		name string
		cmd  Cmd
		rc   int
		out  string
		err  string
		over bool
	}{
		{"exit status and streams", Cmd{Argv: []string{"ok"}, Env: env, Stdin: strings.NewReader("in")}, 3, "in", "err\n", false},
		{"not found", Cmd{Argv: []string{"nope"}, Env: env}, RCNotFound, "", "nope: not found", false},
		{"timeout kills the group", Cmd{Argv: []string{"slow"}, Env: env, Timeout: 200 * time.Millisecond}, RCTimeout, "", "timeout", false},
		{"output cap", Cmd{Argv: []string{"big"}, Env: env, MaxOut: 10}, 0, "y\ny\ny\ny\ny\n", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			start := time.Now()
			r := Exec(context.Background(), &tc.cmd)
			if r.RC != tc.rc || r.Stdout != tc.out || r.Stderr != tc.err || r.Truncated != tc.over {
				t.Errorf("Exec = %+v", r)
			}
			if time.Since(start) > 20*time.Second {
				t.Error("the process group was not killed")
			}
		})
	}
}
