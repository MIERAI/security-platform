//go:build unix

package execadapter

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func env() []string { return []string{"PATH=/usr/bin:/bin", "LC_ALL=C"} }

func TestRunLocal(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, script, stdin string
		want                Result
	}{
		{"stdin, stdout, stderr, status", "cat; echo err >&2; exit 3", "a=1\n", Result{RC: 3, Out: "a=1\n", Err: "err\n"}},
		{"universal newlines, replacement characters", `printf 'a\r\nb\rc\377'`, "", Result{Out: "a\nb\nc�"}},
		{"killed by a signal: minus the signal", "kill -9 $$", "", Result{RC: -9}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := local{environ: env()}.Run(context.Background(), []string{"sh", "-c", tt.script}, tt.stdin, 10*time.Second, false)
			if err != nil || got != tt.want {
				t.Fatalf("Run = %#v, %v; want %#v", got, err, tt.want)
			}
		})
	}
}

func writeExecutable(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o700); err != nil { // #nosec G306 -- an executable fixture
		t.Fatal(err)
	}
}

// Not parallel (nor is TestSSHThroughPATH): they write executables, and a program file being written while another
// test forks cannot be executed ("text file busy").
func TestNotFound(t *testing.T) {
	dir := t.TempDir()
	writeExecutable(t, filepath.Join(dir, "tool"), "#!/bin/sh\necho hi\n")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(wd, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"PATH=/nonexistent", "PATH=" + rel, "PATH=."} { // relative entries are never searched
		got, rerr := local{environ: []string{path}}.Run(context.Background(), []string{"tool"}, "", time.Second, false)
		if rerr != nil || got.RC != StatusNotFound || got.Err != "tool: not found" {
			t.Errorf("%s: %#v, %v", path, got, rerr)
		}
	}
	got, err := local{environ: []string{"PATH=" + dir}}.Run(context.Background(), []string{"tool"}, "", 5*time.Second, false)
	if err != nil || got.Out != "hi\n" {
		t.Errorf("absolute PATH entry: %#v, %v", got, err)
	}
}

// TestTimeout: status 124, "timeout", the output printed so far only when partial, and the whole process group
// stopped (a background child that keeps the pipe open included) well before the child would have finished.
func TestTimeout(t *testing.T) {
	t.Parallel()
	for _, partial := range []bool{true, false} {
		t.Run(strconv.FormatBool(partial), func(t *testing.T) {
			t.Parallel()
			pidFile := filepath.Join(t.TempDir(), "pid")
			script := "echo a=1; sleep 60 & echo $! > " + pidFile + "; wait; echo b=2"
			start := time.Now()
			got, err := local{environ: env()}.Run(context.Background(), []string{"sh", "-c", script}, "", time.Second, partial)
			if err != nil {
				t.Fatal(err)
			}
			want := Result{RC: StatusTimeout, Err: "timeout"}
			if partial {
				want.Out = "a=1\n"
			}
			if got != want {
				t.Errorf("Run = %#v, want %#v", got, want)
			}
			if d := time.Since(start); d > 8*time.Second {
				t.Errorf("took %v", d)
			}
			assertGone(t, pidFile)
		})
	}
}

func assertGone(t *testing.T, pidFile string) {
	t.Helper()
	data, err := os.ReadFile(pidFile) // #nosec G304 -- the test's own file
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for syscall.Kill(pid, 0) == nil && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if syscall.Kill(pid, 0) == nil {
		t.Errorf("the background child %d still runs", pid)
	}
}

// TestSSHThroughPATH: ssh is found on the given environment's PATH and gets the fixed options, the host, one
// remote command line and the script on stdin.
func TestSSHThroughPATH(t *testing.T) {
	dir := t.TempDir()
	writeExecutable(t, filepath.Join(dir, "ssh"), "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done\ncat\n")
	e, err := New(cfg(t, "{type: ssh, host: target}"), []string{"PATH=" + dir + ":/usr/bin:/bin"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.Run(context.Background(), []string{"sh", "-s"}, "script\n", 5*time.Second, false)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Join(append(sshBase(), "target", "sh -s", "script"), "\n") + "\n"
	if got.Out != want || got.RC != 0 {
		t.Errorf("ssh saw %q, want %q", got.Out, want)
	}
}
