package components

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseVersion(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in, want string
		wantErr  bool
	}{
		{"0.3.0\n", "0.3.0", false},
		{"  1.2.3-rc.1  \r\n", "1.2.3-rc.1", false},
		{"0.3", "", true},
		{"01.0.0", "", true},
		{"0.3.0\n0.4.0\n", "", true},
		{"v0.3.0", "", true},
		{"", "", true},
		{strings.Repeat("1", 70) + ".0.0", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			got, err := ParseVersion(strings.NewReader(tc.in))
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Errorf("ParseVersion(%q) = %q, %v; want %q (error %v)", tc.in, got, err, tc.want, tc.wantErr)
			}
			if err != nil && !errors.Is(err, ErrInvalidVersion) {
				t.Errorf("unexpected error kind %v", err)
			}
		})
	}
}

func write(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDiscover(t *testing.T) {
	t.Parallel()
	tree := t.TempDir()
	write(t, filepath.Join(tree, "cli", "VERSION"), "0.3.0\n")
	write(t, filepath.Join(tree, "core", "VERSION"), "0.9.0\n")
	write(t, filepath.Join(tree, "collectors", "host", "VERSION"), "0.3.0\n")
	write(t, filepath.Join(tree, "collectors", "k8s", "VERSION"), "garbage\n")
	write(t, filepath.Join(tree, "collectors", "host", "profiles", "VERSION"), "9.9.9\n") // too deep
	write(t, filepath.Join(tree, ".git", "VERSION"), "1.0.0\n")                           // hidden
	write(t, filepath.Join(tree, "docs", "README.md"), "")
	got, err := Discover(tree)
	if err != nil {
		t.Fatal(err)
	}
	want := []Component{
		{"cli", "0.3.0", Python}, {"collectors/host", "0.3.0", Python},
		{"collectors/k8s", "invalid", Python}, {"core", "0.9.0", Python},
	}
	if len(got) != len(want) {
		t.Fatalf("Discover = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("component %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestDiscoverMissingTree(t *testing.T) {
	t.Parallel()
	if _, err := Discover(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("Discover on a missing tree succeeded")
	}
}

func TestGoImplementedIsFresh(t *testing.T) {
	t.Parallel()
	m := GoImplemented()
	m["cli"] = true
	if GoImplemented()["cli"] {
		t.Fatal("GoImplemented shares state between calls")
	}
}

func FuzzParseVersion(f *testing.F) {
	for _, s := range []string{"0.3.0\n", "1.2.3-rc.1", "", "\x00", "1.2.3\n4"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := ParseVersion(strings.NewReader(string(data)))
		if err != nil {
			return
		}
		if !versionPattern.MatchString(v) || len(v) > maxVersionFile || strings.ContainsAny(v, " \t\r\n") {
			t.Fatalf("ParseVersion(%q) accepted %q", data, v)
		}
	})
}
