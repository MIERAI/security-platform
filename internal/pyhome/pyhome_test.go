package pyhome

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func tree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "cli"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(Entry)), []byte("# sp\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLocate(t *testing.T) {
	t.Parallel()
	explicit, beside, home := tree(t), tree(t), t.TempDir()
	installed := filepath.Join(home, ".local", "opt", "security-platform", "current")
	if err := os.MkdirAll(filepath.Join(installed, "cli"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(installed, filepath.FromSlash(Entry)), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	elsewhere := filepath.Join(t.TempDir(), "sp")
	tests := []struct {
		name, exe, wantDir, wantSource string
		env                            map[string]string
		wantErr                        bool
	}{
		{"explicit wins", filepath.Join(beside, "bin", "sp"), explicit, "env", map[string]string{EnvHome: explicit}, false},
		{"explicit but wrong fails", filepath.Join(beside, "bin", "sp"), "", "", map[string]string{EnvHome: home}, true},
		{"binary in tree/bin", filepath.Join(beside, "bin", "sp"), beside, "binary", nil, false},
		{"binary at tree top", filepath.Join(beside, "sp"), beside, "binary", nil, false},
		{"default install root", elsewhere, installed, "default", map[string]string{"HOME": home}, false},
		{"nowhere", elsewhere, "", "", map[string]string{"HOME": t.TempDir()}, true},
		{"no executable path", "", "", "", nil, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h, err := Locate(env(tc.env), tc.exe)
			if tc.wantErr {
				if !errors.Is(err, ErrNotFound) {
					t.Fatalf("Locate = %+v, %v; want ErrNotFound", h, err)
				}
				return
			}
			if err != nil || h.Dir != tc.wantDir || h.Source != tc.wantSource {
				t.Fatalf("Locate = %+v, %v; want %s (%s)", h, err, tc.wantDir, tc.wantSource)
			}
		})
	}
}

func TestLocateFollowsSymlink(t *testing.T) {
	t.Parallel()
	target := tree(t)
	bin := filepath.Join(target, "bin")
	if err := os.MkdirAll(bin, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "sp"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "sp")
	if err := os.Symlink(filepath.Join(bin, "sp"), link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	h, err := Locate(env(nil), link)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := filepath.EvalSymlinks(target)
	if got, _ := filepath.EvalSymlinks(h.Dir); got != want {
		t.Fatalf("Locate(symlink) = %s, want %s", got, want)
	}
}
