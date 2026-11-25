package credential

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestFile(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("mode bits are not permissions on Windows: File refuses every file there (documented)")
	}
	dir := t.TempDir()
	canary := "canary-" + "s3cr3t-0123"
	tests := []struct {
		name    string
		content string
		mode    os.FileMode
		want    string
		err     error
	}{
		{"private.tok", "  " + canary + "\n", 0o600, canary, nil},
		{"readonly.tok", canary, 0o400, canary, nil},
		{"group.tok", canary, 0o640, "", ErrPermissive},
		{"world.tok", canary, 0o644, "", ErrPermissive},
		{"empty.tok", "\n", 0o600, "", ErrEmpty},
		{"big.tok", strings.Repeat("x", MaxSecret+1), 0o600, "", ErrTooLarge},
	}
	for _, tt := range tests {
		p := writeMode(t, filepath.Join(dir, tt.name), tt.content, tt.mode)
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := File(p)
			if !errors.Is(err, tt.err) || got != tt.want {
				t.Fatalf("File = %q, %v; want %q, %v", got, err, tt.want, tt.err)
			}
			if err != nil && strings.Contains(err.Error(), canary) {
				t.Fatalf("the secret is in the error: %v", err)
			}
		})
	}
	if _, err := File(dir); !errors.Is(err, ErrNotRegular) {
		t.Errorf("a directory: %v", err)
	}
	if _, err := File(filepath.Join(dir, "missing")); err == nil {
		t.Error("a missing file is an error")
	}
}

func writeMode(t *testing.T, p, content string, mode os.FileMode) string {
	t.Helper()
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestEnv(t *testing.T) {
	t.Parallel()
	env := map[string]string{"TOK": " value \n", "EMPTY": ""}
	get := func(k string) string { return env[k] }
	if v, err := Env(get, "TOK"); err != nil || v != "value" {
		t.Errorf("TOK: %q %v", v, err)
	}
	for _, name := range []string{"EMPTY", "MISSING", ""} {
		if _, err := Env(get, name); !errors.Is(err, ErrNoVariable) {
			t.Errorf("%q: %v", name, err)
		}
	}
}
