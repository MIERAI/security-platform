package fileio

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWrite(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		durable bool
		stale   bool
	}{
		{"plain", false, false},
		{"durable", true, false},
		{"stale temporary file", false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := filepath.Join(t.TempDir(), "f.json")
			files := map[string]string{p: "old"}
			if tc.stale {
				files[p+".tmp"] = "half"
			}
			writeFiles(t, files)
			write := Write
			if tc.durable {
				write = WriteDurable
			}
			if err := write(p, []byte("new")); err != nil {
				t.Fatal(err)
			}
			checkWritten(t, p, "new")
		})
	}
}

func writeFiles(t *testing.T, files map[string]string) {
	t.Helper()
	for name, content := range files {
		if err := os.WriteFile(name, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// checkWritten: content, no temporary file left, mode 0600 (Windows has no Unix modes).
func checkWritten(t *testing.T, p, want string) {
	t.Helper()
	got, err := Read(p, 1<<10)
	if err != nil || string(got) != want {
		t.Fatalf("content %q, %v", got, err)
	}
	if _, serr := os.Stat(p + ".tmp"); !os.IsNotExist(serr) {
		t.Fatalf("temporary file left: %v", serr)
	}
	fi, err := os.Stat(p)
	if err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600) {
		t.Fatalf("mode %v, %v", fi.Mode(), err)
	}
}

func TestRead(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, make([]byte, 11), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(p, 10); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
	if b, err := Read(p, 11); err != nil || len(b) != 11 {
		t.Fatalf("Read = %d, %v", len(b), err)
	}
	if _, err := Read(p+"-missing", 10); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("err = %v, want fs.ErrNotExist", err)
	}
}

func TestWriteIntoMissingDirectory(t *testing.T) {
	t.Parallel()
	if err := Write(filepath.Join(t.TempDir(), "missing", "f"), []byte("x")); err == nil {
		t.Fatal("Write into a missing directory succeeded")
	}
}
