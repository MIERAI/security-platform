package rundoc

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ErrTooLarge is returned by ReadLimited for a file over its limit.
var ErrTooLarge = errors.New("file too large")

// ReadLimited reads a whole file of at most limit bytes.
func ReadLimited(path string, limit int64) (data []byte, err error) {
	f, err := os.Open(path) // #nosec G304 -- paths from the instance config, the data directory or the run directory
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", filepath.Base(path), err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			data, err = nil, fmt.Errorf("close %s: %w", filepath.Base(path), cerr)
		}
	}()
	return ReadAllLimited(f, limit)
}

// ReadAllLimited reads r to its end, at most limit bytes (more is ErrTooLarge).
func ReadAllLimited(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%w (over %d bytes)", ErrTooLarge, limit)
	}
	return data, nil
}

// WriteFile writes data to path in one step (a temporary file next to it, then a rename), private to the user.
func WriteFile(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	if err := os.Chmod(tmp, 0o600); err != nil { // an existing temporary file keeps its mode under WriteFile
		return fmt.Errorf("chmod %s: %w", filepath.Base(path), err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename %s: %w", filepath.Base(path), err)
	}
	return nil
}

// MkdirPrivate creates dir and its parents, private to the user.
func MkdirPrivate(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Base(dir), err)
	}
	return nil
}

// ExpandUser is Python's os.path.expanduser for "~" and "~/..." (the text is kept as Python keeps it: the home
// directory without its trailing slash, then the rest unchanged; "~name" is left as it is).
func ExpandUser(p, home string) string {
	if home == "" || (p != "~" && !strings.HasPrefix(p, "~/")) {
		return p
	}
	h := strings.TrimRight(home, "/")
	if h == "" {
		h = "/"
		if p != "~" {
			h = ""
		}
	}
	return h + p[1:]
}
