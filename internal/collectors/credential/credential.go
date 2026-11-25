// Package credential reads the secrets of the Go collectors and the events shipper: from a file only its owner can
// read (mode 0600 or stricter, as contracts/collector-protocol §2 requires) or from a named environment variable,
// nothing else. A secret is returned to the caller only; errors name the file or the variable, never the value.
package credential

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// MaxSecret bounds a secret file (a token is far smaller; a large file is a mistake, not a token).
const MaxSecret = 64 << 10

// Errors a caller tells apart.
var (
	ErrPermissive = errors.New("readable or writable by group/others")
	ErrEmpty      = errors.New("empty")
	ErrNotRegular = errors.New("not a regular file")
	ErrTooLarge   = errors.New("too large for a secret")
	ErrNoVariable = errors.New("environment variable not set")
)

// File reads the secret in path (white space around it removed). The file must be a regular file whose mode
// grants nothing to group and others (Python's `st_mode & 0o077 == 0`). On Windows the mode bits Go reports
// (0666/0444) never pass this check: use a named environment variable there.
func File(path string) (string, error) {
	p := filepath.Clean(path)
	st, err := os.Stat(p)
	if err != nil {
		return "", fmt.Errorf("stat %s: %w", path, unwrapPath(err))
	}
	if !st.Mode().IsRegular() {
		return "", fmt.Errorf("%s: %w", path, ErrNotRegular)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("%s: %w (mode %04o, chmod 600)", path, ErrPermissive, st.Mode().Perm())
	}
	return readSecret(p, path)
}

func readSecret(p, shown string) (secret string, err error) {
	f, err := os.Open(filepath.Clean(p))
	if err != nil {
		return "", fmt.Errorf("open %s: %w", shown, unwrapPath(err))
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			secret, err = "", fmt.Errorf("close %s: %w", shown, unwrapPath(cerr))
		}
	}()
	data, err := io.ReadAll(io.LimitReader(f, MaxSecret+1))
	if err != nil {
		return "", fmt.Errorf("read %s: %w", shown, unwrapPath(err))
	}
	if len(data) > MaxSecret {
		return "", fmt.Errorf("%s: %w", shown, ErrTooLarge)
	}
	s := strings.TrimSpace(string(data))
	if s == "" {
		return "", fmt.Errorf("%s: %w", shown, ErrEmpty)
	}
	return s, nil
}

// unwrapPath drops the *fs.PathError wrapper (its text repeats the path) and keeps the cause.
func unwrapPath(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

// Env reads the secret in the named environment variable (white space around it removed).
func Env(getenv func(string) string, name string) (string, error) {
	if name == "" {
		return "", ErrNoVariable
	}
	s := strings.TrimSpace(getenv(name))
	if s == "" {
		return "", fmt.Errorf("%s: %w", name, ErrNoVariable)
	}
	return s, nil
}
