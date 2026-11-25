// Package components lists the product's components (every <dir>/VERSION and <dir>/<sub>/VERSION of a tree, as
// docs/design.md §5 versions them) and which implementation, Go or Python, serves each one.
package components

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Implementation names.
const (
	Go     = "go"
	Python = "python"
)

// maxVersionFile bounds how much of a VERSION file is read.
const maxVersionFile = 64

// versionPattern is never written after initialisation.
var versionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$`)

// Component is one versioned part of the product.
type Component struct {
	Name           string `json:"name"`    // e.g. "cli", "collectors/host"
	Version        string `json:"version"` // from its VERSION file; "invalid" when unreadable or malformed
	Implementation string `json:"implementation"`
}

// GoImplemented returns the components whose Go implementation has replaced the Python one (each passed the
// conformance suite first). A fresh map on every call: nothing can change the answer at run time.
func GoImplemented() map[string]bool {
	return map[string]bool{
		"cli":             true, // sp init|doctor|run|status|findings|explain|digest|notify (internal/cli); SP_CLI=python goes back
		"internal/ledger": true,
		"runner":          true, // sp runner (internal/runner); the trigger chooses which runner ticks (docs/runner.md)
	}
}

// Discover lists the components of a tree, sorted by name, with their implementation.
func Discover(tree string) ([]Component, error) {
	goImpl := GoImplemented()
	dirs, err := componentDirs(tree)
	if err != nil {
		return nil, err
	}
	out := make([]Component, 0, len(dirs))
	for _, name := range dirs {
		c := Component{Name: name, Version: readVersion(filepath.Join(tree, filepath.FromSlash(name), "VERSION")),
			Implementation: Python}
		if goImpl[name] {
			c.Implementation = Go
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// componentDirs returns the slash-separated directories, one or two levels deep, that hold a VERSION file.
// Hidden directories and symbolic links are skipped.
func componentDirs(tree string) ([]string, error) {
	top, err := subdirs(tree)
	if err != nil {
		return nil, fmt.Errorf("list components in %s: %w", tree, err)
	}
	var names []string
	for _, d := range top {
		if isFile(filepath.Join(tree, d, "VERSION")) {
			names = append(names, d)
		}
		sub, err := subdirs(filepath.Join(tree, d))
		if err != nil {
			continue // an unreadable directory has no components we can report
		}
		for _, s := range sub {
			if isFile(filepath.Join(tree, d, s, "VERSION")) {
				names = append(names, d+"/"+s)
			}
		}
	}
	return names, nil
}

func subdirs(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			out = append(out, e.Name())
		}
	}
	return out, nil
}

func isFile(path string) bool {
	fi, err := os.Lstat(path)
	return err == nil && fi.Mode().IsRegular()
}

// readVersion returns the component version in path, or "invalid".
func readVersion(path string) string {
	v, err := readVersionFile(path)
	if err != nil {
		return "invalid"
	}
	return v
}

func readVersionFile(path string) (v string, err error) {
	f, err := os.Open(path) // #nosec G304 -- a VERSION file inside the product tree
	if err != nil {
		return "", fmt.Errorf("open version: %w", err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			v, err = "", fmt.Errorf("close version: %w", cerr)
		}
	}()
	return ParseVersion(f)
}

// ErrInvalidVersion is returned for a VERSION file that is not one MAJOR.MINOR.PATCH[-PRE] line.
var ErrInvalidVersion = errors.New("invalid component version")

// ParseVersion reads a component VERSION file: one MAJOR.MINOR.PATCH[-PRERELEASE] line, surrounding
// whitespace ignored, at most 64 bytes.
func ParseVersion(r io.Reader) (string, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxVersionFile+1))
	if err != nil {
		return "", fmt.Errorf("read version: %w", err)
	}
	v := string(bytes.TrimSpace(data))
	if len(data) > maxVersionFile || !versionPattern.MatchString(v) {
		return "", ErrInvalidVersion
	}
	return v, nil
}
