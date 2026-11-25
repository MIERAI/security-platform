// Package pyhome finds the Python implementation of the product (a release tree or a checkout that contains
// cli/sp.py) that the sp binary delegates to while a subcommand has no Go implementation yet.
package pyhome

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// EnvHome names the environment variable that points at the Python tree explicitly.
const EnvHome = "SP_PY_HOME"

// Entry is the Python command line inside a tree (slash-separated).
const Entry = "cli/sp.py"

// ErrNotFound is returned when no candidate holds cli/sp.py.
var ErrNotFound = errors.New("python implementation not found")

// Home is a located Python tree.
type Home struct {
	Dir    string `json:"dir"`
	Source string `json:"source"` // "env" (SP_PY_HOME), "binary" (next to the sp binary) or "default"
}

// Script is the path of cli/sp.py in the tree.
func (h Home) Script() string { return filepath.Join(h.Dir, filepath.FromSlash(Entry)) }

// Locate finds the Python tree: $SP_PY_HOME when set (and then only there), else the tree the binary sits in
// (<tree>/bin/sp or <tree>/sp, symlinks resolved), else the default install root
// ~/.local/opt/security-platform/current (docs/upgrade.md). exe is the binary's path (os.Executable).
func Locate(getenv func(string) string, exe string) (Home, error) {
	if dir := getenv(EnvHome); dir != "" {
		if !holdsEntry(dir) {
			return Home{}, fmt.Errorf("%s=%q: %w (no %s there)", EnvHome, dir, ErrNotFound, Entry)
		}
		return abs(dir, "env")
	}
	for _, dir := range binaryCandidates(exe) {
		if holdsEntry(dir) {
			return abs(dir, "binary")
		}
	}
	if home := getenv("HOME"); home != "" {
		dir := filepath.Join(home, ".local", "opt", "security-platform", "current")
		if holdsEntry(dir) {
			return abs(dir, "default")
		}
	}
	return Home{}, fmt.Errorf("%w: set %s to a security-platform release or checkout", ErrNotFound, EnvHome)
}

func binaryCandidates(exe string) []string {
	if exe == "" {
		return nil
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	dir := filepath.Dir(exe)
	return []string{filepath.Dir(dir), dir}
}

func holdsEntry(dir string) bool {
	fi, err := os.Stat(filepath.Join(dir, filepath.FromSlash(Entry)))
	return err == nil && fi.Mode().IsRegular()
}

func abs(dir, source string) (Home, error) {
	a, err := filepath.Abs(dir)
	if err != nil {
		return Home{}, fmt.Errorf("absolute path of %q: %w", dir, err)
	}
	return Home{Dir: a, Source: source}, nil
}
