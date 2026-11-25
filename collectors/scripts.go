// Package collectors carries the scripts the exec-adapter collectors run ON their targets: the host profiles and
// their probe helpers (collectors/host/profiles), the inventory profiles (collectors/host-sbom/profiles) and the
// secrets scan (collectors/secrets-files/remote/scan.py). The Go collectors (internal/collectors/...) send exactly
// these files, so a target sees the same script whichever implementation runs; the Python collectors read the same
// files from the tree.
package collectors

import (
	"embed"
	"fmt"
)

// scripts is read-only after initialisation (go:embed).
//
//go:embed host/profiles/*.sh host/profiles/*.ps1 host-sbom/profiles/*.sh host-sbom/profiles/*.ps1 secrets-files/remote/scan.py
var scripts embed.FS

// Script returns one embedded script by its slash-separated path below collectors/, e.g. "host/profiles/linux.sh".
func Script(path string) (string, error) {
	b, err := scripts.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("no embedded script %s: %w", path, err)
	}
	return string(b), nil
}
