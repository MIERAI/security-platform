// Package release names product releases the way cli/release.py does: from product tags
// vMAJOR.MINOR.PATCH[-PRERELEASE] only, never from component tags (<component>/vX.Y.Z) and never from what
// `git describe` happens to prefer.
//
// Deliberate differences from cli/release.py, all stricter:
//   - digits are ASCII only (Python's \d also matches other Unicode digits);
//   - a trailing newline is not part of a tag (Python's $ matches before one);
//   - a RELEASE file larger than MaxReleaseFile bytes is not read.
package release

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// MaxReleaseFile is the largest RELEASE file that is read (bin/sp-install writes two short lines).
const MaxReleaseFile = 4096

// FileName is the file bin/sp-install writes at the top of an installed tree.
const FileName = "RELEASE"

// productTag is never written after initialisation.
var productTag = regexp.MustCompile(
	`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$`)

// Version is a parsed product tag. Numeric parts are kept as decimal strings so that any length compares
// correctly (Python integers are unbounded; so is this).
type Version struct {
	Tag        string
	Major      string
	Minor      string
	Patch      string
	Prerelease []string // nil for a release
}

// Parse parses a product tag. ok is false for anything else, including component tags.
func Parse(tag string) (v Version, ok bool) {
	m := productTag.FindStringSubmatch(tag)
	if m == nil {
		return Version{}, false
	}
	v = Version{Tag: tag, Major: m[1], Minor: m[2], Patch: m[3]}
	if m[4] != "" {
		v.Prerelease = strings.Split(m[4], ".")
	}
	return v, true
}

// IsProductTag reports whether name is a product tag.
func IsProductTag(name string) bool {
	_, ok := Parse(name)
	return ok
}

// Compare orders two versions by semantic version precedence: -1, 0 or +1. A pre-release sorts before its
// release; build metadata does not exist in product tags.
func Compare(a, b Version) int {
	for _, p := range [][2]string{{a.Major, b.Major}, {a.Minor, b.Minor}, {a.Patch, b.Patch}} {
		if c := compareNumeric(p[0], p[1]); c != 0 {
			return c
		}
	}
	switch {
	case a.Prerelease == nil && b.Prerelease == nil:
		return 0
	case a.Prerelease == nil:
		return 1
	case b.Prerelease == nil:
		return -1
	}
	return comparePrerelease(a.Prerelease, b.Prerelease)
}

func comparePrerelease(a, b []string) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if c := compareIdentifier(a[i], b[i]); c != 0 {
			return c
		}
	}
	return compareInt(len(a), len(b))
}

// compareIdentifier: numeric identifiers compare numerically and sort before alphanumeric ones, which compare
// as strings (cli/release.py semver_key).
func compareIdentifier(a, b string) int {
	an, bn := isDigits(a), isDigits(b)
	switch {
	case an && bn:
		return compareNumeric(a, b)
	case an:
		return -1
	case bn:
		return 1
	}
	return strings.Compare(a, b)
}

// compareNumeric compares two ASCII decimal strings of any length ("007" equals "7").
func compareNumeric(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if c := compareInt(len(a), len(b)); c != 0 {
		return c
	}
	return strings.Compare(a, b)
}

func compareInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// Highest returns the highest product tag among names (others are ignored); ok is false when there is none.
func Highest(names []string) (tag string, ok bool) {
	var best Version
	for _, n := range names {
		v, isTag := Parse(n)
		if isTag && (!ok || Compare(v, best) > 0) {
			best, ok = v, true
		}
	}
	return best.Tag, ok
}

// Installed is the content of a RELEASE file: version= and commit= (other keys are ignored).
type Installed struct {
	Version string
	Commit  string
}

// ErrTooLarge is returned for a RELEASE file over MaxReleaseFile bytes.
var ErrTooLarge = errors.New("release file too large")

// ParseFile parses a RELEASE file: key=value lines, surrounding whitespace removed, the last value of a key wins,
// lines without "=" ignored. ok is false when there is no non-empty version (cli/release.py installed_release).
func ParseFile(r io.Reader) (inst Installed, ok bool, err error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxReleaseFile+1))
	if err != nil {
		return Installed{}, false, fmt.Errorf("read release file: %w", err)
	}
	if len(data) > MaxReleaseFile {
		return Installed{}, false, ErrTooLarge
	}
	// universal newlines, as Python's text mode reads the file
	data = bytes.ReplaceAll(bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n")), []byte("\r"), []byte("\n"))
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, MaxReleaseFile+1), MaxReleaseFile+1)
	for sc.Scan() {
		k, v, found := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		switch {
		case !found:
		case k == "version":
			inst.Version = v
		case k == "commit":
			inst.Commit = v
		}
	}
	if err := sc.Err(); err != nil {
		return Installed{}, false, fmt.Errorf("scan release file: %w", err)
	}
	return inst, inst.Version != "", nil
}
