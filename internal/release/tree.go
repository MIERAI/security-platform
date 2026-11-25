package release

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// GitTimeout bounds every git call made to name a checkout.
const GitTimeout = 10 * time.Second

// Unknown is what Describe returns when a tree has neither a RELEASE file nor a usable git checkout.
const Unknown = "unknown"

// Describe is the best-effort product version of a tree for display (cli/release.py describe_tree): the RELEASE
// file of an installed tree, else the product tag or development name of a git checkout, else Unknown. It never
// fails.
func Describe(ctx context.Context, tree string) string {
	if inst, ok, err := ReadInstalled(tree); err == nil && ok {
		return inst.Version
	}
	if _, err := os.Stat(filepath.Join(tree, ".git")); err != nil {
		return Unknown
	}
	name, err := ForRef(ctx, tree, "HEAD")
	if err != nil {
		return Unknown
	}
	return name
}

// ReadInstalled reads <tree>/RELEASE. ok is false when it is missing or has no version.
func ReadInstalled(tree string) (inst Installed, ok bool, err error) {
	f, err := os.Open(filepath.Join(tree, FileName)) // #nosec G304 -- the tree is the product's own install directory
	if errors.Is(err, os.ErrNotExist) {
		return Installed{}, false, nil
	}
	if err != nil {
		return Installed{}, false, fmt.Errorf("open release file: %w", err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			inst, ok, err = Installed{}, false, fmt.Errorf("close release file: %w", cerr)
		}
	}()
	return ParseFile(f)
}

// ForRef names a commit of a git checkout: its highest product tag, else the development name
// dev-<nearest product tag below>-<commits since>-g<commit> (dev-untagged-g<commit> without one).
func ForRef(ctx context.Context, repo, ref string) (string, error) {
	if ref == "" || strings.HasPrefix(ref, "-") {
		return "", fmt.Errorf("invalid ref %q", ref)
	}
	sha, err := git(ctx, repo, "rev-parse", "--verify", "--quiet", ref+"^{commit}")
	if err != nil {
		return "", err
	}
	at, err := git(ctx, repo, "tag", "--points-at", sha)
	if err != nil {
		return "", err
	}
	if tag, ok := Highest(strings.Fields(at)); ok {
		return tag, nil
	}
	return devName(ctx, repo, sha)
}

func devName(ctx context.Context, repo, sha string) (string, error) {
	short, err := git(ctx, repo, "rev-parse", "--short=7", sha)
	if err != nil {
		return "", err
	}
	merged, err := git(ctx, repo, "tag", "--merged", sha)
	if err != nil {
		return "", err
	}
	base, ok := Highest(strings.Fields(merged))
	if !ok {
		return "dev-untagged-g" + short, nil
	}
	n, err := git(ctx, repo, "rev-list", "--count", base+".."+sha)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("dev-%s-%s-g%s", base, n, short), nil
}

// git runs git with an argument vector (never a shell) and a time limit; it returns trimmed stdout.
func git(ctx context.Context, repo string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, GitTimeout)
	defer cancel()
	argv := append([]string{"-C", repo}, args...)
	cmd := exec.CommandContext(ctx, "git", argv...) // #nosec G204 -- fixed program, argument vector, no shell
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %w (%s)", strings.Join(args, " "), err, firstLine(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return line
}
