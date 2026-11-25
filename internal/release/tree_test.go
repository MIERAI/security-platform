package release

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
)

// newRepo makes a repository with an old release (base, if not empty), then a newer commit carrying tags.
func newRepo(t *testing.T, base string, tags ...string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	emptyConfig := filepath.Join(t.TempDir(), "gitconfig") // not os.DevNull: "NUL" is not a file for git on Windows
	if err := os.WriteFile(emptyConfig, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+emptyConfig, "GIT_CONFIG_NOSYSTEM=1",
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q", "-b", "main")
	if base != "" {
		run("commit", "-q", "--allow-empty", "-m", "old")
		run("tag", "-a", "-m", base, base)
	}
	run("commit", "-q", "--allow-empty", "-m", "one")
	run("commit", "-q", "--allow-empty", "-m", "two")
	for _, tag := range tags {
		run("tag", "-a", "-m", tag, tag)
	}
	return dir
}

func TestForRef(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		base string
		tags []string
		want string // a regular expression
	}{
		{"product tag among component tags", "", []string{"core/v0.8.0", "v0.3.0", "runner/v0.9.0"}, `^v0\.3\.0$`},
		{"highest of several", "", []string{"v0.3.0-rc.1", "v0.3.0", "v0.2.9"}, `^v0\.3\.0$`},
		{"component tags only, after a release", "v0.2.0", []string{"core/v0.8.0"}, `^dev-v0\.2\.0-2-g[0-9a-f]{7}$`},
		{"never tagged", "", nil, `^dev-untagged-g[0-9a-f]{7}$`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			repo := newRepo(t, tc.base, tc.tags...)
			got, err := ForRef(t.Context(), repo, "HEAD")
			if err != nil || !regexp.MustCompile(tc.want).MatchString(got) {
				t.Fatalf("ForRef = %q, %v; want %s", got, err, tc.want)
			}
			if d := Describe(t.Context(), repo); d != got {
				t.Errorf("Describe = %q, want %q", d, got)
			}
		})
	}
}

func TestForRefRejectsOptions(t *testing.T) {
	t.Parallel()
	for _, ref := range []string{"", "--output=/tmp/x", "-h"} {
		if _, err := ForRef(t.Context(), t.TempDir(), ref); err == nil {
			t.Errorf("ForRef(%q) accepted an option as a ref", ref)
		}
	}
}

func TestDescribe(t *testing.T) {
	t.Parallel()
	installed := t.TempDir()
	if err := os.WriteFile(filepath.Join(installed, FileName), []byte("version=v0.3.0\ncommit=abc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	noVersion := t.TempDir()
	if err := os.WriteFile(filepath.Join(noVersion, FileName), []byte("commit=abc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	brokenGit := t.TempDir()
	if err := os.WriteFile(filepath.Join(brokenGit, ".git"), []byte("gitdir: /nonexistent\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct{ name, tree, want string }{
		{"installed tree", installed, "v0.3.0"},
		{"release file without version", noVersion, Unknown},
		{"plain directory", t.TempDir(), Unknown},
		{"broken checkout", brokenGit, Unknown},
		{"missing directory", filepath.Join(t.TempDir(), "nope"), Unknown},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := Describe(t.Context(), tc.tree); got != tc.want {
				t.Errorf("Describe = %q, want %q", got, tc.want)
			}
		})
	}
}
