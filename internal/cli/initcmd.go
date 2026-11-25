package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/MIERAI/security-platform/internal/cli/flags"
)

// Modes of what sp init creates: the data directory holds attacker-relevant information (contract §2).
const (
	dirMode  = 0o700
	fileMode = 0o600
)

// plainYAML is a value that needs no quoting in the starter config.
var plainYAML = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// yamlScalar is s as it goes into the starter config: as is when plain, else single-quoted.
func yamlScalar(s string) string {
	if plainYAML.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func runInit(_ context.Context, s *session, a *flags.Result) (int, error) {
	arg := a.Arg("dir")
	d, err := filepath.Abs(expandUser(arg, s.env.Getenv))
	if err != nil {
		return 0, die(ExitUsage, "%s: %v", arg, err)
	}
	if derr := makePrivateDir(d); derr != nil {
		return 0, derr
	}
	p := filepath.Join(d, "instance.yaml")
	exists, err := present(p)
	if err != nil {
		return 0, err
	}
	var out strings.Builder
	if exists && !a.Bool("force") {
		fmt.Fprintf(&out, "%s exists: left as it is (--force overwrites)\n", p)
	} else {
		if err := writePrivate(p, s.starter(d, a.String("name")), true); err != nil {
			return 0, err
		}
		fmt.Fprintf(&out, "wrote %s\n", p)
	}
	if err := writePrivate(filepath.Join(d, "exceptions.yaml"),
		"# Human-approved risk acceptances. `sp explain <id>` prints a ready-to-edit entry.\nexceptions: {}\n", false); err != nil {
		return 0, err
	}
	if err := writePrivate(filepath.Join(d, ".gitignore"), "state/locks/\ncache/\n", false); err != nil {
		return 0, err
	}
	fmt.Fprintf(&out, `
Next:
  1. edit %s  (keep what you have, delete the rest)
  2. sp doctor --data %s     checks tools and permissions
  3. sp run --data %s        first scan, then: sp status / sp findings --open
This directory holds attacker-relevant information: keep it private (mode 0700, never in a public repository).
`, p, arg, arg)
	return ExitOK, emit(s.env.Stdout, out.String())
}

// makePrivateDir creates d (and its parents) private to the user, or makes an existing one private.
func makePrivateDir(d string) error {
	if fi, err := os.Stat(d); err == nil && !fi.IsDir() {
		return die(ExitUsage, "%s: exists and is not a directory", d)
	}
	if err := os.MkdirAll(d, dirMode); err != nil {
		return die(ExitUsage, "%s: %v", d, unwrapPath(err))
	}
	if err := os.Chmod(d, dirMode); err != nil {
		return die(ExitUsage, "%s: %v", d, unwrapPath(err))
	}
	return nil
}

// present reports whether path exists (a symbolic link counts, even a dangling one: it is never followed).
func present(path string) (bool, error) {
	_, err := os.Lstat(path)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	}
	return false, die(ExitUsage, "%s: %v", path, unwrapPath(err))
}

// writePrivate writes a 0600 file: atomically through a temporary file when replace is set (a symbolic link in
// its place is replaced, never followed), else only when nothing is there yet.
func writePrivate(path, content string, replace bool) error {
	if !replace {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode) // #nosec G304 -- inside the new data directory
		if errors.Is(err, fs.ErrExist) {
			return nil
		}
		if err != nil {
			return die(ExitUsage, "%s: %v", path, unwrapPath(err))
		}
		_, werr := f.WriteString(content)
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return die(ExitUsage, "%s: %v", path, unwrapPath(werr))
		}
		return nil
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".instance-*.tmp")
	if err != nil {
		return die(ExitUsage, "%s: %v", path, unwrapPath(err))
	}
	_, werr := tmp.WriteString(content)
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(tmp.Name(), path)
	}
	if werr != nil {
		if rerr := os.Remove(tmp.Name()); rerr != nil {
			werr = errors.Join(werr, rerr)
		}
		return die(ExitUsage, "%s: %v", path, unwrapPath(werr))
	}
	return nil
}

// unwrapPath drops the path an *fs.PathError repeats (the message already names it).
func unwrapPath(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

// profile is the host profile of this machine for the starter config.
func (s *session) profile() string {
	if fi, err := os.Stat("/data/data/com.termux"); err == nil && fi.IsDir() {
		return "termux"
	}
	switch s.env.GOOS {
	case "darwin":
		return "macos"
	case "windows":
		return "windows"
	}
	return "linux"
}

// starter is the starter instance config (the reference's STARTER text).
func (s *session) starter(dir, name string) string {
	if name == "" {
		name = filepath.Base(strings.TrimRight(dir, `/\`))
	}
	host, _, _ := strings.Cut(s.env.Hostname, ".")
	if host == "" {
		host = "this-machine"
	}
	return strings.NewReplacer("{name}", yamlScalar(name), "{host}", yamlScalar(strings.ToLower(host)),
		"{profile}", s.profile()).Replace(starterTemplate)
}
