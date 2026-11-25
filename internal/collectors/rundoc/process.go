package rundoc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Process exit statuses the collectors record like the Python implementations: 124 timed out, 127 not found.
const (
	RCTimeout  = 124
	RCNotFound = 127
)

// waitDelay is how long the output pipes may stay open after the process was killed.
const waitDelay = 5 * time.Second

// Cmd is one child process: an argument vector (never a shell command line), its exact environment, an optional
// standard input, a time limit and how much of each output stream is kept.
type Cmd struct {
	Argv    []string
	Env     []string // the child's whole environment ("K=V")
	Stdin   io.Reader
	Timeout time.Duration
	MaxOut  int64 // bytes of stdout kept (default 64 MiB); stderr keeps at most 1 MiB
	Partial bool  // on timeout, keep the output printed before the process group was stopped
}

// Result is a finished child process.
type Result struct {
	RC             int // exit status; RCTimeout, RCNotFound, or 126 when it could not be started
	Stdout, Stderr string
	Truncated      bool // stdout was longer than MaxOut
	Signal         int  // the signal that ended the process (RC is then 1), 0 otherwise
}

// Exec runs c in its own process group (killed as a whole on timeout), found on the PATH of c.Env.
func Exec(ctx context.Context, c *Cmd) Result {
	prog, err := LookPath(c.Argv[0], c.Env)
	if err != nil {
		return Result{RC: RCNotFound, Stderr: filepath.Base(c.Argv[0]) + ": not found"}
	}
	if c.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.Timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, prog, c.Argv[1:]...) // #nosec G204 -- argument vector, no shell; program from PATH or config
	cmd.Env, cmd.Stdin, cmd.WaitDelay = c.Env, c.Stdin, waitDelay
	setGroup(cmd)
	maxOut := c.MaxOut
	if maxOut <= 0 {
		maxOut = 64 << 20
	}
	var out, errb bytes.Buffer
	so := &capped{b: &out, n: maxOut}
	cmd.Stdout, cmd.Stderr = so, &capped{b: &errb, n: 1 << 20}
	err = cmd.Run()
	if ctx.Err() != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		res := Result{RC: RCTimeout, Stderr: "timeout"}
		if c.Partial {
			res.Stdout, res.Truncated = out.String(), so.over
		}
		return res
	}
	res := Result{Stdout: out.String(), Stderr: errb.String(), Truncated: so.over}
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		res.RC = exitErr.ExitCode()
		if res.RC < 0 {
			res.RC, res.Signal = 1, signalOf(exitErr.ProcessState) // ended by a signal
		}
	default:
		res.RC, res.Stderr = 126, fmt.Sprintf("%s: cannot start: %v", filepath.Base(prog), errors.Unwrap(err))
	}
	return res
}

// LookPath finds a program on the PATH of env (absolute directories only: a relative PATH entry such as "." is
// never searched). A name with a slash is used as it is.
func LookPath(name string, env []string) (string, error) {
	if strings.ContainsRune(name, '/') || strings.ContainsRune(name, filepath.Separator) {
		return name, nil
	}
	for _, dir := range filepath.SplitList(Lookup(env, "PATH")) {
		if !filepath.IsAbs(dir) {
			continue
		}
		for _, p := range candidates(filepath.Join(dir, name)) {
			if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && executable(fi) {
				return p, nil
			}
		}
	}
	return "", fmt.Errorf("%s: %w", name, exec.ErrNotFound)
}

// Lookup is the value of key in an environment list ("" when absent; the last one wins).
func Lookup(env []string, key string) string {
	v := ""
	for _, kv := range env {
		if k, val, ok := strings.Cut(kv, "="); ok && k == key {
			v = val
		}
	}
	return v
}

// WithEnv returns env with the given variables set (replacing earlier values).
func WithEnv(env []string, set map[string]string) []string {
	out := make([]string, 0, len(env)+len(set))
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		if _, replaced := set[k]; !replaced {
			out = append(out, kv)
		}
	}
	for _, k := range sortedKeys(set) {
		out = append(out, k+"="+set[k])
	}
	return out
}

// capped keeps at most n bytes of a stream and remembers whether more came.
type capped struct {
	b    *bytes.Buffer
	n    int64
	over bool
}

func (c *capped) Write(p []byte) (int, error) {
	room := c.n - int64(c.b.Len())
	if room < int64(len(p)) {
		c.over = true
	}
	if room > 0 {
		c.b.Write(p[:min(int64(len(p)), room)])
	}
	return len(p), nil
}
