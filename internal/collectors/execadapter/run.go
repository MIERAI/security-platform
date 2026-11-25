package execadapter

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/collectors/pytext"
)

const (
	maxStdout = 256 << 20 // a package inventory of a large host is a few MB
	maxStderr = 64 << 10  // only its end is ever reported
	// drainDelay is how long, after the process group was stopped, the rest of its output is still read (the
	// Python adapter's communicate(timeout=5)).
	drainDelay    = 5 * time.Second
	statusNoStart = 126
)

// Statuses the adapter gives a run itself.
const (
	StatusTimeout  = 124 // stopped by its time limit
	StatusNotFound = 127 // the program is not installed
)

// job is one program run: its argument vector, standard input, time limit, and whether output printed before the
// limit is kept.
type job struct {
	argv    []string
	stdin   string
	timeout time.Duration
	partial bool
}

// run starts the job's program (looked up on environ's PATH) in its own process group and waits at most its time
// limit.
func run(ctx context.Context, environ []string, j job) (Result, error) {
	argv, stdin, timeout, partial := j.argv, j.stdin, j.timeout, j.partial
	if len(argv) == 0 {
		return Result{}, ErrConfig
	}
	path, ok := lookPath(argv[0], environ)
	if !ok {
		return Result{RC: StatusNotFound, Err: argv[0] + ": not found"}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, argv[1:]...) // #nosec G204 -- an argument vector, no shell
	cmd.Args[0] = argv[0]
	cmd.Env = environ
	cmd.Stdin = strings.NewReader(stdin)
	out := &capBuffer{limit: maxStdout}
	errBuf := &capBuffer{limit: maxStderr, keepTail: true}
	cmd.Stdout, cmd.Stderr = out, errBuf
	ownGroup(cmd)
	cmd.Cancel = func() error { return killGroup(cmd) }
	cmd.WaitDelay = drainDelay
	err := cmd.Run()
	if ctx.Err() != nil && (err != nil || cmd.ProcessState == nil || !cmd.ProcessState.Success()) {
		res := Result{RC: StatusTimeout, Err: "timeout"}
		if partial {
			res.Out = pytext.Decode(out.Bytes())
		}
		return res, nil
	}
	if out.overflow {
		return Result{}, ErrOutputTooLarge
	}
	res := Result{Out: pytext.Decode(out.Bytes()), Err: pytext.Decode(errBuf.Bytes())}
	var exitErr *exec.ExitError
	switch {
	case err == nil, errors.Is(err, exec.ErrWaitDelay):
		res.RC = exitStatus(cmd.ProcessState)
	case errors.As(err, &exitErr):
		res.RC = exitStatus(exitErr.ProcessState)
	default:
		return Result{RC: statusNoStart, Err: argv[0] + ": cannot run: " + err.Error()}, nil
	}
	return res, nil
}

// capBuffer keeps at most limit bytes: the first ones (overflow is then recorded), or the last ones (keepTail).
type capBuffer struct {
	buf      bytes.Buffer
	limit    int
	keepTail bool
	overflow bool
}

func (c *capBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if c.keepTail {
		c.buf.Write(p)
		if extra := c.buf.Len() - c.limit; extra > 0 {
			c.buf.Next(extra)
		}
		return n, nil
	}
	if room := c.limit - c.buf.Len(); len(p) > room {
		p = p[:max(room, 0)]
		c.overflow = true
	}
	c.buf.Write(p)
	return n, nil
}

// Bytes is what was kept.
func (c *capBuffer) Bytes() []byte { return c.buf.Bytes() }

// lookPath finds a program the way execvp does, on the PATH of environ (not of this process): a name with a path
// separator is used as it is; otherwise the first executable regular file in an absolute PATH directory (relative
// entries such as "." are never searched). Windows: the extensions of PATHEXT too.
func lookPath(name string, environ []string) (string, bool) {
	if strings.ContainsRune(name, '/') || runtime.GOOS == "windows" && strings.ContainsAny(name, `\:`) {
		return name, true
	}
	exts := []string{""}
	if runtime.GOOS == "windows" {
		exts = append(exts, strings.Split(strings.ToLower(envValue(environ, "PATHEXT", ".COM;.EXE;.BAT;.CMD")), ";")...)
	}
	for _, dir := range filepath.SplitList(envValue(environ, "PATH", "/bin:/usr/bin")) {
		if !filepath.IsAbs(dir) {
			continue
		}
		for _, ext := range exts {
			p := filepath.Join(dir, name+ext)
			if isExecutable(p) {
				return p, true
			}
		}
	}
	return "", false
}

func envValue(environ []string, key, def string) string {
	val, found := def, false
	for _, kv := range environ {
		k, v, ok := strings.Cut(kv, "=")
		if ok && (k == key || runtime.GOOS == "windows" && strings.EqualFold(k, key)) {
			val, found = v, true
		}
	}
	if !found {
		return def
	}
	return val
}

func isExecutable(p string) bool {
	st, err := os.Stat(p)
	if err != nil || !st.Mode().IsRegular() {
		return false
	}
	return runtime.GOOS == "windows" || st.Mode().Perm()&0o111 != 0
}
