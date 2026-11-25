package cloud

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/cloud/dyn"
)

const (
	maxProcessOutput = 16 << 20 // stdout/stderr kept of an engine (its results go to files)
	maxEngineOutput  = 1 << 30  // an engine's result file (a large account's Prowler output)
	maxImportFile    = 1 << 30  // a native service export
	waitDelay        = 30 * time.Second
)

// processResult is an engine process's exit status (127 not installed, 124 timed out) and output.
type processResult struct {
	rc             int
	stdout, stderr string
}

// runProcess runs argv (no shell) with exactly env, in cwd, killed after timeout.
func runProcess(ctx context.Context, argv []string, env map[string]string, cwd string, timeout time.Duration) processResult {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) // #nosec G204 -- engine paths come from the operator's instance config; no shell
	cmd.Env = envList(env)
	cmd.Dir = cwd
	cmd.WaitDelay = waitDelay
	var out, errb bytes.Buffer
	cmd.Stdout = &capped{b: &out, n: maxProcessOutput}
	cmd.Stderr = &capped{b: &errb, n: maxProcessOutput}
	err := cmd.Run()
	if ctx.Err() != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return processResult{rc: 124, stderr: fmt.Sprintf("timed out after %ds", int(timeout.Seconds()))}
	}
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return processResult{rc: 0, stdout: out.String(), stderr: errb.String()}
	case errors.As(err, &exitErr):
		return processResult{rc: exitErr.ExitCode(), stdout: out.String(), stderr: errb.String()}
	default:
		return processResult{rc: 127, stderr: filepath.Base(argv[0]) + " not installed"}
	}
}

func envList(env map[string]string) []string {
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = k + "=" + env[k]
	}
	return out
}

// capped keeps at most n bytes of a stream.
type capped struct {
	b *bytes.Buffer
	n int
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.n - c.b.Len(); room > 0 {
		c.b.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

// lastLine is the last non-empty line of the first non-empty text (Python: (a.strip().splitlines() or ...)[-1]).
func lastLine(texts ...string) string {
	for _, t := range texts {
		if lines := strings.Split(strings.TrimSpace(t), "\n"); strings.TrimSpace(t) != "" {
			return strings.TrimRight(lines[len(lines)-1], "\r")
		}
	}
	return ""
}

var durationRE = regexp.MustCompile(`^(\d+)([smhd]?)$`)

// Seconds parses a duration like "3h", "10m", "90" (seconds), or returns def.
func Seconds(v any, def int) int {
	if v == nil {
		return def
	}
	m := durationRE.FindStringSubmatch(strings.TrimSpace(dyn.Str(v)))
	if m == nil {
		return def
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return def
	}
	unit := map[string]int{"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m[2]]
	return n * unit
}

// readLimited reads a whole file of at most limit bytes.
func readLimited(path string, limit int64) (data []byte, err error) {
	f, err := os.Open(path) // #nosec G304 -- engine output / export paths from the instance config or the run's own directory
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			data, err = nil, fmt.Errorf("close: %w", cerr)
		}
	}()
	data, err = io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, errFileTooLarge
	}
	return data, nil
}

var errFileTooLarge = errors.New("file too large")
