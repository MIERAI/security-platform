//go:build unix

package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/runner/config"
)

// pythonPrograms are the product programs the runner starts, by component, as paths in the Python tree (what
// the reference runs). A fresh map on every call.
func pythonPrograms() map[string][]string {
	return map[string][]string{
		"ledger":      {"core", "ledger.py"},
		"remediation": {"core", "remediation.py"},
		"export":      {"core", "export.py"},
		"digest":      {"core", "digest.py"},
		"notify":      {"cli", "sp.py"},
		"events":      {"events", "ship.py"},
		"scorecard":   {"scorecard", "scorecard.py"},
	}
}

// fixedArgs are the arguments a component's program always gets first (the notify job is `sp.py notify`).
func fixedArgs(component string) []string {
	if component == "notify" {
		return []string{"notify"}
	}
	return nil
}

// errNoProgram is the error class of a product program that cannot be started.
var errNoProgram = errors.New("cannot start")

// program returns the argument vector of a product program of the Python tree (what the reference runs);
// collectors are "collectors/<name>". Which implementation runs the ledger and remediation is the
// implementation switch's business (impl.go).
func (r *Runner) program(component string) ([]string, error) {
	return r.pythonProgram(component)
}

func (r *Runner) pythonProgram(component string) ([]string, error) {
	if err := r.needPython(); err != nil {
		return nil, fmt.Errorf("%w %s: %w", errNoProgram, component, err)
	}
	if name, ok := strings.CutPrefix(component, "collectors/"); ok {
		return []string{r.python, filepath.Join(r.tree, "collectors", name, "collector.py")}, nil
	}
	rel, ok := pythonPrograms()[component]
	if !ok {
		return nil, fmt.Errorf("%w %s: unknown component", errNoProgram, component)
	}
	return append([]string{r.python, filepath.Join(append([]string{r.tree}, rel...)...)}, fixedArgs(component)...), nil
}

// errNoPython is returned when the Python tree or its interpreter is needed and was not found.
var errNoPython = errors.New("the Python implementation is needed for this")

func (r *Runner) needPython() error {
	switch {
	case r.tree == "":
		return fmt.Errorf("%w: no Python tree (install sp in <tree>/bin or set SP_PY_HOME)", errNoPython)
	case r.python == "":
		return fmt.Errorf("%w: no interpreter (set SP_PYTHON)", errNoPython)
	}
	return nil
}

// bridgeOut is what runner/bridge.py prints.
type bridgeOut struct {
	RC      int    `json:"rc"`
	Note    string `json:"note"`
	Merge   bool   `json:"merge"`
	Sent    int    `json:"sent"`
	Pending *int   `json:"pending"`
	Error   string `json:"error"`
}

// bridgeTimeout bounds one bridge operation (an ingest pulls and merges a whole outbox).
const bridgeTimeout = time.Hour

// maxCapture bounds how much of a helper program's output is kept.
const maxCapture = 1 << 20

// bridge runs one operation of runner/bridge.py: the parts of the runner that are still Python only.
func (r *Runner) bridge(ctx context.Context, op string, args ...string) (bridgeOut, error) {
	if err := r.needPython(); err != nil {
		return bridgeOut{}, fmt.Errorf("runner/bridge.py: %w", err)
	}
	argv := append([]string{r.python, filepath.Join(r.tree, "runner", "bridge.py"), op, "--instance", r.inst.Path,
		"--data", r.data}, args...)
	c, err := r.capture(ctx, argv, r.environ, bridgeTimeout, true)
	if err != nil {
		return bridgeOut{}, err
	}
	var out bridgeOut
	lines := strings.Split(strings.TrimSpace(c.stdout), "\n")
	if c.rc != 0 || json.Unmarshal([]byte(lines[len(lines)-1]), &out) != nil {
		return bridgeOut{}, fmt.Errorf("bridge %s: exit %d without a result", op, c.rc)
	}
	return out, nil
}

// capture runs a helper program to completion with a time limit and returns its stdout and stderr (bounded).
// With passStderr its stderr also goes to the runner's log stream, as the Python runner's own messages did.
// captured is the outcome of a helper program.
type captured struct {
	stdout, stderr string
	rc             int
}

func (r *Runner) capture(ctx context.Context, argv, env []string, limit time.Duration, passStderr bool) (captured, error) {
	cctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	cmd := exec.CommandContext(cctx, argv[0], argv[1:]...) // #nosec G204 -- product programs, argument vector
	var so, se boundedBuffer
	so.limit, se.limit = maxCapture, maxCapture
	cmd.Env, cmd.Stdout, cmd.Stderr = env, &so, &se
	err := cmd.Run()
	if passStderr && se.Len() > 0 {
		_, _ = fmt.Fprint(r.log.w, se.String()) // the bridge's diagnostics belong in the runner log
	}
	if cctx.Err() != nil {
		return captured{stdout: so.String(), stderr: se.String()}, fmt.Errorf("%s timed out after %.0f seconds: %w", filepath.Base(argv[len(argv)-1]),
			limit.Seconds(), cctx.Err())
	}
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		return captured{}, fmt.Errorf("run %s: %w", filepath.Base(argv[0]), err)
	}
	return captured{stdout: so.String(), stderr: se.String(), rc: cmd.ProcessState.ExitCode()}, nil
}

// boundedBuffer keeps at most limit bytes: the start (where a result begins) for a small output, the tail of a
// long one is dropped. Enough for notes and the bridge's one-line result.
type boundedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	room := b.limit - b.Len()
	if room > 0 {
		if len(p) < room {
			room = len(p)
		}
		_, _ = b.Buffer.Write(p[:room]) // bytes.Buffer.Write never fails
	}
	return len(p), nil
}

// ledger merges a run directory into the ledger under the ledger lock (blocking: merges are serialized), with
// the implementation runner.implementations.ledger selects (contract §7).
func (r *Runner) ledger(ctx context.Context, runDir string) (int, string) {
	mode, bin := r.implementation(ctx, "ledger", runDir)
	if mode == implShadow {
		// the Python runner's own shadow run: it takes the ledger lock itself
		out, err := r.bridge(ctx, "ledger", "--run-dir", runDir)
		if err != nil {
			return rcInternal, failureNote(err)
		}
		return out.RC, out.Note
	}
	lk, err := acquire(filepath.Join(r.stateDir, "locks"), "ledger", true)
	if err != nil {
		return rcInternal, failureNote(err)
	}
	defer r.unlock(lk)
	var argv []string
	if mode == implGo {
		argv = []string{bin, "ledger", "merge", "--run", runDir, "--data", r.data, "--latest", r.latest, "--instance", r.inst.Path}
	} else {
		if argv, err = r.program("ledger"); err != nil {
			return 64, err.Error()
		}
		argv = append(argv, "--run", runDir, "--data", r.data, "--latest", r.latest)
	}
	c, err := r.capture(ctx, argv, r.productEnv(), 600*time.Second, false)
	if werr := os.WriteFile(filepath.Join(runDir, "ledger.log"), []byte(c.stdout+c.stderr), 0o600); werr != nil && err == nil {
		err = werr
	}
	if err != nil {
		return rcInternal, failureNote(err)
	}
	if c.rc != 0 {
		return c.rc, fmt.Sprintf("ledger rc=%d: %s", c.rc, tail(c.stderr, 200))
	}
	return 0, "ledger merged"
}

// jobEvents ships security events (events/ship.py); success = exit 0 (every source shipped).
func (r *Runner) jobEvents(ctx context.Context, j *config.Job, runDir string) (int, string) {
	if !j.Raw.Has("loki") {
		return rcInternal, "KeyError: 'loki'"
	}
	sources := j.Raw.Get("sources")
	if !config.Truthy(sources) {
		sources = []any{}
	}
	cf := filepath.Join(runDir, "events.config.json")
	if err := writeJSON(cf, map[string]any{"loki": config.Plain(j.Raw.Get("loki")), "sources": config.Plain(sources)}); err != nil {
		return rcInternal, failureNote(err)
	}
	argv, err := r.program("events")
	if err != nil {
		return 64, err.Error()
	}
	summary := filepath.Join(runDir, "events.summary.json")
	argv = append(argv, "--config", cf, "--state", filepath.Join(r.data, "state", "events", j.Name), "--summary", summary)
	rc, err := r.spawn(ctx, spawnSpec{argv: argv, env: r.jobEnv(j, runDir), timeout: j.Timeout,
		logPath: filepath.Join(runDir, "events.log"), job: j.Name})
	if err != nil {
		return rcInternal, failureNote(err)
	}
	note := eventsNote(summary)
	if rc == 0 {
		return 0, "events " + note
	}
	return rc, fmt.Sprintf("events rc=%d (%s; see events.log)", rc, note)
}

func eventsNote(summary string) string {
	m, ok := readJSONObject(summary)
	if !ok {
		return "no summary"
	}
	srcs, ok := m["sources"].(map[string]any)
	if !ok {
		return "no summary"
	}
	parts := make([]string, 0, len(srcs))
	for _, k := range sortedKeys(srcs) {
		v, _ := srcs[k].(map[string]any) // not an object: reported as failed
		if config.Truthy(v["ok"]) {
			parts = append(parts, k+": "+config.Str(v["shipped"]))
		} else {
			parts = append(parts, k+": FAILED")
		}
	}
	return strings.Join(parts, ", ")
}

// sortedKeys returns the keys of a map, sorted.
func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
