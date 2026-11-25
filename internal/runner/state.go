//go:build unix

package runner

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"

	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// StateSchema is the schema of state/runner/<job>.json.
const StateSchema = "security-platform/runner-state/v1"

// maxStateFile bounds how much of a state file is read.
const maxStateFile = 4 << 20

// State is one job's state file: every key is kept as read, so fields written by another implementation or a
// newer version survive (contract: unknown fields are ignored and preserved).
type State map[string]any

// NewState is the state of a job that never ran.
func NewState(job string) State {
	return State{"schema": StateSchema, "job": job, "runs_total": int64(0), "failures_total": int64(0)}
}

// Int returns an integer field, truncating a float, or def when absent or not a number.
func (s State) Int(key string, def int64) int64 {
	v, ok := num(s[key])
	if !ok {
		return def
	}
	return int64(v)
}

// Has reports whether a numeric field is present.
func (s State) Has(key string) bool {
	_, ok := num(s[key])
	return ok
}

// Float returns a numeric field.
func (s State) Float(key string) (float64, bool) {
	return num(s[key])
}

func num(v any) (float64, bool) {
	switch x := v.(type) {
	case int64:
		return float64(x), true
	case float64:
		return x, !math.IsInf(x, 0) && !math.IsNaN(x)
	case int:
		return float64(x), true
	default:
		return 0, false
	}
}

// readFile reads a file of at most limit bytes.
func readFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- paths are built from the data directory and job names
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", filepath.Base(path), err)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", filepath.Base(path), err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("read %s: %w", filepath.Base(path), errTooLarge)
	}
	return data, nil
}

var errTooLarge = errors.New("file too large")

// readJSONObject reads a JSON object file; a missing, unreadable or malformed file gives ok=false.
func readJSONObject(path string) (map[string]any, bool) {
	data, err := readFile(path, maxStateFile)
	if err != nil {
		return nil, false
	}
	v, err := pyvalue.DecodeJSON(data)
	if err != nil {
		return nil, false
	}
	m, ok := fromPy(v).(map[string]any)
	return m, ok
}

// writeJSON writes v atomically (a temporary file in the same directory, then rename) as Python's
// json.dump(v, indent=1, sort_keys=True).
func writeJSON(path string, v any) error {
	data, err := pyvalue.EncodeJSON(toPy(v), true)
	if err != nil {
		return fmt.Errorf("encode %s: %w", filepath.Base(path), err)
	}
	return writeAtomic(path, data, 0o600)
}

// writeAtomic replaces path with data: readers see the old or the new content, never a partial file.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	name := tmp.Name()
	_, werr := tmp.Write(data)
	if werr == nil {
		werr = tmp.Chmod(mode)
	}
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(name, path)
	}
	if werr != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), errors.Join(werr, removeIfExists(name)))
	}
	return nil
}

func (r *Runner) statePath(job string) string {
	return filepath.Join(r.stateDir, job+".json")
}

// LoadState reads a job's state; a missing or unreadable file is a job that never ran.
func (r *Runner) LoadState(job string) State {
	m, ok := readJSONObject(r.statePath(job))
	if !ok {
		return NewState(job)
	}
	return State(m)
}

// SaveState writes a job's state atomically.
func (r *Runner) SaveState(job string, st State) error {
	return writeJSON(r.statePath(job), map[string]any(st))
}

// removeIfExists removes a file; one that is already gone is not an error.
func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", filepath.Base(path), err)
	}
	return nil
}

// glob lists the files matching a pattern, sorted (the patterns used here are constant and valid).
func glob(pattern string) []string {
	m, err := filepath.Glob(pattern)
	if err != nil {
		return nil
	}
	sort.Strings(m)
	return m
}

// toPy converts plain Go maps and integers to the document model of pyvalue (whose encoder writes exactly what
// Python's json.dump(v, indent=1, sort_keys=True) writes).
func toPy(v any) any {
	switch x := v.(type) {
	case map[string]any:
		m := pyvalue.NewMap()
		for k, e := range x {
			m.Set(k, toPy(e))
		}
		return m
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = toPy(e)
		}
		return out
	case int:
		return int64(x)
	default:
		return v
	}
}

// fromPy converts decoded mappings to plain Go maps (key order does not matter: files are written sorted).
func fromPy(v any) any {
	switch x := v.(type) {
	case *pyvalue.Map:
		out := make(map[string]any, x.Len())
		for _, k := range x.Keys() {
			out[k] = fromPy(x.Value(k))
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = fromPy(e)
		}
		return out
	default:
		return v
	}
}
