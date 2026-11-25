// Package collkit is the frame every Go collector runs in (contracts/collector-protocol): the environment it is
// given, the instance config read as the Python SDK reads it (YAML 1.1 through pyvalue), per-asset scope, the
// findings document and the exit statuses (0 written, 1 failed, 2 usage or configuration error).
package collkit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/collectors/spdoc"
	"github.com/MIERAI/security-platform/internal/ledger/fileio"
	"github.com/MIERAI/security-platform/internal/pyvalue"
	"github.com/MIERAI/security-platform/internal/textsafe"
)

// Exit statuses of a collector run.
const (
	ExitOK     = 0
	ExitFailed = 1
	ExitUsage  = 2
)

const maxInstanceFile = 16 << 20

// ErrConfig is a usage or configuration error (exit status 2).
var ErrConfig = errors.New("configuration error")

// GapError is a target the run cannot cover: it becomes a coverage gap with Reason, it does not fail the run.
type GapError struct{ Reason string }

func (e *GapError) Error() string { return e.Reason }

// Gap returns a GapError.
func Gap(reason string) error { return &GapError{Reason: reason} }

// AsGap is the reason of the GapError in err's chain.
func AsGap(err error) (string, bool) {
	var g *GapError
	if errors.As(err, &g) {
		return g.Reason, true
	}
	return "", false
}

// Env is what a collector reads from its process, injected.
type Env struct {
	Getenv  func(string) string
	Environ []string // the environment of the programs the collector starts
	Stderr  io.Writer
	Now     func() time.Time
}

// Run is one collector run: its instance config, document and directories.
type Run struct {
	Env
	Inst *pyvalue.Map
	Doc  *spdoc.Document
	Dir  string // SP_RUN_DIR
	Data string // SP_DATA, "." when unset (as the Python collectors)
}

// Main runs body inside the collector frame and returns the exit status: it reads SP_RUN_DIR and SP_INSTANCE,
// starts the document under SP_COLLECTOR_NAME or name, and writes it when body succeeds.
func Main(ctx context.Context, env Env, name, version string, body func(context.Context, *Run) error) int {
	r, err := start(env, name, version)
	if err == nil {
		err = body(ctx, r)
	}
	if err == nil {
		err = r.Doc.Write(r.Dir)
	}
	if err != nil {
		_, _ = fmt.Fprintln(env.Stderr, name+": "+textsafe.Line(err.Error())) // the exit status says it too
		if errors.Is(err, ErrConfig) {
			return ExitUsage
		}
		return ExitFailed
	}
	_, _ = fmt.Fprintln(env.Stderr, r.Doc.Summary()) // informational; the document is the result
	return ExitOK
}

func start(env Env, name, version string) (*Run, error) {
	dir := env.Getenv("SP_RUN_DIR")
	if dir == "" {
		return nil, fmt.Errorf("%w: SP_RUN_DIR not set", ErrConfig)
	}
	inst, err := loadInstance(env.Getenv)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create the run directory: %w", err)
	}
	if n := env.Getenv("SP_COLLECTOR_NAME"); n != "" {
		name = n
	}
	data := env.Getenv("SP_DATA")
	if data == "" {
		data = "."
	}
	return &Run{Env: env, Inst: inst, Dir: dir, Data: data,
		Doc: spdoc.New(name, version, env.Getenv("SP_INSTANCE_NAME"), env.Now)}, nil
}

func loadInstance(getenv func(string) string) (*pyvalue.Map, error) {
	p := getenv("SP_INSTANCE")
	if p == "" {
		return nil, fmt.Errorf("%w: SP_INSTANCE not set (path to the private instance.yaml)", ErrConfig)
	}
	data, err := fileio.Read(ExpandUser(p, getenv("HOME")), maxInstanceFile)
	if err != nil {
		return nil, fmt.Errorf("%w: instance config unreadable: %w", ErrConfig, err)
	}
	v, err := pyvalue.DecodeYAML(data)
	if err != nil {
		return nil, fmt.Errorf("%w: instance config is not YAML/JSON: %w", ErrConfig, err)
	}
	m, ok := v.(*pyvalue.Map)
	if !ok {
		return nil, fmt.Errorf("%w: instance config is not a mapping", ErrConfig)
	}
	return m, nil
}

// ExpandUser is os.path.expanduser for "~" and "~/..." (the home of the running user).
func ExpandUser(p, home string) string {
	if home != "" && (p == "~" || strings.HasPrefix(p, "~/")) {
		return filepath.Join(home, p[1:])
	}
	return p
}

// List is the list at key of m: absent or null is empty, anything but a list a configuration error.
func List(m *pyvalue.Map, key string) ([]any, error) {
	switch v := m.Value(key).(type) {
	case nil:
		return nil, nil
	case []any:
		return v, nil
	default:
		return nil, fmt.Errorf("%w: %s must be a list, not %s", ErrConfig, key, pyvalue.TypeName(v))
	}
}

// Targets is the list at key of the instance with every element a mapping that has `nameKey`.
func Targets(inst *pyvalue.Map, key, nameKey string) ([]*pyvalue.Map, error) {
	items, err := List(inst, key)
	if err != nil {
		return nil, err
	}
	out := make([]*pyvalue.Map, len(items))
	for i, it := range items {
		m, ok := it.(*pyvalue.Map)
		if !ok || !m.Has(nameKey) {
			return nil, fmt.Errorf("%w: %s[%d] needs %s", ErrConfig, key, i, nameKey)
		}
		out[i] = m
	}
	return out, nil
}

// InScope is false when the instance's `scope:` limits the asset `name` to other collectors (it is then skipped,
// not a gap): the first entry whose `names` holds name decides.
func InScope(inst *pyvalue.Map, name any, collector string) bool {
	scopes, _ := inst.Value("scope").([]any) // absent or not a list: no per-asset scope
	for _, s := range scopes {
		sm, ok := s.(*pyvalue.Map)
		if !ok {
			continue
		}
		if in, err := pyvalue.In(name, orEmpty(sm.Value("names"))); err == nil && in {
			ok, err := pyvalue.In(collector, orEmpty(sm.Value("scope")))
			return err == nil && ok
		}
	}
	return true
}

func orEmpty(v any) any {
	if !pyvalue.Truthy(v) {
		return []any{}
	}
	return v
}

// SafeFileName reports whether a configured name can be a file name inside the run directory (evidence files are
// named after hosts): no path separators, not "." or "..", no NUL.
func SafeFileName(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.ContainsAny(s, "/\\\x00")
}
