package rundoc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/pyvalue"
	"github.com/MIERAI/security-platform/internal/textsafe"
)

// MaxInstanceFile bounds the instance config read.
const MaxInstanceFile = 16 << 20

// Env is everything a collector run reads from its process.
type Env struct {
	Getenv func(string) string
	Stderr io.Writer
	Now    func() time.Time
}

// Home is the user's home directory for "~" in configured paths (HOME, else USERPROFILE).
func (e Env) Home() string {
	if h := e.Getenv("HOME"); h != "" {
		return h
	}
	return e.Getenv("USERPROFILE")
}

// ErrUsage marks a configuration error of the run as a whole (exit 2).
var ErrUsage = errors.New("configuration error")

// Run is one started collector run: its instance config and its document.
type Run struct {
	Env      Env
	Instance *pyvalue.Map
	Doc      *Document
}

// Start reads SP_INSTANCE and SP_RUN_DIR (collector protocol §2) and starts the document of collector name
// (SP_COLLECTOR_NAME overrides it).
func Start(env Env, name, version string) (*Run, error) {
	instPath, runDir := env.Getenv("SP_INSTANCE"), env.Getenv("SP_RUN_DIR")
	if instPath == "" {
		return nil, fmt.Errorf("%w: SP_INSTANCE not set (path to the private instance config)", ErrUsage)
	}
	if runDir == "" {
		return nil, fmt.Errorf("%w: SP_RUN_DIR not set", ErrUsage)
	}
	inst, err := LoadConfig(ExpandUser(instPath, env.Home()))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUsage, err)
	}
	if err := os.MkdirAll(runDir, 0o750); err != nil {
		return nil, fmt.Errorf("create the run directory: %w", err)
	}
	if n := env.Getenv("SP_COLLECTOR_NAME"); n != "" {
		name = n
	}
	return &Run{Env: env, Instance: inst, Doc: New(name, version, env.Getenv("SP_INSTANCE_NAME"), runDir, env.Now)}, nil
}

// LoadConfig reads a YAML or JSON mapping as the Python implementation does (PyYAML safe_load, YAML 1.1 typing);
// an empty document is an empty mapping.
func LoadConfig(path string) (*pyvalue.Map, error) {
	data, err := ReadLimited(path, MaxInstanceFile)
	if err != nil {
		return nil, fmt.Errorf("config unreadable: %w", err)
	}
	v, err := pyvalue.DecodeYAML(data)
	if err != nil {
		return nil, fmt.Errorf("config is not YAML/JSON: %w", err)
	}
	switch m := v.(type) {
	case *pyvalue.Map:
		return m, nil
	case nil:
		return pyvalue.NewMap(), nil
	default:
		return nil, errors.New("config is not a mapping")
	}
}

// ErrTooLarge is returned for a file over its size limit.
var ErrTooLarge = errors.New("file too large")

// ReadLimited reads at most limit bytes of a file; a larger file is an error.
func ReadLimited(path string, limit int64) (data []byte, err error) {
	f, err := os.Open(filepath.Clean(path))
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
		return nil, fmt.Errorf("%w (over %d bytes)", ErrTooLarge, limit)
	}
	return data, nil
}

// ExpandUser is os.path.expanduser for "~" and "~/..." (other users' "~name" stay as they are).
func ExpandUser(p, home string) string {
	if home == "" {
		return p
	}
	if p == "~" {
		return home
	}
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		return filepath.Join(home, p[2:])
	}
	return p
}

// Finish writes the document and prints the SDK's summary line on stderr.
func (r *Run) Finish() error {
	if err := r.Doc.Write(); err != nil {
		return err
	}
	f, a, g := r.Doc.Counts()
	_, _ = fmt.Fprintf(r.Env.Stderr, "[%s %s] findings=%d assets=%d gaps=%d\n", r.Doc.Name, r.Doc.Version, f, a, g) // the document is written: a lost summary line changes nothing
	return nil
}

// Main runs a collector's collect function as `sp <collector> collect` and returns the exit status: 0 done,
// 1 failed, 2 usage or configuration error.
func Main(ctx context.Context, env Env, args []string, prog string, collect func(context.Context, Env) error) int {
	if len(args) != 1 || args[0] != "collect" {
		_, _ = fmt.Fprintf(env.Stderr, "usage: sp %s collect    (collector protocol: SP_RUN_DIR, SP_INSTANCE, ...)\n", prog) // the status says it too
		return 2
	}
	err := collect(ctx, env)
	if err == nil {
		return 0
	}
	_, _ = fmt.Fprintln(env.Stderr, "sp "+prog+" collect: "+textsafe.Line(err.Error())) // the status says it too
	if errors.Is(err, ErrUsage) {
		return 2
	}
	return 1
}
