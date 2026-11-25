package rundoc

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// ErrUsage marks a configuration error of the run as a whole (exit 2).
var ErrUsage = errors.New("configuration error")

// maxInstanceFile bounds the instance config read.
const maxInstanceFile = 16 << 20

// Env is everything a collector run reads from its process. Only cmd/sp/main.go fills it from the real process.
type Env struct {
	Getenv  func(string) string
	Environ []string // the inherited environment, passed to tools (kubectl, trivy, gh) as is
	Stderr  io.Writer
	Now     func() time.Time
	HTTP    *http.Client // nil: a default client (tests inject one)
}

// Clock returns env.Now, or time.Now when unset.
func (e *Env) Clock() func() time.Time {
	if e.Now != nil {
		return e.Now
	}
	return time.Now
}

// Errout returns env.Stderr, or io.Discard when unset.
func (e *Env) Errout() io.Writer {
	if e.Stderr != nil {
		return e.Stderr
	}
	return io.Discard
}

// Run is one collector run's protocol context: where it writes, what it reads.
type Run struct {
	Dir      string       // SP_RUN_DIR
	Data     string       // SP_DATA ("" when unset)
	Input    string       // SP_INPUT_DIR ("" when unset)
	Home     string       // HOME, for "~" in configured paths
	Instance *pyvalue.Map // the instance config (an empty mapping when the file holds no mapping)
	Doc      *Document
}

// Start reads the collector-protocol environment and the instance config and starts the document of a run of
// the collector `name` (SP_COLLECTOR_NAME overrides it). Missing SP_RUN_DIR / SP_INSTANCE or an unreadable
// instance is an ErrUsage error.
func Start(env *Env, name, version string) (*Run, error) {
	runDir, instPath := env.Getenv("SP_RUN_DIR"), env.Getenv("SP_INSTANCE")
	if instPath == "" {
		return nil, fmt.Errorf("%w: SP_INSTANCE not set (path to the private instance config)", ErrUsage)
	}
	if runDir == "" {
		return nil, fmt.Errorf("%w: SP_RUN_DIR not set", ErrUsage)
	}
	home := env.Getenv("HOME")
	data, err := ReadLimited(ExpandUser(instPath, home), maxInstanceFile)
	if err != nil {
		return nil, fmt.Errorf("%w: instance config unreadable: %w", ErrUsage, err)
	}
	v, err := pyvalue.DecodeYAML(data)
	if err != nil {
		return nil, fmt.Errorf("%w: the instance config is not YAML/JSON: %w", ErrUsage, err)
	}
	inst, ok := v.(*pyvalue.Map)
	if !ok {
		inst = pyvalue.NewMap() // an empty file (None in the reference): every section absent
	}
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		return nil, fmt.Errorf("create the run directory: %w", err)
	}
	if n := env.Getenv("SP_COLLECTOR_NAME"); n != "" {
		name = n
	}
	return &Run{Dir: runDir, Data: env.Getenv("SP_DATA"), Input: env.Getenv("SP_INPUT_DIR"), Home: home,
		Instance: inst, Doc: New(name, version, env.Getenv("SP_INSTANCE_NAME"), env.Clock())}, nil
}

// ExitStatus maps a run's error to the collector-protocol exit status: 0 done, 2 configuration, 1 otherwise.
func ExitStatus(err error) int {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, ErrUsage):
		return 2
	default:
		return 1
	}
}
