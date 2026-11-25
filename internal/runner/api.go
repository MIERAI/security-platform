package runner

import (
	"io"
	"time"
)

// Exit statuses of `sp runner`.
const (
	ExitOK       = 0
	ExitUsage    = 2  // as argparse
	ExitNoConfig = 78 // the runner cannot start (unreadable instance): contract §1
)

// Usage is the command line of `sp runner` (contract §1). Jobs are positional (RUNNER-D3: there is no --only).
const Usage = `usage: sp runner tick    --instance F --data D [--now EPOCH] [JOB ...]   run whatever is due, then publish; exit 0
       sp runner run     --instance F --data D [JOB ...]                 run these jobs now (all when none); exit = max rc
       sp runner status  --instance F --data D [--now EPOCH]             the job states as one JSON object
       sp runner metrics --instance F --data D [--now EPOCH]             (re)publish the metrics
       sp runner serve-metrics --dir DIR [--port 9851]                   HTTP GET /metrics = every DIR/*.prom
       sp runner version                                                 the runner's version
`

// Env is everything `sp runner` takes from its process.
type Env struct {
	Args       []string // after "runner"
	Stdout     io.Writer
	Stderr     io.Writer
	Getenv     func(string) string
	Environ    []string
	Executable string
	Wall       func() time.Time
}
