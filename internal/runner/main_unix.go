//go:build unix

package runner

import (
	"context"
	"errors"
	"fmt"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/MIERAI/security-platform/internal/delegate"
	"github.com/MIERAI/security-platform/internal/pyhome"
)

// Main runs `sp runner ...` and returns its exit status.
func Main(ctx context.Context, env Env) int {
	for _, a := range env.Args {
		if a == "-h" || a == "--help" {
			_, _ = fmt.Fprint(env.Stdout, Usage) // nothing else to report if stdout is gone
			return ExitOK
		}
	}
	a, err := parseArgs(env.Args)
	if err != nil {
		_, _ = fmt.Fprintf(env.Stderr, "%ssp runner: %v\n", Usage, err) // the exit status says it all
		return ExitUsage
	}
	switch a.cmd {
	case "version":
		_, _ = fmt.Fprintln(env.Stdout, Version) // see above
		return ExitOK
	case "serve-metrics":
		return serveMetrics(ctx, env, a)
	}
	syscall.Umask(0o077) // every file the runner and its jobs write is private to the user (contract §4)
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer stop()
	clock := NewClock(a.now, env.Wall)
	log := &Logger{w: env.Stderr, clock: clock, loc: time.Local}
	r, err := New(options(env, a, clock, log))
	if err != nil {
		log.Printf("cannot start: %v", err)
		return ExitNoConfig
	}
	return dispatch(ctx, env, a, r)
}

func options(env Env, a args, clock *Clock, log *Logger) Options {
	o := Options{Instance: a.instance, Data: a.data, Exe: env.Executable, Environ: env.Environ, Clock: clock,
		Log: log, Loc: time.Local, Wall: env.Wall}
	if home, err := pyhome.Locate(env.Getenv, env.Executable); err == nil {
		o.Tree = home.Dir
	}
	if py, err := delegate.Interpreter(env.Getenv); err == nil {
		o.Python = py
	}
	return o
}

func dispatch(ctx context.Context, env Env, a args, r *Runner) int {
	if bad := r.Unknown(a.jobs); len(bad) > 0 {
		_, _ = fmt.Fprintf(env.Stderr, "sp runner: not in runner.jobs: %s\n", strings.Join(bad, ", ")) // exit status says it
		return ExitUsage
	}
	switch a.cmd {
	case "status":
		out, err := r.Status()
		if err != nil {
			r.log.Printf("status: %v", err)
			return 1
		}
		_, _ = fmt.Fprintf(env.Stdout, "%s\n", out) // a closed stdout cannot be reported anywhere
		return ExitOK
	case "metrics":
		if !r.publishLogged(ctx) {
			return 1
		}
		return ExitOK
	case "run":
		return r.Run(ctx, a.jobs)
	default: // tick
		r.Tick(ctx, a.jobs)
		return ExitOK
	}
}

// errNoServer is returned when the exporter cannot listen.
var errNoServer = errors.New("serve-metrics")
