// Package shim is the sp command line during the move from Python to Go: a subcommand with a Go implementation
// runs here, every other one is handed to the Python implementation (cli/sp.py) with its arguments, standard
// streams, environment and exit code unchanged.
package shim

import (
	"context"
	"fmt"
	"io"
	"sort"

	"github.com/MIERAI/security-platform/internal/buildinfo"
	"github.com/MIERAI/security-platform/internal/delegate"
	"github.com/MIERAI/security-platform/internal/pyhome"
)

// Exit statuses of the shim itself (a delegated command's status is passed through unchanged).
const (
	ExitOK          = 0
	ExitUsage       = 2   // as argparse
	ExitCannotRun   = 126 // the Python implementation was found but could not be started
	ExitNotFound    = 127 // no Python implementation or interpreter to delegate to
	versionFlagName = "--version"
)

// Env is everything the shim reads from its process, injected so that tests need no global state.
type Env struct {
	Args       []string // after the program name
	Stdin      io.Reader
	Stdout     io.Writer
	Stderr     io.Writer
	Getenv     func(string) string
	Environ    []string
	Executable string // os.Executable(); "" when unknown
	Build      buildinfo.Info
	// Exec runs a delegated command; delegate.Replace in production. It returns the exit status.
	Exec func(context.Context, delegate.Spec) (int, error)
}

type command func(ctx context.Context, env Env, args []string) int

// goCommands are the subcommands implemented in Go. A fresh map on every call.
func goCommands() map[string]command {
	return map[string]command{
		"cloud":         runCloud,
		"host":          runHost,
		"host-sbom":     runHostSBOM,
		"identity":      runIdentity,
		"k8s":           runK8s,
		"ledger":        runLedger,
		"version":       runVersion,
		"runner":        runRunner,
		"scorecard":     runScorecard,
		"secrets-files": runSecretsFiles,
		"vuln-intel":    runVulnIntel,
	}
}

// GoSubcommands lists the subcommands implemented in Go, sorted.
func GoSubcommands() []string {
	names := make([]string, 0, len(goCommands()))
	for n := range goCommands() {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Main runs sp and returns its exit status.
func Main(ctx context.Context, env Env) int {
	if len(env.Args) > 0 {
		if env.Args[0] == versionFlagName {
			return runVersion(ctx, env, nil)
		}
		if cmd, ok := goCommands()[env.Args[0]]; ok {
			return cmd(ctx, env, env.Args[1:])
		}
	}
	return toPython(ctx, env)
}

// toPython hands the whole invocation to cli/sp.py.
func toPython(ctx context.Context, env Env) int {
	home, err := pyhome.Locate(env.Getenv, env.Executable)
	if err != nil {
		return fail(env, ExitNotFound, "this command has no Go implementation yet and %v", err)
	}
	python, err := delegate.Interpreter(env.Getenv)
	if err != nil {
		return fail(env, ExitNotFound, "%v", err)
	}
	spec := delegate.Spec{Python: python, Script: home.Script(), Args: env.Args, Env: env.Environ,
		Stdin: env.Stdin, Stdout: env.Stdout, Stderr: env.Stderr}
	code, err := env.Exec(ctx, spec)
	if err != nil {
		return fail(env, ExitCannotRun, "%v", err)
	}
	return code
}

// fail reports a shim error on stderr. A failed write to stderr cannot be reported anywhere else; the exit
// status still says what happened.
func fail(env Env, code int, format string, args ...any) int {
	_, _ = fmt.Fprintf(env.Stderr, "sp: "+format+"\n", args...)
	return code
}
