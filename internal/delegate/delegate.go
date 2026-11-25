// Package delegate runs the Python implementation of a subcommand with the caller's argument vector, standard
// streams, environment and exit code passed through unchanged. It never goes through a shell.
//
// On Unix the sp process is replaced (execve), so signals, the process id, the controlling terminal and the exit
// status are exactly the Python program's. On Windows, which has no exec, sp waits for a child process and exits
// with its exit code; console Ctrl-C reaches the child directly and sp ignores it while waiting.
//
// There is no time limit: a delegated command (sp run) can legitimately run long, and enforces its own limits.
package delegate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
)

// EnvPython names the environment variable that selects the Python interpreter (a path or a program name).
const EnvPython = "SP_PYTHON"

// Spec is one delegated invocation.
type Spec struct {
	Python string   // interpreter, resolved (see Interpreter)
	Script string   // cli/sp.py of the located tree
	Args   []string // the user's arguments after "sp", unchanged
	Env    []string // the environment, unchanged
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// Argv is the argument vector of the interpreter: python, script, then the user's arguments verbatim.
func (s Spec) Argv() []string {
	argv := make([]string, 0, len(s.Args)+2)
	argv = append(argv, s.Python, s.Script)
	return append(argv, s.Args...)
}

// ErrNoInterpreter is returned when no Python interpreter can be found.
var ErrNoInterpreter = errors.New("python interpreter not found")

// Interpreter resolves the Python interpreter: $SP_PYTHON when set, else python3 (and python on Windows) from
// PATH. A program found only through a relative PATH entry (such as ".") is refused, as exec.LookPath does.
func Interpreter(getenv func(string) string) (string, error) {
	names := []string{"python3"}
	if runtime.GOOS == "windows" {
		names = append(names, "python")
	}
	if p := getenv(EnvPython); p != "" {
		names = []string{p}
	}
	var errs []error
	for _, n := range names {
		path, err := exec.LookPath(n)
		if err == nil {
			return path, nil
		}
		errs = append(errs, err)
	}
	return "", fmt.Errorf("%w (set %s): %w", ErrNoInterpreter, EnvPython, errors.Join(errs...))
}

// Child runs the interpreter as a child process and returns its exit code (128+N when signal N ended it, as a
// shell reports it). Errors are returned only when the program could not be run at all.
func Child(ctx context.Context, s Spec) (int, error) {
	argv := s.Argv()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) // #nosec G204 -- argument vector, no shell; see package doc
	cmd.Env, cmd.Stdin, cmd.Stdout, cmd.Stderr = s.Env, s.Stdin, s.Stdout, s.Stderr
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, os.Interrupt) // the child gets the console's Ctrl-C itself; sp must outlive it
	defer signal.Stop(interrupts)
	err := cmd.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitCode(exitErr.ProcessState), nil
	}
	if err != nil {
		return 0, fmt.Errorf("run %s: %w", argv[0], err)
	}
	return 0, nil
}
