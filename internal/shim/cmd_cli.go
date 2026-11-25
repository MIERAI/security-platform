package shim

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"runtime"
	"slices"
	"time"

	"github.com/MIERAI/security-platform/internal/cli"
	"github.com/MIERAI/security-platform/internal/delegate"
	"github.com/MIERAI/security-platform/internal/pyhome"
)

// EnvCLI selects the implementation of the day-to-day commands: "python" hands them (and unknown commands) to
// cli/sp.py as before the move, for one release, so that switching back is one variable (docs/go.md).
const EnvCLI = "SP_CLI"

// pythonCLI reports whether the day-to-day commands go to the Python implementation.
func pythonCLI(env Env) bool {
	return env.Getenv(EnvCLI) == "python"
}

// isCLI reports whether args are for the cli package: one of its commands, the top-level help, no command, or an
// unknown one (which it reports as a usage error).
func isCLI(args []string) bool {
	return len(args) == 0 || slices.Contains(cli.Commands(), args[0]) || !goSubcommand(args[0])
}

func goSubcommand(name string) bool {
	_, ok := goCommands()[name]
	return ok || name == versionFlagName
}

// runCLI is `sp init|doctor|run|status|findings|explain|digest|notify` (internal/cli, contracts/cli).
func runCLI(ctx context.Context, env Env, args []string) int {
	home, treeErr := pyhome.Locate(env.Getenv, env.Executable)
	return cli.Main(ctx, cli.Env{
		Stdout: env.Stdout, Stderr: env.Stderr, Getenv: env.Getenv,
		Color: env.StdoutTTY && env.Getenv("NO_COLOR") == "",
		Now:   time.Now, Loc: time.Local, Hostname: env.Hostname, GOOS: runtime.GOOS,
		Tree: home.Dir, TreeErr: treeErr,
		Python: func() (string, error) { return delegate.Interpreter(env.Getenv) },
		Exec:   runChild,
		Probe: func(ctx context.Context, argv []string) (int, error) {
			return runChild(ctx, argv, io.Discard, io.Discard)
		},
	}, args)
}

// runChild runs a program of the product (the runner, an interpreter check) with its output going to the given
// streams and returns its exit status. The runner enforces its jobs' time limits itself; ctx ends it early.
func runChild(ctx context.Context, argv []string, stdout, stderr io.Writer) (int, error) {
	if len(argv) == 0 {
		return 0, errors.New("empty command")
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) // #nosec G204 -- the product's own programs, argument vector
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err := cmd.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), nil
	}
	if err != nil {
		return 0, fmt.Errorf("start %s: %w", argv[0], err)
	}
	return 0, nil
}
