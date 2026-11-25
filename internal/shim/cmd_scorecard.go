package shim

import (
	"context"
	"path/filepath"
	"runtime"
	"time"

	"github.com/MIERAI/security-platform/internal/delegate"
	"github.com/MIERAI/security-platform/internal/pyhome"
	"github.com/MIERAI/security-platform/internal/scorecard"
)

// runScorecard is `sp scorecard compute|lint|list|version|attest ...` (contracts/scorecard/SPEC.md §1). The
// catalog and the component version come from the located product tree; `attest` (a human's command) is
// handed to the reference implementation, scorecard/scorecard.py, unchanged.
func runScorecard(ctx context.Context, env Env, args []string) int {
	home, err := pyhome.Locate(env.Getenv, env.Executable)
	if err != nil {
		return fail(env, ExitNotFound, "scorecard: the product tree (catalog) was not found: %v", err)
	}
	userHome := env.Getenv("HOME")
	if runtime.GOOS == "windows" {
		userHome = env.Getenv("USERPROFILE")
	}
	return scorecard.Main(ctx, scorecard.Env{
		Stdout: env.Stdout, Stderr: env.Stderr, Home: userHome, Product: home.Dir, Now: time.Now,
		GitLog: scorecard.RunGitLog,
		Attest: func(ctx context.Context, argv []string) int { return attestInPython(ctx, env, home, argv) },
	}, args)
}

func attestInPython(ctx context.Context, env Env, home pyhome.Home, argv []string) int {
	python, err := delegate.Interpreter(env.Getenv)
	if err != nil {
		return fail(env, ExitNotFound, "%v", err)
	}
	spec := delegate.Spec{Python: python, Script: filepath.Join(home.Dir, "scorecard", "scorecard.py"), Args: argv,
		Env: env.Environ, Stdin: env.Stdin, Stdout: env.Stdout, Stderr: env.Stderr}
	code, err := env.Exec(ctx, spec)
	if err != nil {
		return fail(env, ExitCannotRun, "%v", err)
	}
	return code
}
