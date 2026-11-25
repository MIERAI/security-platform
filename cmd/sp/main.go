// Command sp is the security-platform command line. During the move to Go it runs the Go implementation of a
// subcommand when there is one and hands every other invocation to the Python implementation unchanged
// (docs/go.md).
package main

import (
	"context"
	"os"

	"github.com/MIERAI/security-platform/internal/buildinfo"
	"github.com/MIERAI/security-platform/internal/delegate"
	"github.com/MIERAI/security-platform/internal/shim"
)

func main() {
	exe, err := os.Executable()
	if err != nil {
		exe = "" // the Python tree is then found through SP_PY_HOME or the default install root only
	}
	os.Exit(shim.Main(context.Background(), shim.Env{
		Args:       os.Args[1:],
		Stdin:      os.Stdin,
		Stdout:     os.Stdout,
		Stderr:     os.Stderr,
		Getenv:     os.Getenv,
		Environ:    os.Environ(),
		Executable: exe,
		Build:      buildinfo.Read(),
		Exec:       delegate.Replace,
	}))
}
