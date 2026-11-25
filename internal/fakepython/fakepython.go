// Package fakepython stands in for the Python interpreter in tests: a test binary calls Main from TestMain when
// FAKE_PYTHON is set, and is then run as "python <script> <args...>".
//
// Its first argument after the script selects the behaviour:
//
//	argv              print the script and every argument, one per line, quoted
//	stdin             copy standard input to standard output
//	exit N            write "out" to stdout and "err" to stderr, then exit with status N
//	kill              end itself with SIGKILL (Unix)
package fakepython

import (
	"fmt"
	"io"
	"os"
	"strconv"
)

// EnvVar switches a test binary into the fake interpreter.
const EnvVar = "FAKE_PYTHON"

// Main runs the fake interpreter and returns its exit status.
func Main(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) < 2 {
		_, _ = fmt.Fprintln(stderr, "fakepython: usage: python SCRIPT MODE [ARGS...]")
		return 100
	}
	switch args[1] {
	case "argv":
		for _, a := range args {
			_, _ = fmt.Fprintf(stdout, "%q\n", a)
		}
	case "stdin":
		if _, err := io.Copy(stdout, stdin); err != nil {
			return 101
		}
	case "exit":
		n, err := strconv.Atoi(args[len(args)-1])
		if err != nil {
			return 102
		}
		_, _ = fmt.Fprint(stdout, "out")
		_, _ = fmt.Fprint(stderr, "err")
		return n
	case "kill":
		return killSelf()
	default:
		return 103
	}
	return 0
}

// Environ is the environment for running a test binary as the fake interpreter: the caller's, with EnvVar set and
// GOCOVERDIR pointed at coverDir. Under `go test -cover` every run of the (instrumented) test binary writes coverage
// files on exit; with the shared GOCOVERDIR of the parent, parallel runs race on renaming the same meta-data file,
// which Windows refuses, and the error lands on the fake interpreter's stderr. A directory per run avoids that.
func Environ(coverDir string) []string {
	return append(os.Environ(), EnvVar+"=1", "GOCOVERDIR="+coverDir)
}

// Run is TestMain's hook: when EnvVar is set it runs Main and exits, otherwise it returns.
func Run() {
	if os.Getenv(EnvVar) == "" {
		return
	}
	os.Exit(Main(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) //nolint:revive // test-only interpreter: exiting is its job
}
