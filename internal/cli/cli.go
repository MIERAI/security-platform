// Package cli is the Go implementation of the day-to-day `sp` commands (contracts/cli/SPEC.md): init, doctor, run,
// status, findings, explain, digest and notify. Output, exit statuses and files are those of the reference
// implementation, cli/sp.py, except where the contract records a known deviation (CLI-D2..D5) whose target this
// implementation follows.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/cli/explain"
	"github.com/MIERAI/security-platform/internal/cli/flags"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// Exit statuses.
const (
	ExitOK    = 0
	ExitFail  = 1 // doctor found something to fix; a notifier failed; none configured
	ExitUsage = 2 // command line, missing or unreadable data (as the reference's die())
)

// Env is everything the commands read from their process, injected so tests need no global state.
type Env struct {
	Stdout, Stderr io.Writer
	Getenv         func(string) string
	Color          bool // stdout is a terminal and NO_COLOR is unset
	Now            func() time.Time
	Loc            *time.Location // local time zone (TZ)
	Hostname       string         // this machine's name (sp init's first host)
	GOOS           string
	// Tree is the product tree (collectors, runner); "" when none was found, TreeErr says why.
	Tree    string
	TreeErr error
	// Python returns the interpreter that runs the product's Python programs (the runner, PyYAML check).
	Python func() (string, error)
	// Exec runs a program with the given streams and returns its exit status (sp run: the runner).
	Exec func(ctx context.Context, argv []string, stdout, stderr io.Writer) (int, error)
	// Probe runs a short check program and returns its exit status (sp doctor: PyYAML in the interpreter).
	Probe func(ctx context.Context, argv []string) (int, error)
}

// Error is a failure reported as one line `sp: <msg>` with an exit status.
type Error struct {
	Code int
	Msg  string
}

func (e *Error) Error() string { return e.Msg }

func die(code int, format string, args ...any) error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, args...)}
}

type command struct {
	spec *flags.Spec
	run  func(ctx context.Context, s *session, a *flags.Result) (int, error)
}

// Commands lists the subcommands this package implements, in help order.
func Commands() []string {
	return []string{"init", "doctor", "run", "status", "findings", "explain", "digest", "notify"}
}

func commands() map[string]command {
	return map[string]command{
		"init":     {initSpec(), runInit},
		"doctor":   {dataSpec("doctor"), runDoctor},
		"run":      {runSpec(), runRun},
		"status":   {dataSpec("status"), runStatus},
		"findings": {findingsSpec(), runFindings},
		"explain":  {explainSpec(), runExplain},
		"digest":   {digestSpec(), runDigest},
		"notify":   {notifySpec(), runNotify},
	}
}

// Main runs `sp <args>` for the commands of this package (and the top-level help and usage errors) and returns
// the exit status.
func Main(ctx context.Context, env Env, args []string) int {
	width := textWidth(env.Getenv)
	cmd, code, done := topLevel(env, args, width)
	if done {
		return code
	}
	cmd.spec.Width = width
	a, err := flags.Parse(cmd.spec, args[1:])
	if err != nil {
		// as argparse: arguments no command knows are reported by the top-level parser
		if strings.HasPrefix(err.Error(), "unrecognized arguments: ") {
			return usage(env, topUsage(width), "sp", err.Error())
		}
		return usage(env, cmd.spec.Usage(), cmd.spec.Prog, err.Error())
	}
	if a.Help {
		return exitWith(env, ExitOK, emit(env.Stdout, cmd.spec.Help()))
	}
	texts, err := explain.Load()
	if err != nil {
		return exitWith(env, ExitFail, err)
	}
	code, err = cmd.run(ctx, &session{env: env, texts: texts, args: a}, a)
	return exitWith(env, code, err)
}

// topLevel handles what comes before a command: none (usage error), the top-level help, an unknown command. done is
// false when args name a command, which it returns.
func topLevel(env Env, args []string, width int) (cmd command, code int, done bool) {
	switch {
	case len(args) == 0:
		return cmd, usage(env, topUsage(width), "sp", "the following arguments are required: cmd"), true
	case args[0] == "-h" || isLongOptionPrefix(args[0], "--help"):
		return cmd, exitWith(env, ExitOK, emit(env.Stdout, topHelp(width))), true
	}
	cmd, ok := commands()[args[0]]
	switch {
	case ok:
		return cmd, 0, false
	case strings.HasPrefix(args[0], "-"):
		return cmd, usage(env, topUsage(width), "sp", "unrecognized arguments: "+args[0]), true
	}
	return cmd, usage(env, topUsage(width), "sp", fmt.Sprintf("argument cmd: invalid choice: %s (choose from %s)",
		pyvalue.Repr(args[0]), strings.Join(Commands(), ", "))), true
}

// isLongOptionPrefix reports whether arg is a long option that abbreviates option (argparse: --he means --help).
func isLongOptionPrefix(arg, option string) bool {
	return len(arg) > 2 && strings.HasPrefix(arg, "--") && strings.HasPrefix(option, arg)
}

// exitWith reports err (if any) as one line `sp: <msg>` on stderr and returns the exit status: the error's own
// for an *Error, 2 for any other, else code.
func exitWith(env Env, code int, err error) int {
	if err == nil {
		return code
	}
	var e *Error
	if errors.As(err, &e) {
		code = e.Code
	} else {
		code = ExitUsage
	}
	// stderr is the last place to report anything; the exit status says what happened when it fails too
	_, _ = fmt.Fprintf(env.Stderr, "sp: %s\n", err.Error())
	return code
}

// emit writes text to w; a failed write (a closed pipe) fails the command.
func emit(w io.Writer, text string) error {
	if _, err := io.WriteString(w, text); err != nil {
		return die(ExitFail, "write: %v", err)
	}
	return nil
}

func emitf(w io.Writer, format string, args ...any) error {
	return emit(w, fmt.Sprintf(format, args...))
}

// usage reports a command-line mistake as argparse does: the synopsis, then "<prog>: error: <msg>"; exit 2.
func usage(env Env, synopsis, prog, msg string) int {
	_, _ = fmt.Fprintf(env.Stderr, "%s\n%s: error: %s\n", synopsis, prog, msg) // nowhere else to report a failure
	return ExitUsage
}

// textWidth is the width of usage and help text: $COLUMNS (argparse reads it too) minus 2, else 78.
func textWidth(getenv func(string) string) int {
	if n, err := strconv.Atoi(strings.TrimSpace(getenv("COLUMNS"))); err == nil && n > 2 {
		return n - 2
	}
	return flags.DefaultWidth
}

func topUsage(width int) string {
	return flags.FormatUsage("sp", []string{"[-h]", "[--version]"}, []string{"{" + strings.Join(Commands(), ",") + "}", "..."},
		width)
}

func topHelp(width int) string {
	return topUsage(width) + `

security-platform command line

positional arguments:
  {` + strings.Join(Commands(), ",") + `}
    init                create a private data directory with a starter config
    doctor              check the config, tools and permissions
    run                 run jobs now
    status              one-screen overview
    findings            list findings
    explain             explain one finding in plain language
    digest              print the short summary
    notify              send the summary to the configured notifiers

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit

    sp init DIR [--name NAME]          create a private data directory with a starter instance.yaml
    sp doctor                          check the config, the tools each configured collector needs, file permissions
    sp run [JOB ...]                   run jobs now (default: every job in the config), then publish the metrics
    sp status                          one screen: jobs, open findings, overdue fixes, coverage, scorecard
    sp findings [--open] [--severity high] [--layer L] [--check C] [--overdue] [--json|--ids]
    sp explain ID                      what it is, why it matters, how to fix it, how to verify, how to accept it
    sp digest [--daily]                the short summary that notifiers send (aggregates only)
    sp notify [--dry-run]              send the digest through the configured notifiers
`
}

// ---- command syntax -----------------------------------------------------------------------------------------

func dataOptions() []flags.Option {
	return []flags.Option{
		{Name: "data", Kind: flags.String, Help: "private data directory (default $SP_DATA)"},
		{Name: "instance", Kind: flags.String, Help: "instance config (default DATA/instance.yaml)"},
	}
}

// dataSpec is the syntax of a command that reads the data directory. The help shows no summary line, as the
// reference's (the summaries are in the top-level help).
func dataSpec(name string, extra ...flags.Option) *flags.Spec {
	return &flags.Spec{Prog: "sp " + name, Options: append(dataOptions(), extra...)}
}

func initSpec() *flags.Spec {
	return &flags.Spec{Prog: "sp init",
		Options:     []flags.Option{{Name: "name", Kind: flags.String}, {Name: "force", Kind: flags.Bool}},
		Positionals: []flags.Positional{{Name: "dir"}}}
}

func runSpec() *flags.Spec {
	s := dataSpec("run")
	s.Positionals = []flags.Positional{{Name: "jobs", Variadic: true}}
	return s
}

func findingsSpec() *flags.Spec {
	return dataSpec("findings",
		flags.Option{Name: "open", Kind: flags.Bool, Help: "only open findings"},
		flags.Option{Name: "severity", Kind: flags.String, Choices: severities(), Help: "this severity or worse"},
		flags.Option{Name: "layer", Kind: flags.String},
		flags.Option{Name: "check", Kind: flags.String, Help: "check name or prefix"},
		flags.Option{Name: "overdue", Kind: flags.Bool, Help: "past the remediation SLO"},
		flags.Option{Name: "json", Kind: flags.Bool},
		flags.Option{Name: "ids", Kind: flags.Bool, Help: "only the ids"})
}

func explainSpec() *flags.Spec {
	s := dataSpec("explain")
	s.Positionals = []flags.Positional{{Name: "id"}}
	return s
}

func digestSpec() *flags.Spec {
	return dataSpec("digest",
		flags.Option{Name: "daily", Kind: flags.Bool},
		flags.Option{Name: "days", Kind: flags.Int, Default: 1})
}

func notifySpec() *flags.Spec {
	return dataSpec("notify",
		flags.Option{Name: "dry-run", Kind: flags.Bool},
		flags.Option{Name: "days", Kind: flags.Int, Default: 1})
}
