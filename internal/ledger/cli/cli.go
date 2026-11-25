// Package cli is `sp ledger`: the command lines of the Go ledger component.
//
//	sp ledger merge --run RUN --data DATA [--latest DIR] [--instance F] [--now EPOCH] [--reference-behaviour IDS]
//	sp ledger track --data DATA [--instance F] [--now EPOCH] [--no-external-sync]
//	sp ledger version
//
// merge and track take the arguments of the contract (contracts/ledger/SPEC.md §1, §7); --instance gives merge
// the instance's remediation SLOs (LEDGER-D2), --now pins the clock, --no-external-sync keeps track from
// calling an external tracker (shadow runs). --reference-behaviour is diagnostic: it reproduces the reference's
// known deviations (D2, D3, D5) so that a shadow comparison can attribute every difference.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/ledger"
	"github.com/MIERAI/security-platform/internal/ledger/fileio"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
	"github.com/MIERAI/security-platform/internal/ledger/yamlcfg"
	"github.com/MIERAI/security-platform/internal/remediation"
)

// Exit statuses.
const (
	ExitOK    = 0
	ExitError = 1 // the job could not be done (nothing half-written)
	ExitUsage = 2
)

// Env is what the command reads from its process.
type Env struct {
	Stdout, Stderr io.Writer
	Environ        []string         // passed to the programs it runs (gh)
	Now            func() time.Time // the wall clock
	GH             remediation.GHFunc
}

const usage = `usage: sp ledger merge --run RUN --data DATA [--latest DIR] [--instance F] [--now EPOCH]
       sp ledger track --data DATA [--instance F] [--now EPOCH] [--no-external-sync]
       sp ledger version`

// Run executes `sp ledger <args>` and returns the exit status.
func Run(ctx context.Context, env Env, args []string) int {
	if len(args) == 0 {
		return usageError(env, "a subcommand is required")
	}
	switch args[0] {
	case "merge":
		return runMerge(env, args[1:])
	case "track":
		return runTrack(ctx, env, args[1:])
	case "version", "--version":
		_, _ = fmt.Fprintf(env.Stdout, "sp ledger %s\n", ledger.Version()) // nothing to do if stdout is gone
		return ExitOK
	case "-h", "--help", "help":
		_, _ = fmt.Fprintln(env.Stdout, usage) // nothing to do if stdout is gone
		return ExitOK
	default:
		return usageError(env, fmt.Sprintf("unknown subcommand %q", args[0]))
	}
}

func usageError(env Env, msg string) int {
	_, _ = fmt.Fprintf(env.Stderr, "%s\nsp ledger: error: %s\n", usage, msg) // the status says it anyway
	return ExitUsage
}

func failure(env Env, cmd string, err error) int {
	_, _ = fmt.Fprintf(env.Stderr, "sp ledger %s: error: %v\n", cmd, err) // the status says it anyway
	return ExitError
}

// common are the flags both subcommands take.
type common struct {
	data, instance, now string
}

func newFlags(name string, env Env, c *common) *flag.FlagSet {
	fs := flag.NewFlagSet("sp ledger "+name, flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	fs.StringVar(&c.data, "data", "", "private data directory (required)")
	fs.StringVar(&c.instance, "instance", "", "instance config (YAML or JSON): its remediation section")
	fs.StringVar(&c.now, "now", "", "epoch seconds to use as the current time")
	return fs
}

// clock returns --now, or the wall clock.
func clock(env Env, now string) (float64, error) {
	if now == "" {
		return float64(env.Now().UnixNano()) / 1e9, nil
	}
	f, err := strconv.ParseFloat(now, 64)
	if err != nil || !pyjson.IsFinite(f) {
		return 0, fmt.Errorf("--now %q is not a number of seconds", now)
	}
	return f, nil
}

func runMerge(env Env, args []string) int {
	var c common
	var run, latest, reference string
	fs := newFlags("merge", env, &c)
	fs.StringVar(&reference, "reference-behaviour", "", "diagnostic: reproduce the reference for these deviations (LEDGER-D2,LEDGER-D3,LEDGER-D5)")
	fs.StringVar(&run, "run", "", "run directory with the findings documents (required)")
	fs.StringVar(&latest, "latest", "", "the newest document of every collector (coverage gaps, collector metrics)")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 || run == "" || c.data == "" {
		return usageError(env, "merge needs --run and --data, and no other arguments")
	}
	now, err := clock(env, c.now)
	if err != nil {
		return usageError(env, err.Error())
	}
	ref, err := parseReference(reference)
	if err != nil {
		return usageError(env, err.Error())
	}
	rem, err := remediationSection(c.instance)
	if err != nil {
		return failure(env, "merge", err)
	}
	opt := ledger.Options{Run: run, Data: c.data, Latest: latest, Remediation: rem, Now: now,
		Version: ledger.Version(), Stderr: env.Stderr, Reference: ref}
	if err := ledger.Merge(opt); err != nil {
		return failure(env, "merge", err)
	}
	return ExitOK
}

func runTrack(ctx context.Context, env Env, args []string) int {
	var c common
	var noExternal bool
	fs := newFlags("track", env, &c)
	fs.BoolVar(&noExternal, "no-external-sync", false, "sync only the local files tracker (never an external one)")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 || c.data == "" {
		return usageError(env, "track needs --data, and no other arguments")
	}
	now, err := clock(env, c.now)
	if err != nil {
		return usageError(env, err.Error())
	}
	rem, err := remediationSection(c.instance)
	if err != nil {
		return failure(env, "track", err)
	}
	gh := env.GH
	if gh == nil {
		gh = remediation.ExecGH(env.Environ)
	}
	opt := remediation.Options{Data: c.data, Config: rem, Now: now, Wall: float64(env.Now().Unix()),
		NoExternalSync: noExternal, Version: ledger.Version(), Stderr: env.Stderr, GH: gh}
	if err := remediation.Track(ctx, opt); err != nil {
		return failure(env, "track", err)
	}
	return ExitOK
}

// parseReference reads --reference-behaviour: deviation ids, with or without the LEDGER- prefix.
func parseReference(list string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, id := range strings.Split(list, ",") {
		if id = strings.TrimSpace(id); id == "" {
			continue
		}
		if !strings.HasPrefix(id, "LEDGER-") {
			id = "LEDGER-" + id
		}
		known := false
		for _, d := range ledger.ReferenceDeviations() {
			known = known || d == id
		}
		if !known {
			return nil, fmt.Errorf("--reference-behaviour: %q is not one of %s", id, strings.Join(ledger.ReferenceDeviations(), ", "))
		}
		out[id] = true
	}
	return out, nil
}

// ErrInstance is wrapped by errors about the instance file.
var ErrInstance = errors.New("instance config")

// remediationSection reads the instance file's `remediation:` mapping; no file: nil.
func remediationSection(path string) (*pyjson.Object, error) {
	if path == "" {
		return nil, nil
	}
	if rest, ok := strings.CutPrefix(path, "~/"); ok {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInstance, err)
		}
		path = filepath.Join(home, rest)
	}
	data, err := fileio.Read(path, ledger.MaxYAMLBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInstance, err)
	}
	v, err := yamlcfg.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrInstance, path, err)
	}
	inst, _ := v.(*pyjson.Object) // an empty or non-mapping file has no remediation section
	if inst == nil {
		return nil, nil
	}
	return inst.Obj("remediation"), nil
}
