// Package scorecard is the Go implementation of the scorecard component (contracts/scorecard/SPEC.md): it
// scores the security programme per dimension, pillar and NIST CSF function from the catalog, the instance,
// the ledger, the published metrics, the runner's job states and human attestations, and writes the report,
// the metrics and the regression state. `attest` (a human's command) stays with the reference implementation.
package scorecard

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	pv "github.com/MIERAI/security-platform/internal/scorecard/pyvalue"
	"github.com/MIERAI/security-platform/internal/textsafe"
)

// Exit statuses.
const (
	ExitOK     = 0
	ExitFailed = 1 // a configuration error (compute), catalog errors (lint)
	ExitUsage  = 2
)

// Env is everything the command reads from its process, injected.
type Env struct {
	Stdout, Stderr io.Writer
	Home           string           // the user's home directory ("" = ~ is not expanded)
	Product        string           // the product tree (scorecard/catalog, scorecard/VERSION)
	Now            func() time.Time // the wall clock, when --now is absent or 0
	GitLog         GitLog
	// Attest runs the reference implementation's `attest` with the original arguments; it returns the exit
	// status.
	Attest func(ctx context.Context, args []string) int
}

// Main runs `scorecard <command> ...` and returns its exit status.
func Main(ctx context.Context, env Env, argv []string) int {
	a, err := ParseArgs(argv)
	switch {
	case errors.Is(err, ErrHelp):
		_, _ = fmt.Fprintln(env.Stdout, Usage) // nothing else can report a failed write to stdout
		return ExitOK
	case err != nil:
		return usageError(env, strings.TrimPrefix(err.Error(), ErrUsage.Error()+": "))
	}
	if a.Command == "attest" {
		return env.Attest(ctx, argv)
	}
	version, err := readComponentVersion(env.Product)
	if err != nil {
		return failed(env, err)
	}
	if a.Command == "version" {
		_, _ = fmt.Fprintln(env.Stdout, version)
		return ExitOK
	}
	inst, err := loadInstance(a.Instance, env.Home)
	if err != nil {
		return failed(env, err)
	}
	if a.Command == "lint" || a.Command == "list" {
		return lintOrList(env, a, inst)
	}
	return compute(ctx, env, a, inst, version)
}

// usageError prints the synopsis and the problem; a failed write to stderr cannot be reported anywhere else.
func usageError(env Env, msg string) int {
	_, _ = fmt.Fprintf(env.Stderr, "%s\nscorecard: error: %s\n", Usage, textsafe.Line(msg))
	return ExitUsage
}

func failed(env Env, err error) int {
	_, _ = fmt.Fprintf(env.Stderr, "scorecard: %s\n", textsafe.Line(err.Error())) // nothing else can report it
	return ExitFailed
}

func readComponentVersion(product string) (string, error) {
	data, err := readFile(filepath.Join(product, "scorecard", "VERSION"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func loadInstance(path, home string) (any, error) {
	if path == "" {
		return pv.NewMap(), nil
	}
	return readYAMLFile(expandUser(path, home))
}

func compute(ctx context.Context, env Env, a Args, inst any, version string) int {
	if a.Data == "" {
		return usageError(env, "--data is required")
	}
	data, err := filepath.Abs(expandUser(a.Data, env.Home))
	if err != nil {
		return failed(env, fmt.Errorf("data directory: %w", err))
	}
	now, err := clock(a.Now, env.Now)
	if err != nil {
		return usageError(env, "argument --now: invalid float value: "+pv.Repr(a.Now))
	}
	r, err := Compute(ctx, Options{Data: data, Product: env.Product, Home: env.Home, Instance: inst, Now: now,
		ExtraCatalogs: a.Catalogs, Version: version, GitLog: env.GitLog})
	if err == nil {
		err = UpdateRegressions(data, r)
	}
	if err == nil {
		err = WriteOutputs(data, r)
	}
	if err != nil {
		return failed(env, err)
	}
	_, _ = fmt.Fprintln(env.Stderr, textsafe.Line(r.Summary())) // a failed write to stderr cannot be reported
	return ExitOK
}

// clock is --now, or the wall clock when it is absent or 0.
func clock(text string, wall func() time.Time) (float64, error) {
	if text != "" {
		f, err := pv.ToFloat(text)
		if err != nil {
			return 0, err
		}
		if f != 0 {
			return f, nil
		}
	}
	t := wall()
	return float64(t.UnixNano()) / 1e9, nil
}

// Summary is the one line printed on stderr after a compute.
func (r *Result) Summary() string {
	weakest := "None"
	if r.Weakest != "" {
		weakest = r.Weakest
	}
	var b bytes.Buffer
	b.WriteString("[scorecard " + r.Version + "] " + r.Status + " overall=" + pv.FloatRepr(r.Overall) + " weakest=" +
		weakest + " ")
	parts := make([]string, len(r.Dims))
	for i, d := range r.Dims {
		parts[i] = d.ID + "=" + pv.FloatRepr(d.Score)
	}
	b.WriteString(strings.Join(parts, " "))
	return b.String()
}

func lintOrList(env Env, a Args, inst any) int {
	sc, err := scorecardSection(inst)
	if err != nil {
		return failed(env, err)
	}
	dirs, err := catalogDirs(sc, env.Product, env.Home, a.Catalogs)
	if err != nil {
		return failed(env, err)
	}
	cat, err := LoadCatalog(dirs, sc)
	if err != nil {
		return failed(env, err)
	}
	if a.Command == "list" {
		return list(env, cat, a.Dimension)
	}
	errs := Lint(cat)
	for _, e := range lintInstance(sc) {
		errs = append(errs, "instance scorecard: "+e)
	}
	for _, e := range errs {
		_, _ = fmt.Fprintln(env.Stderr, textsafe.Line(e)) // a failed write to stderr cannot be reported
	}
	_, _ = fmt.Fprintf(env.Stderr, "%d dimensions, %d controls, %d error(s)\n", len(cat.Dims), len(cat.Controls),
		len(errs))
	if len(errs) > 0 {
		return ExitFailed
	}
	return ExitOK
}

func list(env Env, cat *Catalog, dimension string) int {
	for _, c := range cat.Controls {
		if dimension != "" && c.Dimension != dimension {
			continue
		}
		if err := validateForCompute(c); err != nil {
			return failed(env, err)
		}
		line, err := listLine(c)
		if err != nil {
			return failed(env, err)
		}
		if _, err := fmt.Fprintln(env.Stdout, textsafe.Line(line)); err != nil {
			return failed(env, fmt.Errorf("write: %w", err))
		}
	}
	return ExitOK
}
