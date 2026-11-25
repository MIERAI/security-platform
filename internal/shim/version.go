package shim

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/MIERAI/security-platform/internal/buildinfo"
	"github.com/MIERAI/security-platform/internal/components"
	"github.com/MIERAI/security-platform/internal/pyhome"
	"github.com/MIERAI/security-platform/internal/release"
	"github.com/MIERAI/security-platform/internal/textsafe"
)

// VersionSchema identifies the `sp version --json` document; additive changes keep it, others bump it.
const VersionSchema = "security-platform/version/v1"

// Report is what `sp version --json` prints.
type Report struct {
	Schema string `json:"schema"`
	// Release is the product release: the Python tree's (what is installed, what the runner reports) when one
	// is found, else the binary's own.
	Release         string                 `json:"release"`
	ReleaseMismatch bool                   `json:"release_mismatch"` // binary and tree are different releases
	Binary          buildinfo.Info         `json:"binary"`
	Python          *PythonTree            `json:"python"` // null when no Python tree was found
	PythonError     string                 `json:"python_error,omitempty"`
	Components      []components.Component `json:"components"`
	GoSubcommands   []string               `json:"go_subcommands"`
}

// PythonTree describes the Python implementation that sp delegates to.
type PythonTree struct {
	Dir        string `json:"dir"`
	Source     string `json:"source"`
	Release    string `json:"release"`
	CLIVersion string `json:"cli_version"`
}

func runVersion(ctx context.Context, env Env, args []string) int {
	fs := flag.NewFlagSet("sp version", flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	asJSON := fs.Bool("json", false, "print a JSON document ("+VersionSchema+")")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsage
	}
	if fs.NArg() > 0 {
		return fail(env, ExitUsage, "version: unexpected argument %q", fs.Arg(0))
	}
	r := buildReport(ctx, env)
	var err error
	if *asJSON {
		err = writeJSON(env.Stdout, r)
	} else {
		err = writeText(env.Stdout, r)
	}
	if err != nil {
		return fail(env, 1, "version: %v", err)
	}
	return ExitOK
}

func buildReport(ctx context.Context, env Env) Report {
	r := Report{Schema: VersionSchema, Release: env.Build.Release, Binary: env.Build,
		Components: []components.Component{}, GoSubcommands: GoSubcommands()}
	home, err := pyhome.Locate(env.Getenv, env.Executable)
	if err != nil {
		r.PythonError = err.Error()
		return r
	}
	tree := &PythonTree{Dir: home.Dir, Source: home.Source, Release: release.Describe(ctx, home.Dir),
		CLIVersion: release.Unknown}
	if comps, err := components.Discover(home.Dir); err == nil {
		r.Components = comps
	}
	for _, c := range r.Components {
		if c.Name == "cli" {
			tree.CLIVersion = c.Version
		}
	}
	r.Python, r.Release = tree, tree.Release
	r.ReleaseMismatch = release.IsProductTag(env.Build.Release) && env.Build.Release != tree.Release
	return r
}

func writeJSON(w io.Writer, r Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("write json: %w", err)
	}
	return nil
}

// writeText prints the human form. Its first line keeps the format of the Python `sp --version`:
// "sp <cli version> (security-platform <release>)". Values read from files are made terminal-safe.
func writeText(w io.Writer, r Report) error {
	cli := release.Unknown
	if r.Python != nil {
		cli = r.Python.CLIVersion
	}
	var b strings.Builder
	fmt.Fprintf(&b, "sp %s (security-platform %s)\n", textsafe.Line(cli), textsafe.Line(r.Release))
	fmt.Fprintf(&b, "binary: %s, %s, %s\n", r.Binary.Release, r.Binary.GoVersion, r.Binary.Platform)
	if r.Python != nil {
		fmt.Fprintf(&b, "python: %s (%s, found via %s)\n", textsafe.Line(r.Python.Dir),
			textsafe.Line(r.Python.Release), r.Python.Source)
	} else {
		fmt.Fprintf(&b, "python: not found (%s)\n", textsafe.Line(r.PythonError))
	}
	if r.ReleaseMismatch {
		fmt.Fprintf(&b, "warning: the sp binary is %s but the Python tree is %s\n", r.Binary.Release,
			textsafe.Line(r.Python.Release))
	}
	fmt.Fprintf(&b, "go subcommands: %s\n", strings.Join(r.GoSubcommands, " "))
	for _, impl := range []string{components.Go, components.Python} {
		fmt.Fprintf(&b, "%s components: %s\n", impl, namesOf(r.Components, impl))
	}
	if _, err := io.WriteString(w, b.String()); err != nil {
		return fmt.Errorf("write text: %w", err)
	}
	return nil
}

func namesOf(cs []components.Component, impl string) string {
	var names []string
	for _, c := range cs {
		if c.Implementation == impl {
			names = append(names, textsafe.Line(c.Name))
		}
	}
	if len(names) == 0 {
		return "(none)"
	}
	return strings.Join(names, " ")
}
