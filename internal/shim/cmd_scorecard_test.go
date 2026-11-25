package shim

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/MIERAI/security-platform/internal/buildinfo"
	"github.com/MIERAI/security-platform/internal/delegate"
)

// scorecardTree is a fake tree with the scorecard component and a one-control catalog.
func scorecardTree(t *testing.T) string {
	t.Helper()
	tree := fakeTree(t, "")
	writeFile(t, filepath.Join(tree, "scorecard", "VERSION"), "0.5.0\n")
	writeFile(t, filepath.Join(tree, "scorecard", "catalog", "01-d.yaml"),
		"schema: security-platform/scorecard-catalog/v1\ndimension: {id: d, order: 1, title: D, pillars: [device]}\n"+
			"controls:\n  - {id: d.a, title: A, csf: PR.PS, check: automated, weight: 1, source: {type: findings}}\n")
	return tree
}

func TestScorecardRunsInGo(t *testing.T) {
	t.Parallel()
	tree := scorecardTree(t)
	data := t.TempDir()
	vars := map[string]string{"SP_PY_HOME": tree}
	if r := run(t, vars, "", "scorecard", "version"); r.code != 0 || r.stdout != "0.5.0\n" {
		t.Fatalf("version: %+v", r)
	}
	r := run(t, vars, "", "scorecard", "compute", "--data", data, "--now", "1894233600")
	if r.code != 0 || !strings.HasPrefix(r.stderr, "[scorecard 0.5.0] PASS overall=100.0") {
		t.Fatalf("compute: %+v", r)
	}
	if _, err := os.Stat(filepath.Join(data, "reports", "scorecard.json")); err != nil {
		t.Fatal(err)
	}
	if r := run(t, vars, "", "scorecard", "nope"); r.code != 2 {
		t.Fatalf("usage error: %+v", r)
	}
	if !slices.Contains(GoSubcommands(), "scorecard") {
		t.Fatal("scorecard is not listed as a Go subcommand")
	}
}

func TestScorecardNeedsTheProductTree(t *testing.T) {
	t.Parallel()
	r := run(t, map[string]string{"SP_PY_HOME": filepath.Join(t.TempDir(), "missing")}, "", "scorecard", "version")
	if r.code != ExitNotFound {
		t.Fatalf("got %+v, want exit %d", r, ExitNotFound)
	}
}

func TestScorecardAttestRunsTheReference(t *testing.T) {
	t.Parallel()
	tree := scorecardTree(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	vars := map[string]string{"SP_PY_HOME": tree, delegate.EnvPython: exe}
	var got delegate.Spec
	args := []string{"scorecard", "attest", "--data", "/d", "d.a", "--by", "a person", "--days", "30"}
	var out bytes.Buffer
	env := Env{Args: args, Stdout: &out, Stderr: &out, Getenv: func(k string) string { return vars[k] },
		Build: buildinfo.Info{Release: "v0.4.0"},
		Exec:  func(_ context.Context, s delegate.Spec) (int, error) { got = s; return 3, nil }}
	if code := Main(t.Context(), env); code != 3 {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	if got.Script != filepath.Join(tree, "scorecard", "scorecard.py") || !slices.Equal(got.Args, args[1:]) {
		t.Fatalf("delegated %+v", got)
	}
}
