package scorecard

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const testNow = "1894233600" // 2030-01-10T00:00:00Z

// tree is a product tree, a data directory and an instance in a temporary directory.
type tree struct {
	t                       *testing.T
	product, data, instance string
	stdout, stderr          bytes.Buffer
	attested                []string
	gitTime                 string
}

func newTree(t *testing.T, catalog map[string]string, instance string) *tree {
	t.Helper()
	root := t.TempDir()
	tr := &tree{t: t, product: filepath.Join(root, "product"), data: filepath.Join(root, "data"),
		instance: filepath.Join(root, "instance.yaml")}
	tr.write(filepath.Join(tr.product, "scorecard", "VERSION"), "9.9.9\n")
	for name, text := range catalog {
		tr.write(filepath.Join(tr.product, "scorecard", "catalog", name), text)
	}
	tr.write(tr.instance, instance)
	if err := os.MkdirAll(tr.data, 0o700); err != nil {
		t.Fatal(err)
	}
	return tr
}

func (tr *tree) write(path, text string) {
	tr.t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		tr.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		tr.t.Fatal(err)
	}
}

func (tr *tree) run(args ...string) int {
	tr.t.Helper()
	tr.stdout.Reset()
	tr.stderr.Reset()
	env := Env{Stdout: &tr.stdout, Stderr: &tr.stderr, Home: tr.product, Product: tr.product,
		Now:    func() time.Time { return time.Unix(1894233600, 0) },
		GitLog: func(context.Context, string, string) string { return tr.gitTime },
		Attest: func(_ context.Context, argv []string) int { tr.attested = argv; return 7 }}
	return Main(context.Background(), env, args)
}

func (tr *tree) compute() int {
	tr.t.Helper()
	return tr.run("compute", "--data", tr.data, "--instance", tr.instance, "--now", testNow)
}

// controls returns status and detail of every control of the report.
func (tr *tree) controls() map[string][2]string {
	tr.t.Helper()
	var doc struct {
		Controls []struct{ ID, Status, Detail string }
	}
	data, err := os.ReadFile(filepath.Join(tr.data, "reports", "scorecard.json"))
	if err != nil {
		tr.t.Fatal(err)
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		tr.t.Fatal(err)
	}
	out := map[string][2]string{}
	for _, c := range doc.Controls {
		out[c.ID] = [2]string{c.Status, c.Detail}
	}
	return out
}

const catalogHead = "schema: security-platform/scorecard-catalog/v1\ndimension: {id: d, order: 1, title: D, pillars: [device]}\ncontrols:\n"

func ctl(id, src string) string {
	return "  - {id: d." + id + ", title: " + id + ", csf: PR.PS, check: automated, weight: 1, source: " + src + "}\n"
}

func TestComputeWritesEveryOutput(t *testing.T) {
	t.Parallel()
	tr := newTree(t, map[string]string{"01-d.yaml": catalogHead + ctl("a", "{type: findings}")}, "")
	if code := tr.compute(); code != ExitOK {
		t.Fatalf("exit %d: %s", code, tr.stderr.String())
	}
	if got := tr.stderr.String(); got != "[scorecard 9.9.9] PASS overall=100.0 weakest=d d=100.0\n" {
		t.Errorf("summary %q", got)
	}
	for _, rel := range []string{"reports/scorecard.json", "reports/scorecard.md", "metrics/scorecard.prom", "state/scorecard.json"} {
		fi, err := os.Stat(filepath.Join(tr.data, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" && strings.HasPrefix(rel, "reports/") && fi.Mode().Perm() != privateMode {
			t.Errorf("%s mode %v, want 0600 (failing controls are attacker intelligence)", rel, fi.Mode().Perm())
		}
	}
	state, err := os.ReadFile(filepath.Join(tr.data, "state", "scorecard.json"))
	if err != nil || string(state) != "{\n \"below\": {\n  \"d\": false\n },\n \"regressions_total\": {\n  \"d\": 0\n }\n}" {
		t.Errorf("state %q %v", state, err)
	}
}

func TestEvaluatorErrorsAreUnknown(t *testing.T) {
	t.Parallel()
	cat := catalogHead + ctl("key", "{type: sli}") + ctl("attr", "{type: all, of: [x]}") +
		ctl("builtin", "{type: builtin, name: x}") + ctl("regex", "{type: metric, name: m, match: {a: '('}}") +
		ctl("agg", "{type: metric, name: m, agg: avg}") + ctl("op", "{type: metric, name: m, op: '=<'}") +
		ctl("job", "{type: job, jobs: [j]}") + ctl("type", "{type: all, of: [{type: [x]}]}") + ctl("unknown", "{type: nope}") +
		ctl("max", "{type: findings, max: '2.5'}") + ctl("missing", "{type: file, path: nothing}") +
		ctl("first", "{type: first_known, of: []}")
	tr := newTree(t, map[string]string{"01-d.yaml": cat}, "")
	tr.write(filepath.Join(tr.data, "metrics", "security-platform.prom"), "m{a=\"1\"} 2\n")
	tr.write(filepath.Join(tr.data, "state", "runner", "j.json"), `{"last_success": "yesterday"}`)
	if code := tr.compute(); code != ExitOK {
		t.Fatalf("exit %d: %s", code, tr.stderr.String())
	}
	want := map[string]string{
		"d.key":     "evaluator error: KeyError: 'sli'",
		"d.attr":    "evaluator error: AttributeError: 'str' object has no attribute 'get'",
		"d.builtin": "evaluator error: ValueError: unknown builtin 'x'",
		"d.agg":     "evaluator error: KeyError: 'avg'",
		"d.op":      "evaluator error: KeyError: '=<'",
		"d.job":     "evaluator error: TypeError: unsupported operand type(s) for -: 'float' and 'str'",
		"d.type":    "evaluator error: TypeError: unhashable type: 'list'",
		"d.unknown": "unknown source type 'nope'",
		"d.max":     "evaluator error: ValueError: invalid literal for int() with base 10: '2.5'",
		"d.first":   "no sources",
	}
	got := tr.controls()
	for id, detail := range want {
		if got[id] != [2]string{"unknown", detail} {
			t.Errorf("%s = %v, want unknown %q", id, got[id], detail)
		}
	}
	if !strings.HasPrefix(got["d.regex"][1], "evaluator error: error: ") {
		t.Errorf("regex: %v", got["d.regex"])
	}
	if got["d.missing"] != [2]string{"fail", "nothing missing"} {
		t.Errorf("missing file: %v", got["d.missing"])
	}
}

func TestFileEvidenceAge(t *testing.T) {
	t.Parallel()
	cat := catalogHead + ctl("fresh", "{type: file, path: doc.md, max_age: 30d}") +
		ctl("stale", "{type: file, path: doc.md, max_age: 1d}") + ctl("dir", "{type: file, path: scorecard, contains: x}")
	tr := newTree(t, map[string]string{"01-d.yaml": cat}, "")
	tr.write(filepath.Join(tr.product, "doc.md"), "text\n")
	tr.gitTime = "1893801600\n" // 5 days before now
	if code := tr.compute(); code != ExitOK {
		t.Fatalf("exit %d: %s", code, tr.stderr.String())
	}
	got := tr.controls()
	if got["d.fresh"] != [2]string{"pass", "doc.md present (changed 5.0d ago)"} {
		t.Errorf("fresh: %v", got["d.fresh"])
	}
	if got["d.stale"] != [2]string{"fail", "doc.md not reviewed for 5.0d (max 1d)"} {
		t.Errorf("stale: %v", got["d.stale"])
	}
	if got["d.dir"] != [2]string{"fail", "scorecard lacks /x/"} {
		t.Errorf("a directory has no text: %v", got["d.dir"])
	}
}

func TestExitStatuses(t *testing.T) {
	t.Parallel()
	good := map[string]string{"01-d.yaml": catalogHead + ctl("a", "{type: findings}")}
	tests := []struct {
		name     string
		catalog  map[string]string
		instance string
		args     []string // nil = compute
		want     int
	}{
		{"usage", good, "", []string{"bogus"}, ExitUsage},
		{"no data", good, "", []string{"compute"}, ExitUsage},
		{"bad now", good, "", []string{"compute", "--data", "D", "--now", "x"}, ExitUsage},
		{"bad threshold", good, "scorecard: {threshold: high}\n", nil, ExitFailed},
		{"vars redefine data", good, "scorecard: {vars: {data: x}}\n", nil, ExitFailed},
		{"no reason", good, "scorecard: {not_applicable: {d.a: ''}}\n", nil, ExitFailed},
		{"bad schema", map[string]string{"01-d.yaml": "schema: x\n"}, "", nil, ExitFailed},
		{"weight text", map[string]string{"01-d.yaml": catalogHead + "  - {id: d.a, title: a, check: automated, weight: x}\n"}, "", nil, ExitFailed},
		{"instance not a mapping", good, "- 1\n", nil, ExitFailed},
		{"unhashable top-level type", map[string]string{"01-d.yaml": catalogHead + ctl("a", "{type: [x]}")}, "", nil, ExitFailed},
		{"help", good, "", []string{"--help"}, ExitOK},
		{"version", good, "", []string{"version"}, ExitOK},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tr := newTree(t, tc.catalog, tc.instance)
			var code int
			if tc.args == nil {
				code = tr.compute()
			} else {
				code = tr.run(tc.args...)
			}
			if code != tc.want {
				t.Errorf("exit %d, want %d: %s", code, tc.want, tr.stderr.String())
			}
		})
	}
}

func TestAttestIsDelegated(t *testing.T) {
	t.Parallel()
	tr := newTree(t, nil, "")
	argv := []string{"attest", "--data", "D", "d.a", "--by", "me"}
	if code := tr.run(argv...); code != 7 || strings.Join(tr.attested, " ") != strings.Join(argv, " ") {
		t.Errorf("attest: exit %d, argv %q", code, tr.attested)
	}
}

func TestLintAndList(t *testing.T) {
	t.Parallel()
	cat := catalogHead + ctl("ok", "{type: findings}") +
		"  - {id: x.bad, title: t, csf: ZZ, pillars: [moon], check: maybe, weight: -1, tags: [1], applies_when: {nope: 1}}\n" +
		"  - {id: d.att, title: t, csf: GV, check: attested, weight: 1, validity: 9x}\n"
	tr := newTree(t, map[string]string{"01-d.yaml": cat}, "scorecard: {unconfigured_collectors: maybe}\n")
	if code := tr.run("lint", "--instance", tr.instance); code != ExitFailed {
		t.Fatalf("lint exit %d", code)
	}
	want := `d.att: validity: bad duration '9x' (e.g. 90d, 12h)
d.att: attested controls need the question a human answers
x.bad: id prefix must be its dimension 'd' (one catalog file per dimension)
x.bad: check must be one of ('automated', 'attested', 'evidence')
x.bad: applies_when must be one of {instance: <dotted key>}, {coverage_prefix: <asset prefix>}, {any: [..]}
x.bad: tags must be a list of strings
x.bad: csf 'ZZ' must start with one of ['DE', 'GV', 'ID', 'PR', 'RC', 'RS']
x.bad: pillars must be a non-empty subset of ['network', 'device', 'people', 'software']
x.bad: weight must be a number >= 0
instance scorecard: unconfigured_collectors must be unknown or not_applicable
1 dimensions, 3 controls, 10 error(s)
`
	if got := tr.stderr.String(); got != want {
		t.Errorf("lint:\n%s\nwant\n%s", got, want)
	}
	if code := tr.run("list", "--dimension", "d"); code != ExitOK {
		t.Fatalf("list exit %d: %s", code, tr.stderr.String())
	}
	if got := tr.stdout.String(); !strings.HasPrefix(got, "d.att                                         attested  w=1   device                   GV       t\n") {
		t.Errorf("list:\n%q", got)
	}
}
