package remediation

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
)

// t0 is 2026-11-01T08:00:00Z.
const (
	t0  = 1793520000.0
	day = 86400.0
)

func obj(t *testing.T, s string) *pyjson.Object {
	t.Helper()
	v, err := pyjson.Decode([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	o, _ := v.(*pyjson.Object)
	return o
}

func TestSLOSeconds(t *testing.T) {
	t.Parallel()
	def := map[string]int64{"kev_exposed": 86400, "critical": 604800, "high": 2592000, "medium": 7776000, "low": 15552000}
	// with returns the default table changed by alternating class, seconds pairs (0 removes the class).
	with := func(kv ...any) map[string]int64 {
		m := map[string]int64{}
		for a, b := range def {
			m[a] = b
		}
		for i := 0; i+1 < len(kv); i += 2 {
			k, _ := kv[i].(string)
			v, _ := kv[i+1].(int)
			if v == 0 {
				delete(m, k)
			} else {
				m[k] = int64(v)
			}
		}
		return m
	}
	tests := []struct {
		name, cfg string
		want      map[string]int64
		err       bool
	}{
		{"no config", `{}`, def, false},
		{"null slo", `{"slo": null}`, def, false},
		{"override and add", `{"slo": {"critical": "2d", "info": "1w"}}`, with("critical", 172800, "info", 604800), false},
		{"fractions and units", `{"slo": {"critical": "1.5d", "high": "90m", "low": 3600.9}}`,
			with("critical", 129600, "high", 5400, "low", 3600), false},
		{"plain seconds", `{"slo": {"critical": " 600 "}}`, with("critical", 600), false},
		{"disable a class", `{"slo": {"low": 0, "medium": ""}}`, with("medium", 0, "low", 0), false},
		{"bad unit", `{"slo": {"critical": "7D"}}`, nil, true},
		{"not a mapping", `{"slo": [1]}`, nil, true},
		{"not a duration", `{"slo": {"critical": {}}}`, nil, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := SLOSeconds(obj(t, tc.cfg))
			if tc.err != errors.Is(err, ErrConfig) || (!tc.err && !reflect.DeepEqual(got, tc.want)) {
				t.Fatalf("SLOSeconds = %v, %v; want %v (error: %v)", got, err, tc.want, tc.err)
			}
		})
	}
}

func TestOwnerOf(t *testing.T) {
	t.Parallel()
	cfg := `{"default_owner": "oncall", "owners": [{"layer_in": ["workload"], "owner": "platform-team"},
		{"asset_prefix": "repo:", "severity_in": ["high", "critical"], "owner": "dev-team"}, "not a rule"]}`
	tests := []struct {
		name, entry, cfg, owner, source string
	}{
		{"layer rule", `{"layer": "workload", "asset": "k8s-workload:c/x", "owner": "team-x"}`, cfg, "platform-team", "rule"},
		{"two conditions", `{"layer": "supply-chain", "severity": "high", "asset": "repo:x"}`, cfg, "dev-team", "rule"},
		{"one condition fails", `{"layer": "supply-chain", "severity": "low", "asset": "repo:x", "owner": "team-y"}`, cfg, "team-y", "finding"},
		{"role hint is not a team", `{"layer": "host", "asset": "host:a", "owner": "platform"}`, cfg, "oncall", "default"},
		{"nothing", `{"layer": "host", "asset": "host:a", "owner": "human"}`, `{}`, "unassigned", "none"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			o, src := ownerOf(obj(t, tc.entry), obj(t, tc.cfg))
			if o != tc.owner || src != tc.source {
				t.Fatalf("ownerOf = %v, %s; want %s, %s", o, src, tc.owner, tc.source)
			}
		})
	}
}

// entryJSON is a ledger entry with the given status fields.
func entryJSON(id, extra string) string {
	return `{"id": "` + id + `", "check": "ssh.password_auth_enabled", "layer": "host", "asset": "host:web", "title": "SSH | passwords",
		"severity": "critical", "remediation": "disable it", "needs_human": false, "owner": "platform",
		"first_seen": "2026-11-01T08:00:00Z", ` + extra + `}`
}

func TestUpdateLifecycle(t *testing.T) {
	t.Parallel()
	slo, err := SLOSeconds(nil)
	if err != nil {
		t.Fatal(err)
	}
	items := pyjson.NewObject()
	steps := []struct {
		at    float64
		entry string
		want  map[string]string // field -> Repr
	}{
		{t0 + day, `"status": "open"`, map[string]string{"due_at": "'2026-11-08T08:00:00Z'", "overdue": "False", "slo_class": "'critical'"}},
		{t0 + 8*day, `"status": "open"`, map[string]string{"overdue": "True"}},
		{t0 + 9*day, `"status": "accepted", "exception": {"approved_by": "reviewer", "expires": "2027-01-01", "reason": "lab"}`,
			map[string]string{"overdue": "False", "exception": "{'approved_by': 'reviewer', 'expires': '2027-01-01', 'reason': 'lab'}"}},
		{t0 + 10*day, `"status": "open", "exception": {"expired": true}`,
			map[string]string{"reopen_reason": "'exception expired'", "reopened_at": "'2026-11-11T08:00:00Z'", "due_at": "'2026-11-18T08:00:00Z'"}},
		{t0 + 12*day, `"status": "fixed", "fixed_at": "2026-11-12T08:00:00Z"`,
			map[string]string{"closed_at": "'2026-11-12T08:00:00Z'", "time_to_remediate_days": "1.0", "overdue": "False"}},
		{t0 + 13*day, `"status": "open"`, map[string]string{"reopen_reason": "'regression'", "closed_at": "None",
			"time_to_remediate_days": "None"}},
	}
	for i, st := range steps {
		entries := obj(t, `{"233790a18561": `+entryJSON("233790a18561", st.entry)+`}`)
		Update(items, entries, nil, st.at, slo)
		it := items.Obj("233790a18561")
		for k, want := range st.want {
			if v, _ := it.Get(k); pyjson.Repr(v) != want {
				t.Errorf("step %d: %s = %s, want %s", i, k, pyjson.Repr(v), want)
			}
		}
	}
	if h := items.Obj("233790a18561").List("history"); len(h) != 5 {
		t.Errorf("history %s", pyjson.Repr(h))
	}
}

func TestUpdateSkipsEntriesFixedOnFirstSight(t *testing.T) {
	t.Parallel()
	items := pyjson.NewObject()
	Update(items, obj(t, `{"a": `+entryJSON("a", `"status": "fixed"`)+`}`), nil, t0, map[string]int64{})
	if items.Len() != 0 {
		t.Fatalf("items = %s", pyjson.Repr(items))
	}
}

// fakeGH records calls and answers like the GitHub API.
type fakeGH struct {
	private bool
	calls   []string
	fail    bool
}

func (f *fakeGH) run(_ context.Context, args []string, stdin []byte, _ []string) ([]byte, error) {
	f.calls = append(f.calls, strings.Join(args, " ")+" "+string(stdin))
	switch {
	case f.fail:
		return nil, errors.New("gh: network down")
	case len(args) == 1:
		if f.private {
			return []byte(`{"private": true}`), nil
		}
		return []byte(`{"private": false}`), nil
	case args[len(args)-1] == "POST":
		return []byte(`{"number": 7}`), nil
	default:
		return []byte(`{}`), nil
	}
}

func trackSandbox(t *testing.T, ledger string) string {
	t.Helper()
	data := t.TempDir()
	if err := os.WriteFile(filepath.Join(data, "ledger.json"), []byte(ledger), 0o600); err != nil {
		t.Fatal(err)
	}
	return data
}

func TestTrackTrackers(t *testing.T) {
	t.Parallel()
	ledger := `{"schema": "security-platform/ledger/v1", "runs": [], "entries": {"233790a18561": ` + entryJSON("233790a18561", `"status": "open"`) + `}}`
	gh := `{"tracker": {"type": "github-issues", "repo": "example/private-tracker", "enabled": true}}`
	tests := []struct {
		name, cfg  string
		gh         *fakeGH
		noExternal bool
		wantErr    error
		wantCalls  int
		wantFile   string
	}{
		{name: "default files", cfg: `{}`, gh: &fakeGH{}, wantFile: "tracker/233790a18561.md"},
		{name: "github private", cfg: gh, gh: &fakeGH{private: true}, wantCalls: 2, wantFile: "tracker/github-issues.json"},
		{name: "github public refused", cfg: gh, gh: &fakeGH{}, wantErr: ErrNotPrivate, wantCalls: 1},
		{name: "github not enabled", cfg: `{"tracker": {"type": "github-issues", "repo": "a/b"}}`, gh: &fakeGH{}},
		{name: "shadow: no external sync", cfg: gh, gh: &fakeGH{private: true}, noExternal: true},
		{name: "future tracker", cfg: `{"tracker": {"type": "jira"}}`, gh: &fakeGH{}, wantErr: ErrConfig},
		{name: "future advisor", cfg: `{"advisor": {"type": "claude"}}`, gh: &fakeGH{}, wantErr: ErrConfig},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			data := trackSandbox(t, ledger)
			var stderr bytes.Buffer
			err := Track(context.Background(), Options{Data: data, Config: obj(t, tc.cfg), Now: t0 + day, Wall: t0 + day,
				NoExternalSync: tc.noExternal, Version: "0.0.0-test", Stderr: &stderr, GH: tc.gh.run})
			if !errors.Is(err, tc.wantErr) || (tc.wantErr == nil && err != nil) {
				t.Fatalf("Track error = %v, want %v", err, tc.wantErr)
			}
			if len(tc.gh.calls) != tc.wantCalls {
				t.Fatalf("gh calls: %q", tc.gh.calls)
			}
			wantFiles := map[string]bool{"tracker/items.json": tc.wantErr == nil}
			if tc.wantFile != "" {
				wantFiles[tc.wantFile] = true
			}
			checkFiles(t, data, wantFiles)
		})
	}
}

// checkFiles: each file (slash path under data) exists or not, as wanted.
func checkFiles(t *testing.T, data string, want map[string]bool) {
	t.Helper()
	for name, exists := range want {
		_, err := os.Stat(filepath.Join(data, filepath.FromSlash(name)))
		if (err == nil) != exists {
			t.Errorf("%s exists = %v, want %v", name, err == nil, exists)
		}
	}
}

func TestFilesTrackerText(t *testing.T) {
	t.Parallel()
	ledger := `{"schema": "security-platform/ledger/v1", "runs": [], "entries": {"233790a18561": ` + entryJSON("233790a18561", `"status": "open"`) + `}}`
	data := trackSandbox(t, ledger)
	opt := Options{Data: data, Now: t0 + 9*day, Wall: t0, Version: "0.0.0-test", Stderr: &bytes.Buffer{}}
	if err := Track(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	md, err := os.ReadFile(filepath.Join(data, "tracker", "233790a18561.md"))
	if err != nil {
		t.Fatal(err)
	}
	want := "<!-- status: open -->\n# [critical] SSH | passwords\n\nPRIVATE - attacker intelligence.\n\n" +
		"- status: open (OVERDUE)\n- severity: critical (SLO class critical), due: 2026-11-08T08:00:00Z\n" +
		"- owner: unassigned (none)\n- layer / check: host / `ssh.password_auth_enabled`\n- asset: `host:web`\n" +
		"- opened: 2026-11-01T08:00:00Z\n- needs a human: no\n\n## Remediation\n\ndisable it\n\n" +
		"Closure: only a collector run that covers the asset closes this item. Exceptions: exceptions.yaml (approved_by + expires).\n"
	if string(md) != want {
		t.Fatalf("item file:\n%s\nwant:\n%s", md, want)
	}
	readmeText, err := os.ReadFile(filepath.Join(data, "tracker", "README.md"))
	if err != nil || !strings.Contains(string(readmeText), "| **OVERDUE** | critical | 2026-11-08 | unassigned | SSH / passwords | [233790a18561](233790a18561.md) |") {
		t.Fatalf("README:\n%s %v", readmeText, err)
	}
	prom, err := os.ReadFile(filepath.Join(data, "metrics", "remediation.prom"))
	if err != nil || !strings.Contains(string(prom), "security_remediation_overdue{severity=\"critical\"} 1\n") ||
		!strings.Contains(string(prom), "security_remediation_last_update_timestamp_seconds 1793520000\n") {
		t.Fatalf("remediation.prom:\n%s %v", prom, err)
	}
}

func TestGitHubIssuesLifecycle(t *testing.T) {
	t.Parallel()
	cfg := obj(t, `{"tracker": {"type": "github-issues", "repo": "example/private-tracker", "enabled": true, "label": "sec"}}`)
	led := func(extra string) string {
		return `{"schema": "security-platform/ledger/v1", "runs": [], "entries": {"233790a18561": ` + entryJSON("233790a18561", extra) + `}}`
	}
	data := trackSandbox(t, led(`"status": "open"`))
	gh := &fakeGH{private: true}
	run := func(now float64) {
		t.Helper()
		if err := Track(context.Background(), Options{Data: data, Config: cfg, Now: now, Wall: now, Version: "0", Stderr: &bytes.Buffer{}, GH: gh.run}); err != nil {
			t.Fatal(err)
		}
	}
	run(t0 + day)
	run(t0 + day) // nothing changed: only the repository check
	if err := os.WriteFile(filepath.Join(data, "ledger.json"), []byte(led(`"status": "fixed", "fixed_at": "2026-11-03T08:00:00Z"`)), 0o600); err != nil {
		t.Fatal(err)
	}
	run(t0 + 3*day)
	if len(gh.calls) != 5 || !strings.Contains(gh.calls[1], `"labels": ["sec"]`) ||
		!strings.Contains(gh.calls[4], "issues/7 -X PATCH") || !strings.Contains(gh.calls[4], `"state_reason": "completed"`) {
		t.Fatalf("calls:\n%s", strings.Join(gh.calls, "\n"))
	}
	m, err := os.ReadFile(filepath.Join(data, "tracker", "github-issues.json"))
	if err != nil || !strings.Contains(string(m), `"state": "closed"`) || !strings.Contains(string(m), `"number": 7`) {
		t.Fatalf("map: %s %v", m, err)
	}
	gh.fail = true
	if err := Track(context.Background(), Options{Data: data, Config: cfg, Now: t0 + 4*day, Stderr: &bytes.Buffer{}, GH: gh.run}); err == nil {
		t.Fatal("a failing gh must fail the track")
	}
}
