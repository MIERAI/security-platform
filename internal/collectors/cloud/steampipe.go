package cloud

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/cloud"
	"github.com/MIERAI/security-platform/internal/cloud/dyn"
	"github.com/MIERAI/security-platform/internal/textsafe"
)

const shortTmpLimit = 40 // Steampipe's plugin sockets live in TMPDIR: a long path exceeds the socket path limit

// runSteampipe runs this product's query pack through `steampipe query --output json --search-path sp_<provider>`.
// Steampipe v2 reads connections only from <install_dir>/config, so the run writes its connection (profile name,
// regions, endpoint: no secret) there and removes it afterwards. Credentials come from the engine environment
// (credential_process).
func runSteampipe(ctx context.Context, e *engineCall) *Run {
	run := newRun("steampipe")
	queries := steampipeQueries()[e.prov.Kind()]
	if len(queries) == 0 {
		run.Reason = "steampipe: no query pack for " + e.prov.Kind()
		return run
	}
	if only := e.ecfg.List("queries"); len(only) > 0 {
		queries = selectQueries(queries, only)
	}
	home := cloud.ExpandUser(dyn.Or(e.ecfg.Str("install_dir"), "~/.steampipe"), e.home)
	exe := e.path("steampipe")
	env := copyEnv(e.env)
	env["STEAMPIPE_INSTALL_DIR"], env["STEAMPIPE_UPDATE_CHECK"], env["STEAMPIPE_TELEMETRY"] = home, "false", "none"
	shortTmp := shortTempDir(env)
	defer removeAll(shortTmp, e.warn)
	pr := runProcess(ctx, []string{exe, "--version"}, env, e.workdir, time.Minute)
	if pr.rc != 0 {
		run.Reason = "steampipe unavailable: " + dyn.Cut(strings.TrimSpace(dyn.Or(pr.stderr, pr.stdout)), 160)
		return run
	}
	if f := strings.Fields(pr.stdout); len(f) > 0 {
		run.Version = strings.TrimLeft(f[len(f)-1], "v")
	}
	for _, q := range queries {
		run.Scope[q.Service] = true
	}
	spc := filepath.Join(home, "config", "security-platform-"+e.prov.Kind()+".spc")
	defer removeAll(spc, e.warn)
	if err := writeConnection(spc, e, env); err != nil {
		run.Reason = "steampipe: cannot write its connection file"
		return run
	}
	failed := 0
	sr := steampipeRun{e: e, run: run, env: env, timeout: time.Duration(Seconds(e.ecfg["timeout"], 600)) * time.Second}
	for _, q := range queries {
		if !sr.query(ctx, q) {
			failed++
		}
	}
	run.OK = failed < len(queries)
	if !run.OK {
		firsts := make([]string, 0, len(run.Errors.keys))
		for _, k := range run.Errors.keys {
			firsts = append(firsts, run.Errors.m[k][0])
		}
		run.Reason = "steampipe: every query failed: " + dyn.Cut(strings.Join(firsts, "; "), 200)
	}
	return run
}

func selectQueries(all []steampipeQuery, only []string) []steampipeQuery {
	var out []steampipeQuery
	for _, q := range all {
		for _, id := range only {
			if q.ID == id {
				out = append(out, q)
				break
			}
		}
	}
	return out
}

func copyEnv(env map[string]string) map[string]string {
	out := make(map[string]string, len(env)+3)
	for k, v := range env {
		out[k] = v
	}
	return out
}

// shortTempDir points TMPDIR at a short private directory when the current one is too long; "" when not needed.
func shortTempDir(env map[string]string) string {
	cur := env["TMPDIR"]
	if cur == "" {
		cur = os.TempDir()
	}
	if len(cur) <= shortTmpLimit {
		return ""
	}
	parent := ""
	if st, err := os.Stat("/tmp"); err == nil && st.IsDir() {
		parent = "/tmp"
	}
	dir, err := os.MkdirTemp(parent, "sp-sp-")
	if err != nil {
		return ""
	}
	env["TMPDIR"] = dir
	return dir
}

// removeAll removes a file or directory the run created; what cannot be removed is reported on warn (it holds no
// secret: engine configuration and the workload's short-lived assertion at most, in a 0700 directory).
func removeAll(path string, warn io.Writer) {
	if path == "" {
		return
	}
	if err := os.RemoveAll(path); err != nil {
		_, _ = fmt.Fprintln(warn, "warning: could not remove "+textsafe.Line(path)) // best effort, like the removal
	}
}

func writeConnection(spc string, e *engineCall, env map[string]string) error {
	name := "sp_" + e.prov.Kind()
	quoted := make([]string, len(e.args.Regions))
	for i, r := range e.args.Regions {
		quoted[i] = `"` + r + `"`
	}
	lines := []string{"connection \"" + name + "\" {", "  plugin = \"" + e.ecfg.StrOr("plugin", e.prov.Kind()) + "\"",
		"  profile = \"" + e.args.Profile + "\"", "  regions = [" + strings.Join(quoted, ", ") + "]",
		"  max_error_retry_attempts = 2"}
	if ep := env["AWS_ENDPOINT_URL"]; ep != "" {
		lines = append(lines, "  endpoint_url = \""+ep+"\"", "  s3_force_path_style = true")
	}
	body := "# written by security-platform for one run; removed afterwards\n" + strings.Join(append(lines, "}"), "\n") + "\n"
	if err := os.MkdirAll(filepath.Dir(spc), 0o750); err != nil {
		return fmt.Errorf("create the connection directory: %w", err)
	}
	if err := os.WriteFile(spc, []byte(body), 0o600); err != nil {
		return fmt.Errorf("write the connection file: %w", err)
	}
	return nil
}

// steampipeRun is one Steampipe run against one account.
type steampipeRun struct {
	e       *engineCall
	run     *Run
	env     map[string]string
	timeout time.Duration
}

// query runs one query; false when it failed (the service is then an error of this run).
func (sr steampipeRun) query(ctx context.Context, q steampipeQuery) bool {
	e, run := sr.e, sr.run
	region := ""
	if len(e.args.Regions) > 0 {
		region = e.args.Regions[0]
	}
	pr := runProcess(ctx, []string{e.path("steampipe"), "query", "--output", "json", "--search-path", "sp_" + e.prov.Kind(),
		strings.ReplaceAll(q.SQL, "{region}", region)}, sr.env, e.workdir, sr.timeout)
	var errLines []string
	for _, ln := range strings.Split(pr.stderr+"\n"+pr.stdout, "\n") {
		if strings.HasPrefix(ln, "Error:") || strings.HasPrefix(ln, "Warning: query") {
			errLines = append(errLines, ln)
		}
	}
	rows, ok := steampipeRows(pr.stdout)
	if pr.rc != 0 || len(errLines) > 0 || !ok {
		why := "rc=" + strconv.Itoa(pr.rc)
		if len(errLines) > 0 {
			why = errLines[0]
		}
		run.error(q.Service, q.ID+": "+dyn.Cut(why, 180))
		return false
	}
	run.Results = append(run.Results, Result{Source: "steampipe", Provider: e.prov.Kind(), Account: e.prov.Account(),
		Service: q.Service, Region: region, Check: q.ID, Control: q.Control, Status: "PASS", Severity: "info",
		Title: q.ID, Detail: "query ran", Refs: []string{}, CoverageOnly: true})
	for _, r := range rows {
		row := dyn.Map(r)
		run.Results = append(run.Results, Result{Source: "steampipe", Provider: e.prov.Kind(),
			Account: dyn.Or(dyn.Text(row, "account_id"), e.prov.Account()), Service: q.Service,
			Region: dyn.Or(dyn.Text(row, "region"), "global"), Resource: dyn.Text(row, "arn"), Check: q.ID,
			Control: q.Control, Status: "FAIL", Severity: q.Severity, Title: q.ID, Detail: dyn.Text(row, "detail"),
			Refs: []string{}})
	}
	return true
}

// steampipeRows parses `steampipe query --output json` ({"rows": [...]}, possibly after other output).
func steampipeRows(stdout string) ([]any, bool) {
	i := strings.Index(stdout, "{")
	if i < 0 {
		return nil, false
	}
	v, err := dyn.Decode([]byte(stdout[i:]))
	if err != nil {
		return nil, false
	}
	rows, ok := dyn.Map(v)["rows"]
	if !ok || rows == nil {
		return nil, false
	}
	return dyn.List(rows), true
}
