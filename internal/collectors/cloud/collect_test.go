package cloud

import (
	"bytes"
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/MIERAI/security-platform/internal/cloud/dyn"
)

func TestCollectScanMergesEnginesAndImports(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(fakeSTS("arn:aws:iam::aws:policy/SecurityAudit"))
	t.Cleanup(srv.Close)
	tok := jwtFile(t)
	inst := awsInstance(srv.URL, tok, []any{"prowler", "scoutsuite", "steampipe", "nmap"})
	fixtures := filepath.Join("..", "..", "..", "tests", "fixtures", "cloud")
	abs, err := filepath.Abs(fixtures)
	if err != nil {
		t.Fatal(err)
	}
	dyn.Map(inst["cloud"])["imports"] = []any{
		map[string]any{"type": "securityhub", "file": filepath.Join(abs, "securityhub-asff.json"), "max_age": "100000d"},
		map[string]any{"type": "scc", "file": filepath.Join(abs, "absent.json")},
		map[string]any{"type": "guardduty", "file": "x"},
	}
	o := collect(t, inst, nil)
	cov := coverage(o.doc)
	want := map[string]string{
		"cloud:aws/000000000000":             "ok: <nil>",
		"cloud:aws/000000000000/engine:nmap": "gap: unknown engine nmap (prowler, steampipe, scoutsuite)",
		"cloud:aws/000000000000/inspector2":  "gap: prowler could not list inspector2: AccessDenied",
		"cloud:import/scc":                   "gap: export unreadable: FileNotFoundError",
		"cloud:import/guardduty":             "gap: unknown import type guardduty (securityhub, scc, defender)",
		"cloud:aws/000000000000/cloudtrail":  "",
	}
	for asset, w := range want {
		if w != "" && cov[asset] != w {
			t.Errorf("coverage %s = %q, want %q", asset, cov[asset], w)
		}
	}
	if _, ok := cov["cloud:aws/000000000000/cloudtrail"]; ok {
		t.Errorf("cloudtrail is a gap although Prowler covered it cleanly: %v", cov)
	}
	f := findingsBy(o.doc)["cloud.storage_public cloud:aws/000000000000/s3/global/acme-public-assets"]
	if f == nil {
		t.Fatalf("no merged public-bucket finding in %v", o.doc["findings"])
	}
	engines := at(f, "attributes", "engines")
	if !reflect.DeepEqual(engines, []any{"prowler", "scoutsuite", "securityhub", "steampipe"}) {
		t.Fatalf("public bucket engines %v", engines)
	}
	if !strings.Contains(o.prom, `security_cloud_accounts{collector="cloud",state="scanned"} 1`) ||
		!strings.Contains(o.prom, `security_cloud_engine_runs{collector="cloud",result="ok",source="steampipe"} 1`) {
		t.Fatalf("metrics:\n%s", o.prom)
	}
	assertClean(t, o)
}

func assertClean(t *testing.T, o runOut) {
	t.Helper()
	left, _ := filepath.Glob(filepath.Join(o.tmp, "sp-cloud-*"))
	if len(left) > 0 {
		t.Errorf("temporary directories left: %v", left)
	}
	err := filepath.WalkDir(filepath.Dir(o.run), func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(p)
		for _, secret := range []string{"collector-secret", "collector-session", "ASIACOLLECTORTEST000"} {
			if strings.Contains(string(data), secret) {
				t.Errorf("%s holds credential material", p)
			}
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	logs, _ := filepath.Glob(o.log + ".*")
	for _, l := range logs {
		data, err := os.ReadFile(l)
		if err != nil || strings.Contains(string(data), `"ambient":true`) || !strings.Contains(string(data), `"profile":"security-platform"`) {
			t.Errorf("engine environment %s: %s", l, data)
		}
	}
}

func TestCollectRefusesOverPrivileged(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(fakeSTS("arn:aws:iam::000000000000:policy/admin"))
	t.Cleanup(srv.Close)
	o := collect(t, awsInstance(srv.URL, jwtFile(t), []any{"prowler"}), map[string]string{"SP_COLLECTOR_NAME": "cloud-site"})
	cov := coverage(o.doc)
	if cov["cloud:aws/000000000000"] != "gap: refused to scan: the platform's credential is over-privileged (read-only expected)" {
		t.Fatalf("coverage %v", cov)
	}
	f := findingsBy(o.doc)["cloud.platform_credential_over_privileged cloud:aws/000000000000"]
	if f == nil || f["owner"] != "human" || f["evidence"] != "raw/cloud-site/aws-000000000000.json#self_check" ||
		f["title"] != "the platform's credential for aws 000000000000 can write: arn:aws:iam::000000000000:policy/admin" {
		t.Fatalf("finding %v", f)
	}
	if logs, _ := filepath.Glob(o.log + ".*"); len(logs) > 0 {
		t.Fatalf("an engine ran against a refused account: %v", logs)
	}
	ev := o.raw["aws-000000000000.json"]
	if at(ev, "self_check", "write_capable", 0) != "arn:aws:iam::000000000000:policy/admin" ||
		at(ev, "identity", "principal") != "arn:aws:sts::000000000000:assumed-role/audit/sp" {
		t.Fatalf("evidence %v", ev)
	}
}

func TestCollectAuthFailuresAreGaps(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		acct map[string]any
		want map[string]string
	}{
		{"unknown provider", map[string]any{"provider": "oracle", "name": "x"},
			map[string]string{"cloud:oracle/x": "gap: provider 'oracle' unknown (aws, gcp, azure)"}},
		{"long-lived key", map[string]any{"provider": "aws", "account_id": "1", "secret_access_key": "k"},
			map[string]string{"cloud:aws/1": "gap: long-lived credentials are not accepted (secret_access_key): use federation/short-lived roles"}},
		{"token missing", map[string]any{"provider": "aws", "account_id": "1", "role_arn": "r", "identity_token": map[string]any{"path": "/nonexistent"}},
			map[string]string{"cloud:aws/1": "gap: authentication failed: identity token unavailable: FileNotFoundError"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			o := collect(t, map[string]any{"cloud": map[string]any{"accounts": []any{tc.acct}}}, nil)
			if got := coverage(o.doc); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("coverage %v", got)
			}
			if len(dyn.List(o.doc["findings"])) != 0 {
				t.Fatal("a gap is not 'no findings'")
			}
		})
	}
}

func TestCollectConfigurationErrors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	yaml := filepath.Join(dir, "instance.yaml")
	if err := os.WriteFile(yaml, []byte("cloud: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"no instance", map[string]string{"SP_RUN_DIR": dir}, "SP_INSTANCE not set"},
		{"no run dir", map[string]string{"SP_INSTANCE": yaml}, "SP_RUN_DIR not set"},
		{"broken yaml", map[string]string{"SP_INSTANCE": yaml, "SP_RUN_DIR": dir}, "not YAML/JSON"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var stderr bytes.Buffer
			code := Main(context.Background(), []string{"collect"}, Env{Getenv: func(k string) string { return tc.env[k] },
				Stderr: &stderr}, &bytes.Buffer{})
			if code != 2 || !strings.Contains(stderr.String(), tc.want) {
				t.Fatalf("exit %d, stderr %q", code, stderr.String())
			}
		})
	}
	err := Collect(context.Background(), Env{Getenv: func(string) string { return "" }})
	if !errors.Is(err, ErrUsage) {
		t.Fatalf("got %v", err)
	}
}

func TestMainUsage(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{nil, {"nope"}, {"collect", "x"}, {"discover"}, {"credential-process", "a", "b"}} {
		var stderr bytes.Buffer
		if code := Main(context.Background(), args, Env{Stderr: &stderr}, &bytes.Buffer{}); code != 2 ||
			!strings.Contains(stderr.String(), "usage: sp cloud collect") {
			t.Errorf("%v: exit %d %q", args, code, stderr.String())
		}
	}
	var stderr bytes.Buffer
	code := Main(context.Background(), []string{"credential-process", filepath.Join(t.TempDir(), "absent.json")},
		Env{Stderr: &stderr, Getenv: func(string) string { return "" }}, &bytes.Buffer{})
	if code != 1 || !strings.Contains(stderr.String(), "account file unreadable: FileNotFoundError") {
		t.Fatalf("exit %d %q", code, stderr.String())
	}
}

func TestEngineOrderFollowsTheInstance(t *testing.T) {
	t.Parallel()
	tests := []struct{ name, doc string }{
		{"json", `{"cloud": {"x": {"engines": 1}, "engines": {"steampipe": {}, "prowler": {"a": [1]}, "scoutsuite": null},
			"refuse_over_privileged": false, "accounts": [{"account_id": "000000000000", "session_seconds": 900}]}}`},
		{"yaml", "cloud:\n  x: {engines: 1}\n  engines:\n    steampipe: {}\n    prowler: {a: [1]}\n    scoutsuite:\n" +
			"  refuse_over_privileged: no\n  accounts:\n    - {account_id: \"000000000000\", session_seconds: 900}\n"},
	}
	for _, tc := range tests {
		cfg, err := parseInstance([]byte(tc.doc))
		if err != nil {
			t.Fatal(err)
		}
		acct := dyn.Map(dyn.List(cfg.cloud["accounts"])[0])
		if !reflect.DeepEqual(cfg.engineOrder, []string{"steampipe", "prowler", "scoutsuite"}) ||
			dyn.Truthy(cfg.cloud["refuse_over_privileged"]) || dyn.Str(acct["account_id"]) != "000000000000" ||
			dyn.Str(acct["session_seconds"]) != "900" {
			t.Fatalf("%s: order %v, cloud %v", tc.name, cfg.engineOrder, cfg.cloud)
		}
	}
	if _, err := parseInstance([]byte(`[1]`)); err == nil {
		t.Fatal("a non-object instance was accepted")
	}
}

func TestSeconds(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   any
		want int
	}{{nil, 7}, {"90", 90}, {"10m", 600}, {" 3h ", 10800}, {"2d", 172800}, {"1w", 7}, {"-1", 7}, {true, 7}}
	for _, tc := range tests {
		if got := Seconds(tc.in, 7); got != tc.want {
			t.Errorf("Seconds(%v) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
