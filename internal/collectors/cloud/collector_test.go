package cloud

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/MIERAI/security-platform/internal/cloud/dyn"
)

// The test binary doubles as the engines (Prowler, ScoutSuite, Steampipe): with SP_FAKE_ENGINE set it acts like
// one, writing the shared fixtures where the real tool writes its output.
func TestMain(m *testing.M) {
	if os.Getenv("SP_FAKE_ENGINE") != "" {
		os.Exit(fakeEngine(os.Args[1:]))
	}
	os.Exit(m.Run())
}

func fakeEngine(args []string) int {
	log := map[string]any{"argv": args, "ambient": os.Getenv("AWS_ACCESS_KEY_ID") != "", "profile": os.Getenv("AWS_PROFILE")}
	data, _ := json.Marshal(log)
	_ = os.WriteFile(os.Getenv("SP_FAKE_LOG")+"."+args[0], data, 0o600)
	fx := os.Getenv("SP_FAKE_FIXTURES")
	switch {
	case slices.Contains(args, "--output-formats"): // prowler
		out := args[slices.Index(args, "-o")+1]
		_ = os.MkdirAll(out, 0o700)
		copyFile(filepath.Join(fx, "prowler-aws.ocsf.json"), filepath.Join(out, "scan.ocsf.json"))
		_ = os.WriteFile(filepath.Join(out, "prowler.log"),
			[]byte(`{"level":"ERROR","module":"inspector2_service","message":"AccessDenied"}`+"\n"), 0o600)
	case slices.Contains(args, "--report-dir"): // scoutsuite
		dir := filepath.Join(args[slices.Index(args, "--report-dir")+1], "scoutsuite-results")
		_ = os.MkdirAll(dir, 0o700)
		body, _ := os.ReadFile(filepath.Join(fx, "scoutsuite-aws.json"))
		_ = os.WriteFile(filepath.Join(dir, "scoutsuite_results_aws-1.js"), append([]byte("scoutsuite_results =\n"), body...), 0o600)
	case args[0] == "--version": // steampipe
		fmt.Println("Steampipe v2.0.0")
	case args[0] == "query":
		if strings.Contains(args[len(args)-1], "cloudtrail") {
			fmt.Println("Error: sp_aws: operation error CloudTrail: DescribeTrails, StatusCode: 501")
			return 1
		}
		if strings.Contains(args[len(args)-1], "block_public_policy") {
			fmt.Println(`{"rows":[{"arn":"arn:aws:s3:::acme-public-assets","region":"us-east-1","account_id":"000000000000","detail":"public"}]}`)
			return 0
		}
		fmt.Println(`{"rows":[]}`)
	}
	return 0
}

func copyFile(from, to string) {
	data, err := os.ReadFile(from)
	if err == nil {
		_ = os.WriteFile(to, data, 0o600)
	}
}

// fakeSTS answers the four STS/IAM calls of an AWS account's login and self-check.
func fakeSTS(policies ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		action := r.Form.Get("Action")
		var body string
		switch action {
		case "AssumeRoleWithWebIdentity":
			body = "<Credentials><AccessKeyId>ASIACOLLECTORTEST000</AccessKeyId><SecretAccessKey>collector-secret</SecretAccessKey>" +
				"<SessionToken>collector-session</SessionToken><Expiration>" + time.Now().Add(time.Hour).UTC().Format(time.RFC3339) +
				"</Expiration></Credentials>"
		case "GetCallerIdentity":
			body = "<Arn>arn:aws:sts::000000000000:assumed-role/audit/sp</Arn><Account>000000000000</Account>"
		case "GetRole":
			body = "<Role><RoleName>audit</RoleName><Path>/</Path><RoleId>R</RoleId><Arn>a</Arn><CreateDate>2020-01-01T00:00:00Z</CreateDate></Role>"
		case "ListAttachedRolePolicies":
			for _, p := range policies {
				body += "<member><PolicyArn>" + p + "</PolicyArn></member>"
			}
			body = "<AttachedPolicies>" + body + "</AttachedPolicies><IsTruncated>false</IsTruncated>"
		case "GetPolicy":
			body = "<Policy><DefaultVersionId>v1</DefaultVersionId></Policy>"
		case "GetPolicyVersion":
			body = `<PolicyVersion><Document>%7B%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%22%2A%22%7D%5D%7D</Document></PolicyVersion>`
		case "ListRolePolicies":
			body = "<PolicyNames></PolicyNames><IsTruncated>false</IsTruncated>"
		}
		_, _ = fmt.Fprintf(w, "<%sResponse><%sResult>%s</%sResult></%sResponse>", action, action, body, action, action)
	})
}

func jwtFile(t *testing.T) string {
	t.Helper()
	claims, _ := json.Marshal(map[string]any{"aud": "sts.amazonaws.com", "exp": time.Now().Add(time.Hour).Unix()})
	tok := "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(claims) + ".sig"
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte(tok), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

type runOut struct {
	doc    map[string]any
	prom   string
	raw    map[string]any
	stderr string
	tmp    string
	run    string
	log    string
}

func collect(t *testing.T, inst map[string]any, extraEnv map[string]string) runOut {
	t.Helper()
	dir := t.TempDir()
	instPath := filepath.Join(dir, "instance.json")
	data, err := json.Marshal(inst)
	if err != nil {
		t.Fatal(err)
	}
	o := runOut{run: filepath.Join(dir, "run"), tmp: filepath.Join(dir, "tmp"), log: filepath.Join(dir, "engine")}
	if werr := os.WriteFile(instPath, data, 0o600); werr != nil {
		t.Fatal(werr)
	}
	if merr := os.MkdirAll(o.tmp, 0o700); merr != nil {
		t.Fatal(merr)
	}
	fixtures, err := filepath.Abs(filepath.Join("..", "..", "..", "tests", "fixtures", "cloud"))
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"SP_RUN_DIR": o.run, "SP_INSTANCE": instPath, "TMPDIR": o.tmp, "HOME": dir, "SP_INSTANCE_NAME": "test"}
	for k, v := range extraEnv {
		env[k] = v
	}
	var stderr bytes.Buffer
	err = Collect(context.Background(), Env{Getenv: func(k string) string { return env[k] }, Stderr: &stderr,
		Environ: []string{"PATH=" + os.Getenv("PATH"), "SP_FAKE_ENGINE=1", "SP_FAKE_FIXTURES=" + fixtures, "SP_FAKE_LOG=" + o.log,
			"AWS_ACCESS_KEY_ID=ambient-admin-key"}, Executable: "/opt/sp/bin/sp", GOOS: "linux"})
	if err != nil {
		t.Fatal(err)
	}
	o.stderr = stderr.String()
	name := env["SP_COLLECTOR_NAME"]
	if name == "" {
		name = "cloud"
	}
	o.doc = readJSON(t, filepath.Join(o.run, name+".findings.json"))
	prom, err := os.ReadFile(filepath.Join(o.run, name+".prom"))
	if err != nil {
		t.Fatal(err)
	}
	o.prom = string(prom)
	o.raw = map[string]any{}
	files, _ := filepath.Glob(filepath.Join(o.run, "raw", name, "*.json"))
	for _, f := range files {
		o.raw[filepath.Base(f)] = readJSON(t, f)
	}
	return o
}

func readJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// at walks decoded JSON: at(doc, "findings", 0, "asset"); nil where the path does not exist.
func at(v any, path ...any) any {
	for _, p := range path {
		switch k := p.(type) {
		case string:
			v = dyn.Map(v)[k]
		case int:
			l := dyn.List(v)
			if k >= len(l) {
				return nil
			}
			v = l[k]
		}
	}
	return v
}

func coverage(doc map[string]any) map[string]string {
	out := map[string]string{}
	for _, c := range dyn.List(doc["coverage"]) {
		out[dyn.Str(at(c, "asset"))] = dyn.Str(at(c, "status")) + ": " + fmt.Sprint(at(c, "reason"))
	}
	return out
}

func findingsBy(doc map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, f := range dyn.List(doc["findings"]) {
		out[dyn.Str(at(f, "check"))+" "+dyn.Str(at(f, "asset"))] = dyn.Map(f)
	}
	return out
}

func awsInstance(url, token string, engines []any) map[string]any {
	fake, _ := os.Executable()
	return map[string]any{"cloud": map[string]any{
		"accounts": []any{map[string]any{"provider": "aws", "account_id": "000000000000", "role_arn": "arn:aws:iam::000000000000:role/audit",
			"audience": "sts.amazonaws.com", "identity_token": map[string]any{"path": token}, "endpoint_url": url,
			"regions": []any{"us-east-1"}, "engines": engines}},
		"engines": map[string]any{"prowler": map[string]any{"path": fake}, "scoutsuite": map[string]any{"path": fake},
			"steampipe": map[string]any{"path": fake, "install_dir": filepath.Join(filepath.Dir(token), "steampipe")}},
	}}
}
