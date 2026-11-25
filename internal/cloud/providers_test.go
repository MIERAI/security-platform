package cloud

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
)

func awsAccount(url, token string, extra map[string]any) Account {
	a := Account{"provider": "aws", "account_id": testAccount, "role_arn": "arn:aws:iam::" + testAccount + ":role/audit",
		"audience": "sts.amazonaws.com", "identity_token": map[string]any{"type": "file", "path": token},
		"endpoint_url": url, "regions": []any{"eu-west-1"}}
	for k, v := range extra {
		a[k] = v
	}
	return a
}

func TestAWSSelfCheck(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		extra     map[string]any
		attached  []string
		wantWrite []string
		wantRole  string
	}{
		{"read-only", nil, []string{readOnlyARN}, []string{}, "audit"},
		{"write policy", nil, []string{readOnlyARN, writePolicy}, []string{writePolicy}, "audit"},
		{"assume-role chain", map[string]any{"chain_role_arn": "arn:aws:iam::" + testAccount + ":role/member-audit",
			"external_id": "x"}, []string{readOnlyARN}, []string{}, "member-audit"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFakeAWS()
			f.attached = tc.attached
			perm := awsPermissions(t, f, tc.extra)
			if !reflect.DeepEqual(perm.WriteCapable, tc.wantWrite) || !strings.Contains(perm.Principal, "/"+tc.wantRole+"/") {
				t.Fatalf("write %v principal %s", perm.WriteCapable, perm.Principal)
			}
			if len(perm.Grants) != len(tc.attached)+1 || perm.Grants[len(perm.Grants)-1] != "inline:read" {
				t.Fatalf("grants %v", perm.Grants)
			}
			if tc.extra != nil && !f.signed["AssumeRole"] {
				t.Fatal("the chained AssumeRole was not signed with the first role's credentials")
			}
		})
	}
}

func awsPermissions(t *testing.T, f *fakeAWS, extra map[string]any) Permissions {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	p, err := New(awsAccount(srv.URL, validToken(t, "sts.amazonaws.com"), extra), testDeps(nil))
	if err != nil {
		t.Fatal(err)
	}
	perm, err := p.Permissions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return perm
}

func TestAWSFailuresAreReasons(t *testing.T) {
	t.Parallel()
	expired := func(t *testing.T) string {
		t.Helper()
		return writeToken(t, map[string]any{"aud": "sts.amazonaws.com", "exp": time.Now().Add(-time.Minute).Unix()})
	}
	tests := []struct {
		name  string
		token func(t *testing.T) string
		setup func(f *fakeAWS)
		role  string
		want  string
	}{
		{"expired token", expired, nil, "audit", "identity token expired"},
		{"wrong audience", func(t *testing.T) string { t.Helper(); return validToken(t, "other") }, nil, "audit",
			"identity token audience mismatch (expected sts.amazonaws.com)"},
		{"denied", func(t *testing.T) string { t.Helper(); return validToken(t, "sts.amazonaws.com") },
			func(f *fakeAWS) { f.denySTS = true }, "audit",
			"sts AssumeRoleWithWebIdentity: HTTP 403 AccessDenied: Not authorized to perform sts:AssumeRoleWithWebIdentity"},
		{"missing role", func(t *testing.T) string { t.Helper(); return validToken(t, "sts.amazonaws.com") },
			func(f *fakeAWS) { delete(f.roles, "audit") }, "audit", "aws: role audit does not exist"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFakeAWS()
			if tc.setup != nil {
				tc.setup(f)
			}
			if err := awsPermissionsError(t, f, tc.token(t)); err == nil || Reason(err) != tc.want {
				t.Fatalf("reason %v, want %q", err, tc.want)
			}
			precheck := strings.Contains(tc.name, "token") || strings.Contains(tc.name, "audience")
			if n := f.count("AssumeRoleWithWebIdentity"); precheck && n != 0 {
				t.Fatalf("a token that fails the pre-checks was sent (%d)", n)
			}
		})
	}
}

func awsPermissionsError(t *testing.T, f *fakeAWS, token string) error {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	p, err := New(awsAccount(srv.URL, token, nil), testDeps(nil))
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.Permissions(context.Background())
	return err
}

func TestAWSCredentialsCachedAndEngineEnvKeyless(t *testing.T) {
	t.Parallel()
	f := newFakeAWS()
	srv := httptest.NewServer(f)
	defer srv.Close()
	cfg := awsAccount(srv.URL, validToken(t, "sts.amazonaws.com"), nil)
	p, err := New(cfg, testDeps(nil))
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := p.Identity(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.count("AssumeRoleWithWebIdentity"); n != 1 {
		t.Fatalf("credentials acquired %d times, want 1 (cached in memory)", n)
	}
	checkAWSEngineEnv(t, p, srv.URL)
}

func checkAWSEngineEnv(t *testing.T, p Provider, endpoint string) {
	t.Helper()
	dir := t.TempDir()
	env, args, err := p.EngineEnv(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if args.Profile != "security-platform" || !reflect.DeepEqual(args.Regions, []string{"eu-west-1"}) ||
		env["AWS_ENDPOINT_URL"] != endpoint || env["AWS_SHARED_CREDENTIALS_FILE"] != devNull(runtime.GOOS) {
		t.Fatalf("env %v args %+v", env, args)
	}
	assertNoSecretFiles(t, dir, "ASIA", "test-secret", "test-session")
	conf, rerr := os.ReadFile(env["AWS_CONFIG_FILE"])
	if rerr != nil || !strings.Contains(strings.ReplaceAll(string(conf), `"`, ""), "credential_process = /opt/sp/bin/sp cloud credential-process ") {
		t.Fatalf("profile %q %v", conf, rerr)
	}
	out, err := CredentialProcess(context.Background(), filepath.Join(dir, "aws-"+testAccount+".json"), testDeps(nil))
	if err != nil {
		t.Fatal(err)
	}
	var cp map[string]any
	if err := json.Unmarshal(out, &cp); err != nil || cp["Version"] != 1.0 || cp["SessionToken"] != "test-session-audit" {
		t.Fatalf("credential_process output %s %v", out, err)
	}
}

func assertNoSecretFiles(t *testing.T, dir string, canaries ...string) {
	t.Helper()
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 { // Windows has ACLs, not mode bits
			t.Errorf("%s is readable by others: %v", p, info.Mode())
		}
		data, err := os.ReadFile(p)
		for _, c := range canaries {
			if strings.Contains(string(data), c) {
				t.Errorf("%s holds %q", p, c)
			}
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestWriteActions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, doc string
		want      []string
	}{
		{"read verbs", `{"Statement":[{"Effect":"Allow","Action":["s3:GetObject","ec2:Describe*","iam:List*"]}]}`, []string{}},
		{"single statement object", `{"Statement":{"Effect":"Allow","Action":"s3:PutObject"}}`, []string{"s3:PutObject"}},
		{"wildcards", `{"Statement":[{"Effect":"Allow","Action":["*","s3:*","s3:Get*"]}]}`, []string{"*", "s3:*"}},
		{"deny ignored", `{"Statement":[{"Effect":"Deny","Action":"*"}]}`, []string{}},
		{"not action", `{"Statement":[{"Effect":"Allow","NotAction":"iam:*"}]}`, []string{"NotAction"}},
		{"unparseable", `{`, []string{"<unparseable policy>"}},
		{"not an object", `[1]`, []string{"<unparseable policy>"}},
		{"odd statement", `{"Statement":["x"]}`, []string{"<unparseable policy>"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := WriteActions(tc.doc); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func FuzzWriteActions(f *testing.F) {
	for _, s := range []string{`{"Statement":[{"Effect":"Allow","Action":["s3:Get*"]}]}`, `{"Statement":{"Effect":"Allow","NotAction":"x"}}`, `{`, `null`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, doc string) {
		got := WriteActions(doc)
		if !sort.StringsAreSorted(got) || len(slices.Compact(slices.Clone(got))) != len(got) {
			t.Fatalf("not a sorted set: %q", got)
		}
		if strings.Contains(doc, `"*"`) && strings.Contains(doc, `"Allow"`) && len(got) == 0 && !strings.Contains(doc, "Deny") {
			t.Logf("no write action found in %q", doc) // informative: "*" may sit in another field
		}
	})
}

// A profile is resolved by the SDK's shared-config rules; one that yields long-lived keys is refused. (Not parallel:
// the SDK reads the shared config location from the process environment.)
func TestAWSProfileWithLongLivedKeysIsRefused(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "config")
	if err := os.WriteFile(conf, []byte("[profile keys]\nregion = eu-west-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	creds := filepath.Join(dir, "credentials")
	if err := os.WriteFile(creds, []byte("[keys]\naws_access_key_id = AKIDEXAMPLE\naws_secret_access_key = example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CONFIG_FILE", conf)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", creds)
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	p, err := New(Account{"provider": "aws", "account_id": testAccount, "profile": "keys"}, testDeps(nil))
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.Identity(context.Background())
	if err == nil || Reason(err) != "aws profile keys yields long-lived keys: use SSO or a role" {
		t.Fatalf("got %v", err)
	}
}
