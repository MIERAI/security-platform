package cloud

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/MIERAI/security-platform/internal/cloud/dyn"
)

const (
	testSA  = "audit@my-project.iam.gserviceaccount.com"
	testWIP = "projects/1/locations/global/workloadIdentityPools/p/providers/x"
)

func gcpAccount(url, project string, extra map[string]any) Account {
	a := Account{"provider": "gcp", "project_id": project, "service_account": testSA, "workload_identity_provider": testWIP,
		"sts_url": url + "/sts", "oauth_token_url": url + "/oauth", "iamcredentials_url": url + "/iam/v1",
		"resourcemanager_url": url + "/crm/v1"}
	for k, v := range extra {
		a[k] = v
	}
	return a
}

func writeADC(t *testing.T, mode os.FileMode, content map[string]any) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "adc.json")
	data, err := json.Marshal(content)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func operatorADC(refresh string) map[string]any {
	return map[string]any{"type": "authorized_user", "client_id": "test-client", "client_secret": "test-client-secret",
		"refresh_token": refresh}
}

// The incident this rewrite started from: a conditional (time-bound) read-only grant must be judged by its role.
func TestGCPConditionalGrantsJudgedByRole(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(&fakeGCP{})
	t.Cleanup(srv.Close)
	tests := []struct {
		name, project string
		extra         map[string]any
		wantWrite     []string
	}{
		{"workload identity, read-only", "my-project", map[string]any{"identity_token": map[string]any{"path": validToken(t, "gcp")}}, []string{}},
		{"workload identity, editor", "my-project-over", map[string]any{"identity_token": map[string]any{"path": validToken(t, "gcp")}},
			[]string{"roles/editor"}},
		{"adc, read-only", "my-project", map[string]any{"source": "adc", "adc_file": writeADC(t, 0o600, operatorADC("test-refresh-operator"))},
			[]string{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, err := New(gcpAccount(srv.URL, tc.project, tc.extra), testDeps(nil))
			if err != nil {
				t.Fatal(err)
			}
			perm, err := p.Permissions(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			wantCond := []string{"roles/iam.securityReviewer"}
			if len(tc.wantWrite) > 0 {
				wantCond = []string{"roles/editor", "roles/iam.securityReviewer"}
			}
			if !reflect.DeepEqual(perm.WriteCapable, tc.wantWrite) || !reflect.DeepEqual(perm.Conditional, wantCond) ||
				perm.Principal != "serviceAccount:"+testSA {
				t.Fatalf("permissions %+v", perm)
			}
		})
	}
}

func TestGCPFailuresAreReasons(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(&fakeGCP{})
	t.Cleanup(srv.Close)
	tok := map[string]any{"path": validToken(t, "gcp")}
	adc := func(refresh string) string { return writeADC(t, 0o600, operatorADC(refresh)) }
	tests := []struct {
		name  string
		extra map[string]any
		want  string
	}{
		{"sts rejects audience", map[string]any{"identity_token": tok, "workload_identity_provider": "projects/9/x"},
			"gcp sts token exchange: HTTP 400 invalid_grant: The audience in ID Token does not match the expected audience."},
		{"denied impersonation", map[string]any{"identity_token": tok, "service_account": "someone-else@p.iam.gserviceaccount.com"},
			"gcp impersonation of someone-else@p.iam.gserviceaccount.com: HTTP 403 PERMISSION_DENIED: Permission 'iam.serviceAccounts.getAccessToken' denied"},
		{"missing service account", map[string]any{"identity_token": tok, "service_account": "nobody@p.iam.gserviceaccount.com"},
			"gcp impersonation of nobody@p.iam.gserviceaccount.com: HTTP 404 NOT_FOUND: Service account does not exist."},
		{"adc missing", map[string]any{"source": "adc", "adc_file": filepath.Join(t.TempDir(), "absent.json")},
			"gcp adc: no application default credentials (adc_file): run `gcloud auth application-default login`"},
		{"adc readable by others", map[string]any{"source": "adc", "adc_file": writeADC(t, 0o644, operatorADC("x"))},
			"gcp adc: credentials file (adc_file) is readable by group/others: chmod 600 it"}, // not checked on Windows (ACLs)
		{"adc key file", map[string]any{"source": "adc", "adc_file": writeADC(t, 0o600, map[string]any{"type": "service_account"})},
			"gcp adc: a service-account key file is a long-lived credential and is refused: run `gcloud auth application-default login` (a user login) or use source workload_identity"},
		{"adc incomplete", map[string]any{"source": "adc", "adc_file": writeADC(t, 0o600, map[string]any{"type": "authorized_user"})},
			"gcp adc: incomplete authorized_user credentials (adc_file): run `gcloud auth application-default login`"},
		{"adc revoked", map[string]any{"source": "adc", "adc_file": adc("revoked")},
			"gcp adc refresh: HTTP 400 invalid_grant: Token has been expired or revoked. (expired, revoked or re-authentication required: run `gcloud auth application-default login`)"},
		{"adc denied impersonation", map[string]any{"source": "adc", "adc_file": adc("test-refresh-operator"),
			"service_account": "someone-else@p.iam.gserviceaccount.com"},
			"gcp impersonation of someone-else@p.iam.gserviceaccount.com: HTTP 403 PERMISSION_DENIED: Permission 'iam.serviceAccounts.getAccessToken' denied (the operator needs roles/iam.serviceAccountTokenCreator on it)"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if runtime.GOOS == "windows" && strings.Contains(tc.name, "readable by others") {
				t.Skip("file mode bits are not checked on Windows")
			}
			p, err := New(gcpAccount(srv.URL, "my-project", tc.extra), testDeps(nil))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := p.Identity(context.Background()); err == nil || Reason(err) != tc.want {
				t.Fatalf("reason %v\nwant   %s", err, tc.want)
			}
		})
	}
}

func TestGCPTokenCachedAndRenewedBeforeExpiry(t *testing.T) {
	t.Parallel()
	f := &fakeGCP{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	now := time.Now()
	deps := testDeps(nil)
	deps.Now = func() time.Time { return now }
	p, err := New(gcpAccount(srv.URL, "my-project", map[string]any{"identity_token": map[string]any{"path": validToken(t, "gcp")}}), deps)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := p.Identity(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	now = now.Add(time.Hour - RefreshMargin + time.Second) // inside the refresh margin of the 1 h token
	if _, err := p.Identity(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.exchanges != 2 {
		t.Fatalf("%d token exchanges, want 2 (cached, then renewed before expiry)", f.exchanges)
	}
}

func TestGCPEngineNeverGetsTheOperatorsADC(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(&fakeGCP{})
	t.Cleanup(srv.Close)
	adc := writeADC(t, 0o600, operatorADC("test-refresh-operator"))
	tests := []struct {
		name, engineAuth string
		wantToken        bool
	}{{"access token (default)", "", true}, {"impersonate", "impersonate", false}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := gcpAccount(srv.URL, "my-project", map[string]any{"source": "adc", "adc_file": adc})
			if tc.engineAuth != "" {
				cfg["engine_auth"] = tc.engineAuth
			}
			p, err := New(cfg, testDeps(nil))
			if err != nil {
				t.Fatal(err)
			}
			checkADCEngineEnv(t, p, tc.wantToken)
		})
	}
}

func checkADCEngineEnv(t *testing.T, p Provider, wantToken bool) {
	t.Helper()
	dir := t.TempDir()
	env, args, err := p.EngineEnv(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if (env["CLOUDSDK_AUTH_ACCESS_TOKEN"] == saToken) != wantToken || args.GCPSource != "adc" ||
		!strings.HasPrefix(env["CLOUDSDK_CONFIG"], dir) {
		t.Fatalf("env %v args %+v", env, args)
	}
	for k, v := range env {
		if strings.Contains(v, "test-refresh-operator") || v == userToken {
			t.Fatalf("%s carries the operator's credential", k)
		}
	}
	assertNoSecretFiles(t, dir, "test-refresh-operator", userToken, saToken)
}

func TestGCPWorkloadIdentityEngineConfig(t *testing.T) {
	t.Parallel()
	cfg := gcpAccount("https://example.invalid", "my-project", map[string]any{
		"identity_token": map[string]any{"type": "command", "argv": []any{"print-token"}}})
	p, err := New(cfg, testDeps(nil))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	env, _, err := p.EngineEnv(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(env["GOOGLE_APPLICATION_CREDENTIALS"])
	if err != nil {
		t.Fatal(err)
	}
	var conf map[string]any
	if err := json.Unmarshal(data, &conf); err != nil {
		t.Fatal(err)
	}
	command := dyn.Str(dyn.Map(dyn.Map(conf["credential_source"])["executable"])["command"])
	if conf["type"] != "external_account" || !strings.HasPrefix(command, "/opt/sp/bin/sp cloud executable-token ") ||
		env["GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES"] != "1" || !strings.HasSuffix(dyn.Str(conf["service_account_impersonation_url"]),
		"/iam/v1/projects/-/serviceAccounts/"+testSA+":generateAccessToken") {
		t.Fatalf("external account config %s", data)
	}
}

func azureAccount(url, ca, sub, client, tok string) Account {
	return Account{"provider": "azure", "subscription_id": sub, "tenant_id": testTenant, "client_id": client,
		"identity_token": map[string]any{"path": tok}, "authority_host": url, "arm_url": url, "ca_file": ca}
}

func TestAzure(t *testing.T) {
	t.Parallel()
	srv, ca := tlsServerCA(t, http.HandlerFunc(fakeAzure))
	expired := writeToken(t, map[string]any{"exp": time.Now().Add(-time.Hour).Unix()})
	tests := []struct {
		name, sub, client, token string
		wantWrite                []string
		wantErr                  string
	}{
		{"reader + security reader", "33333333-3333-4333-8333-333333333333", testClient, validToken(t, "api://AzureADTokenExchange"), []string{}, ""},
		{"contributor", "44444444-4444-4444-8444-444444444444", testClient, validToken(t, "api://AzureADTokenExchange"), []string{"Contributor"}, ""},
		{"unknown app", "33333333-3333-4333-8333-333333333333", "99999999-9999-4999-8999-999999999999", validToken(t, "x"), nil,
			"azure federated token: HTTP 400 unauthorized_client: AADSTS700016: Application with identifier was not found in the directory."},
		{"expired assertion", "33333333-3333-4333-8333-333333333333", testClient, expired, nil, "identity token expired"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, err := New(azureAccount(srv.URL, ca, tc.sub, tc.client, tc.token), testDeps(nil))
			if err != nil {
				t.Fatal(err)
			}
			perm, err := p.Permissions(context.Background())
			checkPermissions(t, perm, err, tc.wantWrite, tc.wantErr)
			if err == nil && perm.Principal != testOID {
				t.Fatalf("principal %s", perm.Principal)
			}
		})
	}
}

func TestDiscoverGCP(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(&fakeGCP{})
	t.Cleanup(srv.Close)
	tok := map[string]any{"path": validToken(t, "gcp")}
	tests := []struct {
		name  string
		extra map[string]any
		want  string
	}{
		{"cloudasset, external", map[string]any{"cloudasset_url": srv.URL + "/asset/v1"},
			`[{"name":"web-1","address":"192.0.2.10","os":"","online":true,"attrs":{"asset":"cloud:gcp/my-project/compute/web-1","external":true,"online_verified":true,"project":"my-project","provider":"gcp","status":"RUNNING","zone":"europe-west1-b"}}]`},
		{"cloudasset, internal, stopped too", map[string]any{"cloudasset_url": srv.URL + "/asset/v1", "address": "internal", "include_stopped": true},
			`[{"name":"web-1","address":"10.0.0.2","os":"","online":true,"attrs":{"asset":"cloud:gcp/my-project/compute/web-1","external":true,"online_verified":true,"project":"my-project","provider":"gcp","status":"RUNNING","zone":"europe-west1-b"}},` +
				`{"name":"old-1","address":null,"os":"","online":false,"attrs":{"asset":"cloud:gcp/my-project/compute/old-1","external":false,"online_verified":false,"project":"my-project","provider":"gcp","status":"TERMINATED","zone":"europe-west1-c"}}]`},
		{"compute aggregated list", map[string]any{"api": "compute", "compute_url": srv.URL + "/compute/v1"},
			`[{"name":"batch-1","address":"192.0.2.11","os":"","online":true,"attrs":{"asset":"cloud:gcp/my-project/compute/batch-1","external":true,"online_verified":true,"project":"my-project","provider":"gcp","status":"RUNNING","zone":"europe-west1-b"}}]`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.extra["identity_token"] = tok
			devs, err := DiscoverGCP(context.Background(), gcpAccount(srv.URL, "my-project", tc.extra), testDeps(nil))
			if err != nil {
				t.Fatal(err)
			}
			got, err := json.Marshal(devs)
			if err != nil || !jsonEqual(t, got, []byte(tc.want)) {
				t.Fatalf("devices %s", got)
			}
		})
	}
	_, err := DiscoverGCP(context.Background(), gcpAccount(srv.URL, "my-project-over", map[string]any{"identity_token": tok}), testDeps(nil))
	if err == nil || !strings.Contains(err.Error(), "refused: the discovery identity is over-privileged (read-only expected): roles/editor") {
		t.Fatalf("over-privileged discovery: %v", err)
	}
}

func jsonEqual(t *testing.T, a, b []byte) bool {
	t.Helper()
	var x, y any
	if err := json.Unmarshal(a, &x); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &y); err != nil {
		t.Fatal(err)
	}
	return reflect.DeepEqual(x, y)
}

// checkPermissions: either the expected reason, or the expected write-capable grants.
func checkPermissions(t *testing.T, perm Permissions, err error, wantWrite []string, wantErr string) {
	t.Helper()
	switch {
	case wantErr != "" && (err == nil || Reason(err) != wantErr):
		t.Fatalf("reason %v, want %s", err, wantErr)
	case wantErr == "" && err != nil:
		t.Fatal(err)
	case wantErr == "" && !reflect.DeepEqual(perm.WriteCapable, wantWrite):
		t.Fatalf("permissions %+v", perm)
	}
}
