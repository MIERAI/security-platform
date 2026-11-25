package cloud

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// Fakes of the provider endpoints the adapter calls, shaped like the real services' responses (XML Query API for
// STS/IAM, Google JSON, Entra/ARM JSON). They also record what they were asked.

const (
	testAccount = "123456789012"
	readOnlyARN = "arn:aws:iam::aws:policy/SecurityAudit"
	writePolicy = "arn:aws:iam::123456789012:policy/deployer"
	saToken     = "ya29.test-service-account-token"
	userToken   = "ya29.test-user-token"
)

// unsignedJWT is a token-shaped test value (the adapter never verifies signatures; the servers do).
func unsignedJWT(claims map[string]any) string {
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			panic(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return enc(map[string]string{"alg": "none"}) + "." + enc(claims) + ".sig"
}

func writeToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "token.jwt")
	if err := os.WriteFile(p, []byte(unsignedJWT(claims)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func validToken(t *testing.T, aud string) string {
	t.Helper()
	return writeToken(t, map[string]any{"sub": "system:serviceaccount:security:scanner", "aud": aud,
		"exp": time.Now().Add(time.Hour).Unix()})
}

// ---- AWS ---------------------------------------------------------------------------------------------------

type fakeAWS struct {
	mu       sync.Mutex
	calls    map[string]int
	signed   map[string]bool
	attached []string          // managed policy ARNs on the role
	inline   map[string]string // inline policy name -> document
	roles    map[string]bool   // roles that exist
	denySTS  bool
}

func newFakeAWS() *fakeAWS {
	return &fakeAWS{calls: map[string]int{}, signed: map[string]bool{}, attached: []string{readOnlyARN},
		inline: map[string]string{"read": `{"Statement":[{"Effect":"Allow","Action":["ec2:Describe*","s3:GetObject"]}]}`},
		roles:  map[string]bool{"audit": true, "member-audit": true}}
}

func (f *fakeAWS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	action := r.Form.Get("Action")
	f.mu.Lock()
	f.calls[action]++
	f.signed[action] = strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256")
	f.mu.Unlock()
	w.Header().Set("Content-Type", "text/xml")
	if code, body := f.answer(action, r.Form); code != http.StatusOK {
		w.WriteHeader(code)
		_, _ = fmt.Fprint(w, body)
	} else {
		_, _ = fmt.Fprintf(w, "<%sResponse><%sResult>%s</%sResult></%sResponse>", action, action, body, action, action)
	}
}

func awsError(code, msg string) string {
	return "<ErrorResponse><Error><Type>Sender</Type><Code>" + code + "</Code><Message>" + msg + "</Message></Error></ErrorResponse>"
}

func awsCreds(role string) string {
	return "<Credentials><AccessKeyId>ASIATESTTESTTESTTEST</AccessKeyId><SecretAccessKey>test-secret</SecretAccessKey>" +
		"<SessionToken>test-session-" + role + "</SessionToken><Expiration>" +
		time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + "</Expiration></Credentials>" +
		"<AssumedRoleUser><Arn>arn:aws:sts::" + testAccount + ":assumed-role/" + role + "/sp</Arn><AssumedRoleId>X:sp</AssumedRoleId></AssumedRoleUser>"
}

func roleOf(arn string) string { return arn[strings.LastIndex(arn, "/")+1:] }

func (f *fakeAWS) answer(action string, form url.Values) (int, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch action {
	case "AssumeRoleWithWebIdentity", "AssumeRole":
		if f.denySTS {
			return http.StatusForbidden, awsError("AccessDenied", "Not authorized to perform sts:AssumeRoleWithWebIdentity")
		}
		f.signed["last-role"] = true
		f.calls["role:"+roleOf(form.Get("RoleArn"))]++
		return http.StatusOK, awsCreds(roleOf(form.Get("RoleArn")))
	case "GetCallerIdentity":
		role := "audit"
		if f.calls["role:member-audit"] > 0 {
			role = "member-audit"
		}
		return http.StatusOK, "<Arn>arn:aws:sts::" + testAccount + ":assumed-role/" + role + "/sp</Arn><UserId>X:sp</UserId><Account>" + testAccount + "</Account>"
	default:
		return f.iamAnswer(action, form)
	}
}

func (f *fakeAWS) iamAnswer(action string, form url.Values) (int, string) {
	switch action {
	case "GetRole":
		if !f.roles[form.Get("RoleName")] {
			return http.StatusNotFound, awsError("NoSuchEntity", "The role with name "+form.Get("RoleName")+" cannot be found.")
		}
		return http.StatusOK, "<Role><RoleName>" + form.Get("RoleName") + "</RoleName><Path>/</Path><RoleId>R</RoleId><Arn>a</Arn><CreateDate>2020-01-01T00:00:00Z</CreateDate></Role>"
	case "ListAttachedRolePolicies":
		var b strings.Builder
		for _, a := range f.attached {
			b.WriteString("<member><PolicyArn>" + a + "</PolicyArn><PolicyName>p</PolicyName></member>")
		}
		return http.StatusOK, "<AttachedPolicies>" + b.String() + "</AttachedPolicies><IsTruncated>false</IsTruncated>"
	case "GetPolicy":
		return http.StatusOK, "<Policy><DefaultVersionId>v2</DefaultVersionId><Arn>" + form.Get("PolicyArn") + "</Arn></Policy>"
	case "GetPolicyVersion":
		doc := url.PathEscape(`{"Statement":[{"Effect":"Allow","Action":"s3:PutObject","Resource":"*"}]}`)
		return http.StatusOK, "<PolicyVersion><Document>" + doc + "</Document><VersionId>v2</VersionId><IsDefaultVersion>true</IsDefaultVersion></PolicyVersion>"
	case "ListRolePolicies":
		var b strings.Builder
		for name := range f.inline {
			b.WriteString("<member>" + name + "</member>")
		}
		return http.StatusOK, "<PolicyNames>" + b.String() + "</PolicyNames><IsTruncated>false</IsTruncated>"
	case "GetRolePolicy":
		return http.StatusOK, "<RoleName>r</RoleName><PolicyName>" + form.Get("PolicyName") + "</PolicyName><PolicyDocument>" +
			url.PathEscape(f.inline[form.Get("PolicyName")]) + "</PolicyDocument>"
	}
	return http.StatusBadRequest, awsError("InvalidAction", action)
}

func (f *fakeAWS) count(action string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[action]
}

// ---- GCP ---------------------------------------------------------------------------------------------------

type fakeGCP struct {
	mu        sync.Mutex
	exchanges int
	refreshes int
	paths     []string
}

func (f *fakeGCP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.paths = append(f.paths, r.URL.Path)
	f.mu.Unlock()
	reply := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v) // a test server: the client reports what it could not read
	}
	gerr := func(code int, status, msg string) {
		reply(code, map[string]any{"error": map[string]any{"code": code, "status": status, "message": msg}})
	}
	p := r.URL.Path
	switch {
	case p == "/sts":
		f.sts(r, reply)
	case p == "/oauth":
		f.oauth(r, reply)
	case strings.HasSuffix(p, ":generateAccessToken"):
		f.generate(r, reply, gerr)
	case strings.HasSuffix(p, ":getIamPolicy"):
		f.policy(r, reply, gerr)
	case strings.HasSuffix(p, ":searchAllResources"):
		reply(http.StatusOK, map[string]any{"results": []any{
			map[string]any{"name": "//compute.googleapis.com/projects/p/zones/z/instances/web-1", "displayName": "web-1",
				"location": "europe-west1-b", "state": "RUNNING",
				"additionalAttributes": map[string]any{"internalIPs": []string{"10.0.0.2"}, "externalIPs": []string{"192.0.2.10"}}},
			map[string]any{"name": "//compute.googleapis.com/projects/p/zones/z/instances/old-1", "location": "europe-west1-c",
				"state": "TERMINATED"}}})
	case strings.HasSuffix(p, "/aggregated/instances"):
		reply(http.StatusOK, map[string]any{"items": map[string]any{"zones/europe-west1-b": map[string]any{"instances": []any{
			map[string]any{"name": "batch-1", "status": "RUNNING", "networkInterfaces": []any{
				map[string]any{"networkIP": "10.0.0.3", "accessConfigs": []any{map[string]any{"natIP": "192.0.2.11"}}}}}}}}})
	default:
		gerr(http.StatusNotFound, "NOT_FOUND", "no such path")
	}
}

func (f *fakeGCP) sts(r *http.Request, reply func(int, any)) {
	f.mu.Lock()
	f.exchanges++
	f.mu.Unlock()
	if err := r.ParseForm(); err != nil || r.Form.Get("audience") != "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/x" {
		reply(http.StatusBadRequest, map[string]any{"error": "invalid_grant",
			"error_description": "The audience in ID Token does not match the expected audience."})
		return
	}
	reply(http.StatusOK, map[string]any{"access_token": "federated-token", "expires_in": 3600, "token_type": "Bearer",
		"issued_token_type": "urn:ietf:params:oauth:token-type:access_token"})
}

func (f *fakeGCP) oauth(r *http.Request, reply func(int, any)) {
	f.mu.Lock()
	f.refreshes++
	f.mu.Unlock()
	if err := r.ParseForm(); err != nil || r.Form.Get("refresh_token") != "test-refresh-operator" ||
		r.Form.Get("client_id") != "test-client" || r.Form.Get("client_secret") != "test-client-secret" {
		reply(http.StatusBadRequest, map[string]any{"error": "invalid_grant", "error_description": "Token has been expired or revoked."})
		return
	}
	reply(http.StatusOK, map[string]any{"access_token": userToken, "expires_in": 3599, "token_type": "Bearer"})
}

func (f *fakeGCP) generate(r *http.Request, reply func(int, any), gerr func(int, string, string)) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer federated-token" && auth != "Bearer "+userToken {
		gerr(http.StatusUnauthorized, "UNAUTHENTICATED", "Request had invalid authentication credentials.")
		return
	}
	switch {
	case strings.Contains(r.URL.Path, "nobody@"):
		gerr(http.StatusNotFound, "NOT_FOUND", "Service account does not exist.")
	case strings.Contains(r.URL.Path, "someone-else@"):
		gerr(http.StatusForbidden, "PERMISSION_DENIED", "Permission 'iam.serviceAccounts.getAccessToken' denied")
	default:
		reply(http.StatusOK, map[string]any{"accessToken": saToken, "expireTime": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	}
}

func (f *fakeGCP) policy(r *http.Request, reply func(int, any), gerr func(int, string, string)) {
	if r.Header.Get("Authorization") != "Bearer "+saToken {
		gerr(http.StatusUnauthorized, "UNAUTHENTICATED", "bad token")
		return
	}
	var req struct {
		Options struct {
			RequestedPolicyVersion int `json:"requestedPolicyVersion"`
		} `json:"options"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req) // an empty body asks for version 1
	member := "serviceAccount:audit@my-project.iam.gserviceaccount.com"
	roles := []string{"roles/iam.securityReviewer", "roles/viewer"}
	if strings.Contains(r.URL.Path, "over") {
		roles = append(roles, "roles/editor")
	}
	var bindings []any
	for _, role := range roles {
		b := map[string]any{"role": role, "members": []string{member}}
		if role != "roles/viewer" { // time-bound grants, as recommended for audit access
			if req.Options.RequestedPolicyVersion == 3 {
				b["condition"] = map[string]any{"title": "expires", "expression": `request.time < timestamp("2999-01-01T00:00:00Z")`}
			} else {
				b["role"] = role + "_withcond_0123abcd"
			}
		}
		bindings = append(bindings, b)
	}
	bindings = append(bindings, map[string]any{"role": "roles/owner", "members": []string{"user:owner@example.com"}})
	reply(http.StatusOK, map[string]any{"version": req.Options.RequestedPolicyVersion, "bindings": bindings})
}

// ---- Azure -------------------------------------------------------------------------------------------------

const (
	testTenant = "00000000-0000-4000-8000-00000000aaaa"
	testClient = "11111111-1111-4111-8111-111111111111"
	testOID    = "22222222-2222-4222-8222-222222222222"
)

func fakeAzure(w http.ResponseWriter, r *http.Request) {
	reply := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v) // a test server
	}
	base := "https://" + r.Host
	p := r.URL.Path
	switch {
	case strings.HasSuffix(p, "/v2.0/.well-known/openid-configuration"):
		reply(http.StatusOK, map[string]any{"token_endpoint": base + "/" + testTenant + "/oauth2/v2.0/token",
			"authorization_endpoint": base + "/" + testTenant + "/oauth2/v2.0/authorize", "issuer": base + "/" + testTenant + "/v2.0"})
	case strings.HasSuffix(p, "/oauth2/v2.0/token"):
		if err := r.ParseForm(); err != nil || r.Form.Get("client_id") != testClient {
			reply(http.StatusBadRequest, map[string]any{"error": "unauthorized_client",
				"error_description": "AADSTS700016: Application with identifier was not found in the directory."})
			return
		}
		reply(http.StatusOK, map[string]any{"token_type": "Bearer", "expires_in": 3600,
			"access_token": unsignedJWT(map[string]any{"oid": testOID, "exp": time.Now().Add(time.Hour).Unix()})})
	case strings.HasSuffix(p, "/providers/Microsoft.Authorization/roleAssignments"):
		roles := []string{"acdd72a7-3385-48ef-bd42-f606fba81ae7", "39bc4728-0917-49c7-9d2c-d95423bc2eb4"}
		if strings.Contains(p, "44444444") {
			roles = append(roles, "b24988ac-6180-42a0-ab88-20f7382dd24c")
		}
		var value []any
		for i, role := range roles {
			value = append(value, map[string]any{"id": fmt.Sprintf("/subscriptions/s/providers/Microsoft.Authorization/roleAssignments/%d", i),
				"properties": map[string]any{"principalId": testOID, "roleDefinitionId": "/subscriptions/s/providers/Microsoft.Authorization/roleDefinitions/" + role}})
		}
		reply(http.StatusOK, map[string]any{"value": value})
	default:
		reply(http.StatusNotFound, map[string]any{"error": map[string]any{"code": "NotFound", "message": p}})
	}
}

// tlsServerCA starts a TLS test server and writes its certificate as a PEM file (an account's ca_file).
func tlsServerCA(t *testing.T, h http.Handler) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	p := filepath.Join(t.TempDir(), "ca.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return srv, p
}

func testDeps(env map[string]string) Deps {
	return Deps{Getenv: func(k string) string { return env[k] }, Now: time.Now, Executable: "/opt/sp/bin/sp", GOOS: runtime.GOOS}
}
