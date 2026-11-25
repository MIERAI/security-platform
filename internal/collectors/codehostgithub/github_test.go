package codehostgithub

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// canaries are assembled at run time: no credential-shaped string is committed.
func canaries() (token, alertSecret string) {
	return "tok-canary-" + "5d1e0c", "gh" + "p_" + strings.Repeat("Zq", 18)
}

const status = `github.com
  ✓ Logged in to github.com account bot (keyring)
  - Active account: true
  - Token: gho_************************************
  - Token scopes: 'gist', 'repo', 'admin:org'
  X Failed to log in to github.com account gone (default)
  - Active account: false
`

func TestParseAuthStatus(t *testing.T) {
	t.Parallel()
	// "Failed to log in" starts no account (as the reference reads it): the next "Active" line belongs to bot
	got := ParseAuthStatus(status + "  ✓ Logged in to ghe.example account ops (default)\n")
	if len(got) != 2 {
		t.Fatalf("%d accounts: %+v", len(got), got)
	}
	if a := got[0]; !firstAccountOK(&a) {
		t.Errorf("%+v", a)
	}
	if a := got[1]; a.Account != "ops" || a.Host != "ghe.example" || a.Storage != "default" || a.HasScopes || a.HasActive {
		t.Errorf("%+v", a)
	}
}

func TestParseAuthStatusKeepsNoTokenText(t *testing.T) {
	t.Parallel()
	for _, a := range ParseAuthStatus(status) {
		if strings.Contains(a.Account+a.Host+a.Storage+strings.Join(a.Scopes, ""), "gho_") {
			t.Error("token text in an account")
		}
	}
}

func TestGrouped(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   []any
		want string
		ok   bool
	}{{nil, "null", true}, {[]any{"b", "a", "b"}, `{"a":1,"b":2}`, true}, {[]any{"a", nil}, "null", false}}
	for _, tt := range tests {
		got, ok := Grouped(tt.in)
		b, err := json.Marshal(got)
		if err != nil || string(b) != tt.want || ok != tt.ok {
			t.Errorf("Grouped(%v) = %s %v", tt.in, b, ok)
		}
	}
}

type api struct {
	t       *testing.T
	token   string
	routes  map[string]any
	mu      sync.Mutex
	methods []string
}

func (a *api) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	a.methods = append(a.methods, r.Method)
	a.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+a.token {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	v, ok := a.routes[r.URL.Path]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message": "Not Found"}`))
		return
	}
	if err := json.NewEncoder(w).Encode(v); err != nil {
		a.t.Error(err)
	}
}

func repo(name, vis string) map[string]any {
	return map[string]any{"full_name": "acme/" + name, "owner": map[string]any{"login": "acme"}, "visibility": vis,
		"default_branch": "main"}
}

type result struct {
	doc    string
	files  map[string][]byte
	stderr string
}

func run(t *testing.T, a *api, entry map[string]any, getenv map[string]string) result {
	t.Helper()
	dir := t.TempDir()
	srv := httptest.NewServer(a)
	t.Cleanup(srv.Close)
	entry["api"] = srv.URL
	inst, err := json.Marshal(map[string]any{"codehost": []any{entry}})
	if err != nil {
		t.Fatal(err)
	}
	if werr := os.WriteFile(filepath.Join(dir, "i.json"), inst, 0o600); werr != nil {
		t.Fatal(werr)
	}
	vars := map[string]string{"SP_INSTANCE": filepath.Join(dir, "i.json"), "SP_RUN_DIR": filepath.Join(dir, "run"), "HOME": dir}
	for k, v := range getenv {
		vars[k] = v
	}
	var stderr bytes.Buffer
	env := rundoc.Env{Getenv: func(k string) string { return vars[k] }, Stderr: &stderr, Now: time.Now}
	d := deps{status: func(context.Context) (string, bool) { return status, true }}
	if cerr := collectWith(context.Background(), env, d); cerr != nil {
		t.Fatal(cerr)
	}
	res := result{files: map[string][]byte{}, stderr: stderr.String()}
	err = filepath.WalkDir(filepath.Join(dir, "run"), func(p string, e os.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return err
		}
		b, rerr := os.ReadFile(p)
		res.files[filepath.Base(p)] = b
		return rerr
	})
	if err != nil {
		t.Fatal(err)
	}
	res.doc = string(res.files[Name+".findings.json"])
	return res
}

// TestReadOnlyAndNoSecretValues: every request is a GET, the token and an alert's secret never reach any output.
func TestReadOnlyAndNoSecretValues(t *testing.T) {
	skipOnWindows(t)
	t.Parallel()
	token, secret := canaries()
	a := &api{t: t, token: token, routes: map[string]any{
		"/users/acme/repos": []any{repo("one", "public")},
		"/user/repos":       []any{repo("two", "private")},
		"/repos/acme/one/secret-scanning/alerts": []any{map[string]any{"secret_type_display_name": "GitHub Personal Access Token",
			"secret": secret}},
		"/repos/acme/one/actions/secrets": map[string]any{"secrets": []any{map[string]any{"name": "OLD",
			"updated_at": "2020-01-01T00:00:00Z"}}},
	}}
	dir := t.TempDir()
	tf := filepath.Join(dir, "t")
	if err := os.WriteFile(tf, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res := run(t, a, map[string]any{"type": "github", "owner": "acme", "token_file": tf}, nil)
	for name, b := range res.files {
		for _, c := range []string{token, secret} {
			if bytes.Contains(b, []byte(c)) {
				t.Errorf("canary %.6s... in %s", c, name)
			}
		}
	}
	if strings.Contains(res.stderr, token) {
		t.Error("token on stderr")
	}
	for _, check := range []string{"repo.secret_scanning_alerts_open", "secret.age_over_90d", "repo.default_branch_unprotected",
		"github.token_broad_scopes"} {
		if !strings.Contains(res.doc, `"check": "`+check+`"`) {
			t.Errorf("no %s", check)
		}
	}
	for _, m := range a.methods {
		if m != http.MethodGet {
			t.Errorf("%s sent", m)
		}
	}
}

func TestTokenSources(t *testing.T) {
	skipOnWindows(t)
	t.Parallel()
	token, _ := canaries()
	dir := t.TempDir()
	loose := filepath.Join(dir, "loose")
	if err := os.WriteFile(loose, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o644); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		entry map[string]any
		env   map[string]string
		gap   string
	}{
		{"file readable by others", map[string]any{"token_file": loose}, nil, "group/others"},
		{"no token", map[string]any{"gh_user": "bot"}, nil, "no token_file or token_env"},
		{"empty variable", map[string]any{"token_env": "GH_RO_TOKEN"}, nil, "not set"},
		{"variable", map[string]any{"token_env": "GH_RO_TOKEN"}, map[string]string{"GH_RO_TOKEN": token}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			a := &api{t: t, token: token, routes: map[string]any{"/users/acme/repos": []any{}}}
			tt.entry["type"], tt.entry["owner"] = "github", "acme"
			res := run(t, a, tt.entry, tt.env)
			checkTokenSource(t, a, res.doc, tt.gap, token)
		})
	}
}

func TestVersionMatchesTree(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "collectors", "codehost-github", "VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(data)); got != Version {
		t.Fatalf("VERSION %s, Go %s", got, Version)
	}
}

func FuzzParseAuthStatus(f *testing.F) {
	f.Add(status)
	f.Add("Logged in to account\n- Token scopes:\n- Active account: true")
	f.Add("  ✓ Logged in to h account a (x)(y\n")
	f.Fuzz(func(t *testing.T, text string) {
		for _, a := range ParseAuthStatus(text) {
			if a.Account == "" || a.Host == "" || strings.ContainsAny(a.Account+a.Host, " \n\t") {
				t.Fatalf("%+v", a)
			}
		}
	})
}

// FuzzReductions: any JSON page reduces without failing; only counts and type names come out.
func FuzzReductions(f *testing.F) {
	f.Add([]byte(`[{"secret_type_display_name": "x", "secret": "s"}, {"security_advisory": {"severity": "high"}}]`))
	f.Add([]byte(`[1, null, "a", {"secret_type_display_name": 3}]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := pyvalue.DecodeJSON(data)
		if err != nil {
			return
		}
		l, _ := v.([]any) // not a list: as an empty page
		ss := SecretScanning(l)
		if _, isErr := ss["error"]; !isErr && ss["count"] != len(l) {
			t.Fatalf("count %v of %d", ss["count"], len(l))
		}
		onlyTypeNames(t, ss, l) // only type names, never another field of an alert
		if d := Dependabot(l); d == nil {
			t.Fatal("nil reduction")
		}
	})
}

func checkTokenSource(t *testing.T, a *api, doc, gap, token string) {
	t.Helper()
	switch {
	case gap == "" && (strings.Contains(doc, `"status": "gap"`) || len(a.methods) == 0):
		t.Errorf("token read: %s", doc)
	case gap != "" && (!strings.Contains(doc, gap) || len(a.methods) != 0):
		t.Errorf("%d requests, %s", len(a.methods), doc)
	}
	if strings.Contains(doc, token) {
		t.Error("token in the document")
	}
}

// onlyTypeNames: every key of a types reduction is the type name of an alert.
func onlyTypeNames(t *testing.T, ss map[string]any, l []any) {
	t.Helper()
	types, ok := ss["types"].(map[string]any)
	if !ok {
		return
	}
	for k := range types {
		if !slices.ContainsFunc(l, func(a any) bool { return pyvalue.Equal(rundoc.Get(a, "secret_type_display_name"), k) }) {
			t.Fatalf("%q is not a type name", k)
		}
	}
}

func firstAccountOK(a *Account) bool {
	return a.Account == "bot" && a.Host == "github.com" && a.Storage == "keyring" && !a.Active && a.HasActive &&
		slices.Equal(a.Scopes, []string{"gist", "repo", "admin:org"})
}

// skipOnWindows: the test needs a token file with POSIX permissions (refused on Windows, where the mode bits Go
// reports are not permissions) or POSIX programs; the Linux and macOS runs cover it.
func skipOnWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file permissions / programs")
	}
}
