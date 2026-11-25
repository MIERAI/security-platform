package identity

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
)

func TestAPIBaseIsTLSOnly(t *testing.T) {
	t.Parallel()
	tests := []struct {
		raw string
		ok  bool
	}{
		{"https://api.example.com", true}, {"https://ghe.example/api/v3/", true}, {"http://127.0.0.1:8080", true},
		{"http://localhost:1", true}, {"http://[::1]:9", true}, {"http://api.example.com", false},
		{"ftp://127.0.0.1", false}, {"https://user:pw@api.example.com", false}, {"/relative", false},
		{"https://api.example.com/?q=1", false},
	}
	for _, tc := range tests {
		if _, err := apiBase(tc.raw); (err == nil) != tc.ok {
			t.Errorf("apiBase(%q) error %v, want ok=%v", tc.raw, err, tc.ok)
		}
	}
}

func TestNextPageStaysOnTheAPIHost(t *testing.T) {
	t.Parallel()
	base, err := url.Parse("https://api.example.com/api/v3")
	if err != nil {
		t.Fatal(err)
	}
	g := &ghAPI{base: base}
	tests := []struct{ link, want string }{
		{`<https://api.example.com/api/v3/orgs/o/members?page=2>; rel="next", <https://api.example.com/api/v3/x?page=9>; rel="last"`,
			"/orgs/o/members?page=2"},
		{`<https://evil.example/api/v3/x?page=2>; rel="next"`, ""},
		{`<http://api.example.com/api/v3/x?page=2>; rel="next"`, ""},
		{`<https://api.example.com/other/x>; rel="next"`, ""},
		{`<https://api.example.com/api/v3/x?page=9>; rel="last"`, ""},
		{"", ""},
	}
	for _, tc := range tests {
		if got := g.nextPage(tc.link); got != tc.want {
			t.Errorf("nextPage(%q) = %q, want %q", tc.link, got, tc.want)
		}
	}
}

func TestRateLimitAndScopeHint(t *testing.T) {
	t.Parallel()
	h := func(kv ...string) http.Header {
		out := http.Header{}
		for i := 0; i < len(kv); i += 2 {
			out.Set(kv[i], kv[i+1])
		}
		return out
	}
	tests := []struct {
		status int
		header http.Header
		want   string
		ok     bool
	}{
		{403, h("X-RateLimit-Remaining", "0", "X-RateLimit-Reset", "1795000000"), "rate limited until 2026-11-18T11:06:40Z", true},
		{429, h("Retry-After", "60"), "rate limited (retry after 60 s)", true},
		{403, h("X-RateLimit-Remaining", "12"), "", false},
		{404, h("X-RateLimit-Remaining", "0"), "", false},
	}
	for _, tc := range tests {
		got, ok := rateLimited(&response{status: tc.status, header: tc.header})
		if got != tc.want || ok != tc.ok {
			t.Errorf("rateLimited(%d, %v) = %q, %v", tc.status, tc.header, got, ok)
		}
	}
	if s := scopeHint(h("X-Accepted-OAuth-Scopes", "read:org", "X-OAuth-Scopes", "repo")); s != " (needs scope read:org; the token has repo)" {
		t.Errorf("scopeHint = %q", s)
	}
}

func TestStampIsPythonTs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   pyjson.Value
		want float64
		ok   bool
	}{
		{"2026-01-02T03:04:05Z", 1767323045, true}, {"2026-01-02T03:04:05.123+09:00", 1767323045, true},
		{"2026-01-02", 1767312000, true}, {"2026-1-2", 1767312000, true}, {"", 0, false}, {nil, 0, false},
		{"not a date", 0, false}, {"2026-13-01", 0, false},
	}
	for _, tc := range tests {
		got, ok := stamp(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("stamp(%v) = %v, %v; want %v, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestCertificateIsReadLikeOpenSSL(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile(filepath.Join("testdata", "client-cert.b64"))
	if err != nil {
		t.Fatal(err)
	}
	// `openssl x509 -noout -enddate -subject`: notAfter=Jan  1 00:00:00 2021 GMT, subject=O=system:masters, O=dev-team, CN=admin
	exp, groups := certNotAfter(strings.TrimSpace(string(b)))
	if exp != "2021-01-01T00:00:00Z" || strings.Join(groups, "|") != "system:masters|dev-team" {
		t.Errorf("certNotAfter = %v, %v", exp, groups)
	}
	if exp, groups := certNotAfter("bm90IGEgY2VydA=="); exp != nil || len(groups) != 0 {
		t.Errorf("garbage read as a certificate: %v %v", exp, groups)
	}
}

func TestFnmatchAndACL(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		pat, name string
		want      bool
	}{{"*.token", "a.token", true}, {"*.token", ".hidden.token", false}, {"[!a]x", "bx", true}, {"[!a]x", "ax", false},
		{"[x", "[x", true}, {"?.pub", "k.pub", true}, {"a*", "b", false}} {
		rx, err := fnmatchRegexp(tc.pat)
		if err != nil {
			t.Fatal(err)
		}
		if got := matchName(tc.name, tc.pat, rx); got != tc.want {
			t.Errorf("match(%q, %q) = %v", tc.name, tc.pat, got)
		}
	}
	for _, tc := range []struct {
		acl  string
		want bool
	}{{`{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}`, true},
		{`{"acls": [{"action": "accept", "src": ["group:a"], "dst": ["*:*"]}]}`, false},
		{`{"grants": [{"src": ["*"], "dst": ["*"]}]}`, true}, {`{}`, false}} {
		v, err := pyjson.Decode([]byte(tc.acl))
		if err != nil {
			t.Fatal(err)
		}
		if got := aclAllowsAll(v); got != tc.want {
			t.Errorf("aclAllowsAll(%s) = %v", tc.acl, got)
		}
	}
	if tokenKind("ghp_x") != "pat_classic" || tokenKind("github_pat_x") != "pat_fine_grained" || tokenKind("x") != "token" {
		t.Error("tokenKind")
	}
}

// fakeAPI is a code-host API that pages, answers 304 for a known ETag and redirects /redirect to another host.
type fakeAPI struct {
	mu   sync.Mutex
	seen []string
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" auth="+r.Header.Get("Authorization"))
	f.mu.Unlock()
	switch {
	case r.URL.Path == "/redirect":
		http.Redirect(w, r, "https://evil.example/steal", http.StatusFound)
	case r.Header.Get("If-None-Match") == `"e1"`:
		w.WriteHeader(http.StatusNotModified)
	case r.URL.Query().Get("page") == "2":
		_, _ = w.Write([]byte(`[{"login": "b"}]`))
	default:
		w.Header().Set("Etag", `"e1"`)
		w.Header().Set("Link", "<http://"+r.Host+"/list?page=2>; rel=\"next\"")
		_, _ = w.Write([]byte(`[{"login": "a"}]`))
	}
}

// TestRequestsAreReadOnlyGETs: the API client sends GET only, the token only in the Authorization header, never
// follows a redirect, pages through Link headers and uses the ETag cache (which never holds the token).
func TestRequestsAreReadOnlyGETs(t *testing.T) {
	t.Parallel()
	const token = "ghp_identity-test-canary"
	api := &fakeAPI{}
	srv := httptest.NewServer(api)
	defer srv.Close()
	base, err := apiBase(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	env := &rundoc.Env{Getenv: func(string) string { return "" }}
	g := &ghAPI{base: base, token: token, cache: t.TempDir(), client: httpClient(env), agent: "test"}
	ctx := context.Background()
	for range 2 { // the second time from the ETag cache (304)
		if a := g.getAll(ctx, "/list"); a.err != "" || len(list(a.data)) != 2 {
			t.Fatalf("getAll = %+v", a)
		}
	}
	if a := g.get(ctx, "/redirect"); a.err == "" {
		t.Error("a redirect was followed")
	}
	for _, s := range api.seen {
		if !strings.HasPrefix(s, "GET ") || !strings.HasSuffix(s, "auth=Bearer "+token) {
			t.Errorf("request %q", s)
		}
	}
	assertNoToken(t, g.cache, token)
}

func assertNoToken(t *testing.T, dir, token string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), token) {
			t.Errorf("the token is in the cache file %s", e.Name())
		}
	}
}

func TestVersionMatchesComponent(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "collectors", "identity", "VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(b)) != Version {
		t.Errorf("Version %s, collectors/identity/VERSION %s", Version, b)
	}
}
