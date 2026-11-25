package codehostgitea

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

func canary() string { return "gitea-canary-" + "a91f07" }

type recorder struct {
	mu      sync.Mutex
	methods []string
	auth    []string
}

func (r *recorder) note(req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.methods = append(r.methods, req.Method)
	r.auth = append(r.auth, req.Header.Get("Authorization"))
}

func repoJSON(full, extra string) string {
	return `{"full_name": "` + full + `", "default_branch": "main"` + extra + `}`
}

func run(t *testing.T, url, tokenMode string) (doc string, files map[string][]byte) {
	t.Helper()
	dir := t.TempDir()
	tf := filepath.Join(dir, "token")
	if err := os.WriteFile(tf, []byte(canary()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if tokenMode == "loose" {
		if err := os.Chmod(tf, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	inst, err := json.Marshal(map[string]any{"codehost": []any{map[string]any{"type": "gitea", "url": url, "owner": "lab",
		"token_file": tf}}})
	if err != nil {
		t.Fatal(err)
	}
	if werr := os.WriteFile(filepath.Join(dir, "i.json"), inst, 0o600); werr != nil {
		t.Fatal(werr)
	}
	vars := map[string]string{"SP_INSTANCE": filepath.Join(dir, "i.json"), "SP_RUN_DIR": filepath.Join(dir, "run")}
	var stderr bytes.Buffer
	env := rundoc.Env{Getenv: func(k string) string { return vars[k] }, Stderr: &stderr, Now: time.Now}
	if code := Main(context.Background(), env, []string{"collect"}); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	files = map[string][]byte{"stderr": stderr.Bytes()}
	err = filepath.WalkDir(filepath.Join(dir, "run"), func(p string, e os.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return err
		}
		b, rerr := os.ReadFile(p)
		files[filepath.Base(p)] = b
		return rerr
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(files[Name+".findings.json"]), files
}

func noCanary(t *testing.T, files map[string][]byte) {
	t.Helper()
	for n, b := range files {
		if bytes.Contains(b, []byte(canary())) {
			t.Errorf("token in %s", n)
		}
	}
}

func TestPostureReadOnly(t *testing.T) {
	skipOnWindows(t)
	t.Parallel()
	rec := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.note(r)
		switch r.URL.Path {
		case "/api/v1/orgs/lab/repos":
			_, _ = w.Write([]byte(`[` + repoJSON("lab/a", "") + `,` + repoJSON("lab/b", `, "mirror": true, "original_url": "http://x"`) + `]`))
		case "/api/v1/repos/lab/a/branch_protections":
			_, _ = w.Write([]byte(`[{"rule_name": "main", "enable_push": false, "required_approvals": 1}]`))
		case "/api/v1/repos/lab/b/branch_protections":
			_, _ = w.Write([]byte(`[]`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	doc, files := run(t, srv.URL, "")
	noCanary(t, files)
	for _, want := range []string{`"asset": "repo:gitea/127.0.0.1/lab/a"`, `"check": "repo.default_branch_unprotected"`,
		`"check": "repo.mirror_unverified_remote"`} {
		if !strings.Contains(doc, want) {
			t.Errorf("no %s in %s", want, doc)
		}
	}
	for i, m := range rec.methods {
		if m != http.MethodGet || rec.auth[i] != "token "+canary() {
			t.Errorf("request %d: %s auth=%t", i, m, rec.auth[i] != "")
		}
	}
}

// TestTokenStaysOnItsServer: a redirect to another server is not followed; that server never sees the token.
func TestTokenStaysOnItsServer(t *testing.T) {
	skipOnWindows(t)
	t.Parallel()
	other := &recorder{}
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		other.note(r)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer elsewhere.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	doc, files := run(t, srv.URL, "")
	noCanary(t, files)
	if len(other.methods) != 0 || !strings.Contains(doc, "redirect") {
		t.Errorf("%d requests elsewhere; %s", len(other.methods), doc)
	}
}

func TestLooseTokenFileSendsNothing(t *testing.T) {
	skipOnWindows(t)
	t.Parallel()
	rec := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { rec.note(r) }))
	defer srv.Close()
	doc, files := run(t, srv.URL, "loose")
	noCanary(t, files)
	if len(rec.methods) != 0 || !strings.Contains(doc, "must be mode 0600") {
		t.Errorf("%d requests; %s", len(rec.methods), doc)
	}
}

func TestProtectionFor(t *testing.T) {
	t.Parallel()
	rules := decode(t, `[{"rule_name": "rel*"}, {"branch_name": "main", "n": 1}, {"rule_name": "release/*", "n": 2}, 7]`)
	tests := []struct {
		branch string
		want   any
	}{{"main", int64(1)}, {"release/v1", nil}, {"dev", "none"}}
	for _, tt := range tests {
		got := ProtectionFor(rules, tt.branch)
		switch {
		case tt.want == "none" && got != nil:
			t.Errorf("%s: %v", tt.branch, got.Keys())
		case tt.want != "none" && (got == nil || !pyvalue.Equal(got.Value("n"), tt.want)):
			t.Errorf("%s: %v", tt.branch, got)
		}
	}
}

func decode(tb testing.TB, s string) []any {
	tb.Helper()
	v, err := pyvalue.DecodeJSON([]byte(s))
	if err != nil {
		tb.Fatal(err)
	}
	l, _ := v.([]any) // the callers pass lists
	return l
}

func TestVersionMatchesTree(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "collectors", "codehost-gitea", "VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(data)); got != Version {
		t.Fatalf("VERSION %s, Go %s", got, Version)
	}
}

func FuzzProtectionFor(f *testing.F) {
	f.Add([]byte(`[{"rule_name": "main"}, {"branch_name": "r/*"}]`), "r/x")
	f.Add([]byte(`[{"rule_name": null, "branch_name": 3}, "x", {}]`), "3")
	f.Fuzz(func(t *testing.T, data []byte, branch string) {
		v, err := pyvalue.DecodeJSON(data)
		if err != nil {
			return
		}
		l, _ := v.([]any) // not a list: no rules
		if r := ProtectionFor(l, branch); r != nil && !containsMap(l, r) {
			t.Fatal("a rule that is not in the list")
		}
	})
}

func containsMap(l []any, m *pyvalue.Map) bool {
	for _, x := range l {
		if x == any(m) {
			return true
		}
	}
	return false
}

// skipOnWindows: the test needs a token file with POSIX permissions (refused on Windows, where the mode bits Go
// reports are not permissions) or POSIX programs; the Linux and macOS runs cover it.
func skipOnWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file permissions / programs")
	}
}
