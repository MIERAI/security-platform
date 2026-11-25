package notifier

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/MIERAI/security-platform/internal/pyvalue"
)

const token = "123456:SECRET-bot-token"

type request struct{ path, ctype, ua, body string }

type sink struct {
	mu   sync.Mutex
	got  []request
	code int
}

func (s *sink) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.got = append(s.got, request{r.URL.Path, r.Header.Get("Content-Type"), r.Header.Get("User-Agent"), string(b)})
	code := s.code
	s.mu.Unlock()
	w.WriteHeader(code)
}

func secretFile(t *testing.T, value string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "s")
	if err := os.WriteFile(p, []byte(value+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func cfg(kv ...any) *pyvalue.Map {
	m := pyvalue.NewMap()
	for i := 0; i+1 < len(kv); i += 2 {
		m.Set(fmt.Sprint(kv[i]), kv[i+1])
	}
	return m
}

func env() Env {
	return Env{Stdout: &bytes.Buffer{}, Getenv: func(string) string { return "" }}
}

func TestHTTPAdapters(t *testing.T) {
	t.Parallel()
	text := "Security 2026-11-25 (x)\nOpen: 1 high é"
	tok := secretFile(t, token, 0o600)
	tests := []struct {
		name string
		cfg  func(base string) *pyvalue.Map
		want request
	}{
		{"slack", func(base string) *pyvalue.Map {
			return cfg("type", "webhook", "url_file", secretFile(t, base+"/hook", 0o600))
		}, request{"/hook", "application/json", "security-platform",
			`{"text": "Security 2026-11-25 (x)\nOpen: 1 high \` + `u00e9"}`}},
		{"json", func(base string) *pyvalue.Map { return cfg("type", "webhook", "url", base+"/j", "format", "json") }, request{"/j", "application/json", "security-platform",
			`{"title": "Security 2026-11-25 (x)", "text": "Open: 1 high \` + `u00e9"}`}},
		{"text", func(base string) *pyvalue.Map { return cfg("type", "webhook", "url", base+"/t", "format", "text") }, request{"/t", "text/plain; charset=utf-8",
			"security-platform", text}},
		{"telegram", func(base string) *pyvalue.Map {
			return cfg("type", "telegram", "token_file", tok, "chat_id", int64(42), "api", base+"/")
		},
			request{"/bot" + token + "/sendMessage", "application/x-www-form-urlencoded", "security-platform",
				"chat_id=42&text=" + url.QueryEscape(text) + "&disable_web_page_preview=true"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := &sink{code: 200}
			srv := httptest.NewServer(s)
			t.Cleanup(srv.Close)
			if err := Send(t.Context(), env(), tc.cfg(srv.URL), text); err != nil {
				t.Fatal(err)
			}
			s.mu.Lock()
			got := s.got[len(s.got)-1]
			s.mu.Unlock()
			if got != tc.want {
				t.Fatalf("got %+v\nwant %+v", got, tc.want)
			}
		})
	}
}

// TestErrorsHoldNoSecret: an HTTP error, a refused connection and a refused secret file say what happened, never
// the token or the URL.
func TestErrorsHoldNoSecret(t *testing.T) {
	t.Parallel()
	s := &sink{code: 500}
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	down := httptest.NewServer(http.NotFoundHandler())
	downURL := down.URL
	down.Close()
	tests := []struct {
		name string
		cfg  *pyvalue.Map
		want string
	}{
		{"http 500", cfg("type", "telegram", "token_file", secretFile(t, token, 0o600), "chat_id", "1", "api", srv.URL), "HTTP 500"},
		{"refused", cfg("type", "telegram", "token_file", secretFile(t, token, 0o600), "chat_id", "1", "api", downURL), "cannot connect"},
		{"open token", cfg("type", "telegram", "token_file", secretFile(t, token, 0o644), "chat_id", "1"), "must be mode 0600"},
		{"webhook url file open", cfg("type", "webhook", "url_file", secretFile(t, srv.URL+"/x?key="+token, 0o640)), "must be mode 0600"},
		{"not http", cfg("type", "webhook", "url", "file:///etc/passwd?"+token), "not an http(s) URL"},
		{"bad format", cfg("type", "webhook", "url", srv.URL, "format", "xml"), "webhook format 'xml'"},
		{"unknown type", cfg("type", "pager"), "unknown notifier 'pager' (one of stdout, file, webhook, telegram, exec)"},
		{"no token", cfg("type", "telegram"), "token_file is required"},
		{"nil", nil, "a notifier is a mapping"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := Send(t.Context(), env(), tc.cfg, "text")
			if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "SECRET") ||
				strings.Contains(err.Error(), "127.0.0.1") {
				t.Fatalf("error %v, want %q and no secret or address", err, tc.want)
			}
		})
	}
}

func TestFileAndStdout(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), "sub", "latest.txt")
	if err := Send(t.Context(), env(), cfg("type", "file", "path", p), "Security"); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(p); err != nil || string(b) != "Security\n" { // #nosec G304 -- test file
		t.Fatalf("file: %q %v", b, err)
	}
	var out bytes.Buffer
	if err := Send(t.Context(), Env{Stdout: &out}, cfg("type", "stdout"), "hi"); err != nil || out.String() != "hi\n" {
		t.Fatalf("stdout: %q %v", out.String(), err)
	}
}

func TestExec(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell")
	}
	out := filepath.Join(t.TempDir(), "out")
	ok := cfg("type", "exec", "argv", []any{"/bin/sh", "-c", `cat > "$0"`, out})
	if err := Send(t.Context(), env(), ok, "piped text"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(out); string(b) != "piped text" { // #nosec G304 -- test file
		t.Fatalf("stdin: %q", b)
	}
	fail := cfg("type", "exec", "argv", []any{"/bin/sh", "-c", "echo " + strings.Repeat("x", 200) + "boom >&2; exit 3"})
	err := Send(t.Context(), env(), fail, "t")
	if !errors.Is(err, ErrDelivery) || !strings.HasSuffix(err.Error(), "rc=3: "+strings.Repeat("x", 116)+"boom") {
		t.Fatalf("failing command: %v", err)
	}
	for _, bad := range []*pyvalue.Map{cfg("type", "exec"), cfg("type", "exec", "argv", []any{}),
		cfg("type", "exec", "argv", []any{"x"}, "exec", cfg("type", "ssm")),
		cfg("type", "exec", "argv", []any{"x"}, "exec", cfg("type", "ssh", "host", "-oProxyCommand=x"))} {
		if err := Send(t.Context(), env(), bad, "t"); !errors.Is(err, ErrConfig) {
			t.Errorf("%v: %v", bad, err)
		}
	}
}

func TestCommandLine(t *testing.T) {
	t.Parallel()
	var ran []string
	e := env()
	e.Run = func(_ context.Context, argv []string, _ string) (int, string, error) {
		ran = argv
		return 0, "", nil
	}
	c := cfg("type", "exec", "argv", []any{"say", "it's", "a b", ""}, "exec", cfg("type", "ssh", "host", "speaker", "options", []any{"-p", "2222"}))
	if err := Send(t.Context(), e, c, "t"); err != nil {
		t.Fatal(err)
	}
	want := append(append([]string{"ssh"}, sshBase()...), "-p", "2222", "speaker", `say 'it'"'"'s' 'a b' ''`)
	if strings.Join(ran, "|") != strings.Join(want, "|") {
		t.Fatalf("ssh argv %q", ran)
	}
	// Python subprocess.list2cmdline outputs
	for in, want := range map[string]string{
		"a b\x00c":      `"a b" c`,
		`x"y`:           `x\"y`,
		`back\\`:        `back\\`,
		"sp ace\\\\":    `"sp ace\\\\"`,
		"\x00":          `"" ""`,
		`a\"b`:          `a\\\"b`,
		"tab\there\x00": `"tab	here" ""`,
	} {
		if got := windowsCommandLine(strings.Split(in, "\x00")); got != want {
			t.Errorf("list2cmdline(%q) = %s, want %s", in, got, want)
		}
	}
}

func FuzzShellQuote(f *testing.F) {
	for _, s := range []string{"", "a", "it's", "a b", "$(id)", "'", "\n"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		q := shellQuote(s)
		if got := unquotePOSIX(q); got != s {
			t.Fatalf("shellQuote(%q) = %s reads back as %q", s, q, got)
		}
		_ = windowsCommandLine([]string{s, s})
	})
}

// unquotePOSIX reads back a word made of plain characters, '...' and "'" pieces (what shellQuote writes).
func unquotePOSIX(q string) string {
	var b strings.Builder
	for i := 0; i < len(q); i++ {
		switch q[i] {
		case '\'':
			j := strings.IndexByte(q[i+1:], '\'')
			b.WriteString(q[i+1 : i+1+j])
			i += j + 1
		case '"':
			j := strings.IndexByte(q[i+1:], '"')
			b.WriteString(q[i+1 : i+1+j])
			i += j + 1
		default:
			b.WriteByte(q[i])
		}
	}
	return b.String()
}
