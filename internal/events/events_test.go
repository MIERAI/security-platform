package events

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MIERAI/security-platform/internal/collectors/roclient"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

const testNow = 1795608000.0 // 2026-11-25T12:00:00Z

func TestParseSyslog(t *testing.T) {
	t.Parallel()
	tests := []struct {
		line, event, user, ip string
		ts                    float64
	}{
		{"2026-11-25T11:40:00+00:00 lab sshd[1]: Accepted publickey for ops from 10.0.0.1 port 5 ssh2", "ssh_login_success", "ops", "10.0.0.1", testNow - 1200},
		{"2026-11-25T11:40:00Z lab sshd-session[1]: Failed password for invalid user admin from 192.0.2.7 port 5 ssh2", "ssh_login_failure", "admin", "192.0.2.7", testNow - 1200},
		{"Nov 25 11:40:00 lab dropbear[9]: Bad password attempt for 'root' from 192.0.2.8:4444", "ssh_login_failure", "root", "192.0.2.8", testNow - 1200},
		{"Nov 25 11:40:00 lab dropbear[9]: Pubkey auth succeeded for 'ops' with key x from [2001:db8::1]:22", "ssh_login_success", "ops", "2001:db8::1", testNow - 1200},
		{"2026-11-25T11:40:00+01:00 lab sudo:  ops : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/id", "sudo", "ops", "", testNow - 4800},
		{"2026-11-25T11:40:00+00:00 lab sudo:  ops : 3 incorrect password attempts ; COMMAND=/bin/id", "sudo_failure", "ops", "", testNow - 1200},
	}
	opts := pyvalue.NewMap()
	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			t.Parallel()
			e, err := parseSyslog(tt.line, testNow, opts, time.UTC)
			if err != nil || e == nil {
				t.Fatalf("%v %v", e, err)
			}
			if e.ts != tt.ts || textOf(e.get("event")) != tt.event || textOf(e.get("user")) != tt.user ||
				textOf(e.get("src_ip")) != tt.ip {
				t.Errorf("ts %v meta %v", e.ts, pyvalue.Repr(e.meta))
			}
		})
	}
	for _, line := range []string{"not a log line", "Nov 25 11:40:00 lab dropbear[1]: Exit before auth", "type=AVC avc: sshd: x"} {
		if e, err := parseSyslog(line, testNow, opts, time.UTC); e != nil || err != nil {
			t.Errorf("%q: %v %v", line, e, err)
		}
	}
}

func TestBSDTimeAndOffset(t *testing.T) {
	t.Parallel()
	tz, err := parseTZ("+09:00")
	if err != nil {
		t.Fatal(err)
	}
	got, err := bsdTime("Nov 25 21:00:00", testNow, tz, time.UTC)
	if err != nil || got != testNow {
		t.Errorf("bsdTime +09:00 = %v %v", got, err)
	}
	// a December line read in January belongs to the previous year
	got, err = bsdTime("Dec 31 23:00:00", 1798761600 /* 2027-01-01T00:00Z */, nil, time.UTC)
	if err != nil || got != 1798758000 {
		t.Errorf("year roll = %v %v", got, err)
	}
	for _, bad := range []string{"0900", "+9:00", "+24:00", "UTC"} {
		if _, err := parseTZ(bad); err == nil {
			t.Errorf("parseTZ(%q) accepted", bad)
		}
	}
}

func TestNanosAndStream(t *testing.T) {
	t.Parallel()
	if got := nanos(1795606800.5); got != "1795606800500000000" {
		t.Errorf("nanos = %s", got)
	}
	if got := nextLink(`<https://api/x?page=2>; rel="next", <https://api/x?page=9>; rel="last"`); got != "https://api/x?page=2" {
		t.Errorf("nextLink = %q", got)
	}
}

// TestOnlyPushAndTokenArePosted: GET/HEAD anywhere, POST only to the URLs given, nothing else ever leaves.
func TestOnlyPushAndTokenArePosted(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	c := newHTTP(nil, srv.URL+"/loki/api/v1/push")
	do := func(method, path string) error {
		req, err := http.NewRequestWithContext(context.Background(), method, srv.URL+path, strings.NewReader("{}"))
		if err != nil {
			return err
		}
		res, err := c.Do(req)
		if res != nil {
			if cerr := res.Body.Close(); cerr != nil {
				return cerr
			}
		}
		return err
	}
	if err := do(http.MethodPost, "/loki/api/v1/push"); err != nil {
		t.Fatal(err)
	}
	if err := do(http.MethodGet, "/user"); err != nil {
		t.Fatal(err)
	}
	if err := do(http.MethodPost, "/user/keys"); !errors.Is(err, errPostRefused) {
		t.Errorf("POST elsewhere: %v", err)
	}
	for _, m := range []string{http.MethodPut, http.MethodPatch, http.MethodDelete} {
		if err := do(m, "/loki/api/v1/push"); !errors.Is(err, roclient.ErrMutating) {
			t.Errorf("%s: %v", m, err)
		}
	}
	if strings.Join(seen, ",") != "POST /loki/api/v1/push,GET /user" {
		t.Errorf("requests that reached the server: %v", seen)
	}
}

type pushed struct {
	mu     sync.Mutex
	bodies [][]byte
	auth   []string
	fail   bool
}

func (p *pushed) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.fail {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	var b bytes.Buffer
	if _, err := b.ReadFrom(r.Body); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	p.bodies = append(p.bodies, b.Bytes())
	p.auth = append(p.auth, r.Header.Get("Authorization"))
	w.WriteHeader(http.StatusNoContent)
}

type shipRun struct {
	dir, state string
	stdout     bytes.Buffer
	stderr     bytes.Buffer
}

func setup(t *testing.T, url string, loki map[string]any) *shipRun {
	t.Helper()
	r := &shipRun{dir: t.TempDir()}
	r.state = filepath.Join(r.dir, "state")
	log := "2026-11-25T11:40:00+00:00 lab sshd[1]: Accepted publickey for ops from 10.0.0.1 port 5 ssh2\n"
	writeFile(t, filepath.Join(r.dir, "auth.log"), log, 0o600)
	loki["url"] = url + "/loki/api/v1/push"
	cfg := map[string]any{"loki": loki, "sources": []any{map[string]any{"name": "a", "type": "command", "host": "lab",
		"parser": "openssh", "argv": []any{"cat", filepath.Join(r.dir, "auth.log")}}}}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(r.dir, "events.json"), string(data), 0o600)
	return r
}

func (r *shipRun) run(t *testing.T) int {
	t.Helper()
	env := Env{Getenv: func(string) string { return "" }, Stdout: &r.stdout, Stderr: &r.stderr,
		Now: func() time.Time { return time.Unix(int64(testNow), 0) }, Location: time.UTC}
	return Main(context.Background(), env, []string{"ship", "--config", filepath.Join(r.dir, "events.json"), "--state",
		r.state, "--summary", filepath.Join(r.dir, "summary.json"), "--now", "1795608000"})
}

func writeFile(t *testing.T, p, text string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

func TestCursorKeptOnFailedPush(t *testing.T) {
	t.Parallel()
	p := &pushed{fail: true}
	srv := httptest.NewServer(p)
	defer srv.Close()
	r := setup(t, srv.URL, map[string]any{})
	if code := r.run(t); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if _, err := os.Stat(filepath.Join(r.state, "a.json")); err == nil {
		t.Fatal("state written after a failed push")
	}
	p.mu.Lock()
	p.fail = false
	p.mu.Unlock()
	if code := r.run(t); code != 0 {
		t.Fatalf("exit %d: %s", code, r.stderr.String())
	}
	st, err := os.Stat(filepath.Join(r.state, "a.json"))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("state %v %v", st, err)
	}
	if len(p.bodies) != 2 || !bytes.Contains(p.bodies[0], []byte(`"ssh_login_success"`)) {
		t.Errorf("pushed %q", p.bodies)
	}
}

// TestTokenNeverLeaves: a private token goes only into the push's Authorization header; a token readable by others
// is refused before any push; neither ever reaches the state, the summary or the output.
func TestTokenNeverLeaves(t *testing.T) {
	t.Parallel()
	canary := "push-canary-" + "71c0de"
	for _, mode := range []os.FileMode{0o600, 0o644} {
		p := &pushed{}
		srv := httptest.NewServer(p)
		dir := t.TempDir()
		tok := filepath.Join(dir, "tok")
		writeFile(t, tok, canary+"\n", mode)
		r := setup(t, srv.URL, map[string]any{"token_file": tok})
		code := r.run(t)
		srv.Close()
		want, pushes := 0, 2
		if mode != 0o600 {
			want, pushes = 1, 0
		}
		if code != want || len(p.bodies) != pushes {
			t.Fatalf("mode %o: exit %d, %d pushes", mode, code, len(p.bodies))
		}
		for _, a := range p.auth {
			if a != "Bearer "+canary {
				t.Errorf("Authorization %q", a)
			}
		}
		noCanary(t, r, canary, p.bodies)
	}
}

func noCanary(t *testing.T, r *shipRun, canary string, bodies [][]byte) {
	t.Helper()
	if strings.Contains(r.stdout.String()+r.stderr.String(), canary) {
		t.Error("token in the output")
	}
	for _, b := range bodies {
		if bytes.Contains(b, []byte(canary)) {
			t.Error("token in a pushed body")
		}
	}
	for _, f := range []string{filepath.Join(r.dir, "summary.json"), filepath.Join(r.state, "a.json")} {
		if b, err := os.ReadFile(f); err == nil && bytes.Contains(b, []byte(canary)) {
			t.Errorf("token in %s", f)
		}
	}
}

func TestUsage(t *testing.T) {
	t.Parallel()
	var out, errb bytes.Buffer
	env := Env{Getenv: func(string) string { return "" }, Stdout: &out, Stderr: &errb, Now: time.Now}
	for _, args := range [][]string{nil, {"ship"}, {"ship", "--config", "x"}, {"ship", "--bogus"}, {"other"}} {
		if code := Main(context.Background(), env, args); code != 2 {
			t.Errorf("%v: exit %d", args, code)
		}
	}
}

func TestVersionMatchesTree(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("..", "..", "events", "VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(data)); got != Version {
		t.Fatalf("events/VERSION %s, Go %s", got, Version)
	}
}
