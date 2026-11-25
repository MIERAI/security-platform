package detection

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MIERAI/security-platform/internal/collectors/execad"
	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
)

type fakeScenario struct {
	token string // expected bearer token on log-store paths ("" = none required)
}

type fakeStore struct {
	*httptest.Server
	mutations, tokenSeen, requests atomic.Int64
}

// newFakeStore is a Loki/Alertmanager read API that counts (and refuses) any method but GET.
func newFakeStore(t *testing.T, sc fakeScenario) *fakeStore {
	t.Helper()
	f := &fakeStore{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		if r.Method != http.MethodGet {
			f.mutations.Add(1)
			http.Error(w, "read-only", http.StatusMethodNotAllowed)
			return
		}
		if sc.token != "" && r.Header.Get("Authorization") == "Bearer "+sc.token {
			f.tokenSeen.Add(1)
		}
		switch r.URL.Path {
		case "/loki/api/v1/query":
			_, _ = fmt.Fprint(w, `{"data": {"result": [{"metric": {"host": "web-1"}, "value": [1, "4"]}]}}`)
		case "/prometheus/api/v1/rules":
			_, _ = fmt.Fprint(w, `{"data": {"groups": [{"rules": [{"name": "SecurityDetectionAuthSudoFailure", "health": "ok"}]}]}}`)
		case "/api/v2/status":
			_, _ = fmt.Fprint(w, `{"config": {"original": "route: {routes: [{receiver: p, matchers: [severity=page]}]}\nreceivers: [{name: p, webhook_configs: [{}]}]"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.Close)
	return f
}

type result struct {
	doc    map[string]any
	stderr string
	files  map[string][]byte
}

func write(t *testing.T, p, text string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(text), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

func run(t *testing.T, dir string, detection map[string]any, kube kubectlFunc) result {
	t.Helper()
	inst, err := json.Marshal(map[string]any{"detection": detection, "kubernetes": []any{map[string]any{"name": "lab"}}})
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "instance.json"), string(inst), 0o600)
	runDir := filepath.Join(dir, "run")
	vars := map[string]string{"SP_INSTANCE": filepath.Join(dir, "instance.json"), "SP_RUN_DIR": runDir,
		"SP_DATA": filepath.Join(dir, "data"), "HOME": dir}
	var stderr bytes.Buffer
	env := &rundoc.Env{Getenv: func(k string) string { return vars[k] }, Stderr: &stderr, Now: time.Now}
	c := &rundoc.Collector{Name: Name, Version: Version, Collect: func(ctx context.Context, run *rundoc.Run, env *rundoc.Env) error {
		return collect(ctx, run, env, filepath.Join("..", "..", ".."), kube)
	}}
	if code := rundoc.Main(context.Background(), c, []string{"collect"}, env, io.Discard); code != 0 {
		t.Fatalf("collect: exit %d (%s)", code, stderr.String())
	}
	res := result{stderr: stderr.String(), files: map[string][]byte{}}
	err = filepath.WalkDir(runDir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, rerr := os.ReadFile(p)
		res.files[p] = b
		return rerr
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(res.files[filepath.Join(runDir, "detection.findings.json")], &res.doc); err != nil {
		t.Fatal(err)
	}
	return res
}

func coverage(doc map[string]any) map[string]string {
	out := map[string]string{}
	list, _ := doc["coverage"].([]any) // shape fixed by rundoc
	for _, c := range list {
		m, _ := c.(map[string]any)
		asset, _ := m["asset"].(string)
		status, _ := m["status"].(string)
		reason, _ := m["reason"].(string)
		out[asset] = strings.TrimSpace(status + " " + reason)
	}
	return out
}

func noCanary(t *testing.T, res result, canary string) {
	t.Helper()
	for p, b := range res.files {
		if bytes.Contains(b, []byte(canary)) {
			t.Errorf("token in %s", p)
		}
	}
	if strings.Contains(res.stderr, canary) {
		t.Error("token on stderr")
	}
}

func canaryToken() string { return "detection-canary-" + strings.Repeat("7q", 8) }

func noKube(context.Context, string, []string) execad.Result {
	return execad.Result{RC: 1, Err: "no cluster"}
}

// TestTokenSentOnlyFromPrivateFile: a 0600 token file is used and never written anywhere; a group-readable one is
// refused before any request carries it (DETECTION-D1).
func TestTokenSentOnlyFromPrivateFile(t *testing.T) {
	skipOnWindows(t)
	t.Parallel()
	tok := canaryToken()
	tests := []struct {
		name     string
		mode     os.FileMode
		wantSeen bool
		status   string
	}{{"private", 0o600, true, "ok"}, {"group-readable", 0o640, false, "gap log store query failed: PermissionError: token_file readable by group/others"}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			srv := newFakeStore(t, fakeScenario{token: tok})
			dir := t.TempDir()
			write(t, filepath.Join(dir, "tok"), tok+"\n", tt.mode)
			res := run(t, dir, map[string]any{"log_store": map[string]any{"url": srv.URL, "token_file": "~/tok"},
				"alertmanager": map[string]any{"url": srv.URL}, "expected": map[string]any{"auth": []any{"web-1"}}}, noKube)
			noCanary(t, res, tok)
			if got := srv.tokenSeen.Load() > 0; got != tt.wantSeen {
				t.Errorf("token seen by the server: %v", got)
			}
			if got := coverage(res.doc)["log-source:auth/web-1"]; !strings.HasPrefix(got, tt.status) {
				t.Errorf("coverage %q, want %q", got, tt.status)
			}
			if srv.mutations.Load() != 0 {
				t.Error("a mutating request reached the server")
			}
		})
	}
}

func TestSensorsThroughKubectl(t *testing.T) {
	t.Parallel()
	var calls atomic.Int64
	kube := func(_ context.Context, kc string, args []string) execad.Result {
		calls.Add(1)
		if args[0] != "get" || args[len(args)-1] != "json" {
			t.Errorf("kubectl %v: not a read", args)
		}
		if kc != "" {
			return execad.Result{RC: 1, Err: "  denied \n"}
		}
		if args[1] == "daemonsets" {
			return execad.Result{Out: `{"items": [{"metadata": {"name": "falco"}, "status": {"desiredNumberScheduled": 2, "numberReady": 2}}]}`}
		}
		return execad.Result{Out: `{"items": []}`}
	}
	res := run(t, t.TempDir(), map[string]any{"clusters": []any{map[string]any{"name": "lab"},
		map[string]any{"name": "prod", "kubeconfig": "~/p.yaml"}}, "expected": map[string]any{"k8s-audit": []any{"lab"}}}, kube)
	cov := coverage(res.doc)
	if cov["k8s-cluster:lab"] != "ok" || cov["k8s-cluster:prod"] != "gap cannot list DaemonSets: denied" {
		t.Errorf("coverage %v", cov)
	}
	var checks []string
	list, _ := res.doc["findings"].([]any) // shape fixed by rundoc
	for _, f := range list {
		m, _ := f.(map[string]any)
		checks = append(checks, fmt.Sprint(m["check"], " ", m["asset"]))
	}
	want := []string{"detection.sensor_missing k8s-cluster:lab/node-logs", "detection.backstop_missing k8s-cluster:lab/backstop",
		"detection.drill_overdue detection-drills:lab"}
	if strings.Join(checks, "|") != strings.Join(want, "|") {
		t.Errorf("findings %v, want %v", checks, want)
	}
	if calls.Load() != 4 {
		t.Errorf("%d kubectl calls", calls.Load())
	}
}

// skipOnWindows: the test needs a token file with POSIX permissions (refused on Windows, where the mode bits Go
// reports are not permissions) or POSIX programs; the Linux and macOS runs cover it.
func skipOnWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file permissions / programs")
	}
}
