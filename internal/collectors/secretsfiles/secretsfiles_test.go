package secretsfiles

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

func TestVersionMatchesTree(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "collectors", "secrets-files", "VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(b)); got != Version {
		t.Fatalf("collectors/secrets-files/VERSION %s, Version %s", got, Version)
	}
}

func TestHomeRelative(t *testing.T) {
	t.Parallel()
	tests := []struct{ path, home, want string }{
		{"/home/u/.ssh/id", "/home/u", "~/.ssh/id"},
		{"/home/u", "/home/u", "~"},
		{"/home/u2/.env", "/home/u", "/home/u2/.env"},
		{"/backup/home/u/.ssh/id", "/home/u", "/backup/home/u/.ssh/id"},
		{"/home/u/x", "/home/u/", "~/x"},
		{`C:\Users\u\.ssh\id`, `C:\Users\u`, `~\.ssh\id`},
		{"/etc/x", "/", "/etc/x"},
		{"/etc/x", "", "/etc/x"},
	}
	for _, tt := range tests {
		if got := homeRelative(tt.path, tt.home); got != tt.want {
			t.Errorf("homeRelative(%q, %q) = %q, want %q", tt.path, tt.home, got, tt.want)
		}
	}
}

func TestParseScanRejects(t *testing.T) {
	t.Parallel()
	for _, out := range []string{"", "\n \n", "Traceback\nnot json", `[1]`, `{"home": 1, "items": []}`,
		`{"home": "/h", "items": [1]}`, `{"home": "/h", "items": [{"path": "/h/x", "kind": "dotenv", "mode": "0o6z0", "mtime": 1}]}`,
		`{"home": "/h", "items": [{"path": "/h/x", "kind": "dotenv", "mode": "0o600", "mtime": true}]}`,
		`{"home": "/h", "items": [{"path": "/h/x", "kind": "dotenv", "mode": "0o600"}]}`} {
		if _, err := parseScan(out); err == nil {
			t.Errorf("parseScan(%q) accepted", out)
		}
	}
	sr, err := parseScan("noise\n" + `{"home": "C:\\Users\\u", "items": [{"path": "C:\\Users\\u\\a\\b", "kind": "secret-file", "mode": "unknown", "mtime": 1.5}]}` + "\n")
	if err != nil || len(sr.items) != 1 || sr.items[0].path != "~/a/b" {
		t.Fatalf("parseScan: %+v %v", sr, err)
	}
}

func newRun(t *testing.T, now time.Time) *job {
	t.Helper()
	clock := func() time.Time { return now }
	return &job{Run: &rundoc.Run{Instance: pyvalue.NewMap(), Dir: t.TempDir(), Doc: rundoc.New("secrets-files", Version, "", clock)},
		env: &rundoc.Env{Stderr: &bytes.Buffer{}, Now: clock}}
}

// TestReport: severities from mode bits and properties, the host-key and kubeconfig exceptions, age thresholds.
func TestReport(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC)
	ago := func(days float64) float64 { return float64(now.Unix()) - days*86400 }
	items := []map[string]any{
		{"path": "/h/.ssh/id", "kind": "private-key", "mode": "0o600", "mtime": ago(91), "passphrase": false},
		{"path": "/h/.ssh/ssh_host_rsa_key", "kind": "private-key", "mode": "0o600", "mtime": ago(1), "passphrase": false},
		{"path": "/h/.ssh/ok", "kind": "private-key", "mode": "0o600", "mtime": ago(90.5), "passphrase": nil},
		{"path": "/h/k1", "kind": "kubeconfig", "mode": "0o644", "mtime": ago(1)},
		{"path": "/h/k2", "kind": "kubeconfig", "mode": "0o640", "mtime": ago(1), "token_auth": true},
		{"path": "/h/s.tfstate", "kind": "tf-state", "mode": "0o604", "mtime": ago(1), "encrypted": true},
		{"path": "/h/.env", "kind": "dotenv", "mode": "0o600", "mtime": ago(400)},
		{"path": "/h/n.md", "kind": "notes", "mode": "0o644", "mtime": ago(400), "credential_like_lines": 2},
	}
	data, err := json.Marshal(map[string]any{"home": "/h", "items": items})
	if err != nil {
		t.Fatal(err)
	}
	sr, err := parseScan(string(data))
	if err != nil {
		t.Fatal(err)
	}
	r := newRun(t, now)
	if err := report(r, "x", sr); err != nil {
		t.Fatal(err)
	}
	var got []string
	findings, _ := docJSON(t, r.Doc, now)["findings"].([]any)
	for _, f := range findings {
		m, _ := f.(map[string]any)
		got = append(got, pyvalue.Str(m["asset"])+" "+pyvalue.Str(m["check"])+" "+pyvalue.Str(m["severity"]))
	}
	want := []string{
		"secret-file:x:~/.ssh/id secret.ssh_key_no_passphrase medium",
		"secret-file:x:~/.ssh/id secret.age_over_90d low",
		"secret-file:x:~/k2 secret.permissions_too_open medium",
		"secret-file:x:~/s.tfstate secret.permissions_too_open low",
		"secret-file:x:~/.env secret.age_over_90d medium",
		"secret-file:x:~/n.md secret.credential_in_notes high",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("findings\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// FuzzParseScan: any scan output is either rejected or read into items with home-relative, "/"-separated paths;
// the report of what was read never fails.
func FuzzParseScan(f *testing.F) {
	f.Add(`{"home": "/h", "items": [{"path": "/h/a", "kind": "private-key", "mode": "0o644", "mtime": 1, "passphrase": false}]}`)
	f.Add("x\n" + `{"home": "C:\\U", "items": [{"path": "C:\\U\\b", "kind": "notes", "mode": "unknown", "mtime": 1e300}]}`)
	f.Add(`{"home": "", "items": []}`)
	f.Fuzz(func(t *testing.T, out string) {
		sr, err := parseScan(out)
		if err != nil {
			return
		}
		for _, it := range sr.items {
			if strings.Contains(it.path, `\`) {
				t.Fatalf("path %q", it.path)
			}
		}
		if err := report(newRun(t, time.Unix(1_800_000_000, 0)), "h", sr); err != nil {
			t.Fatal(err)
		}
	})
}

// TestNoContentReachesOutput runs the collector end to end on a fixture home (the real scan program, the local
// python3): every file holds a canary value; none of them may appear in any output file or on stderr, and every
// output file is private (0600).
func TestNoContentReachesOutput(t *testing.T) {
	t.Parallel()
	python, err := exec.LookPath("python3")
	if err != nil || runtime.GOOS == "windows" {
		t.Skip("needs python3 and POSIX file modes")
	}
	home, run := t.TempDir(), t.TempDir()
	files := map[string]string{".ssh/id_x": "-----BEGIN OPENSSH PRIVATE " + "KEY-----\nCANARY-KEY\n",
		"p/.env": "TOKEN=CANARY-ENV\n", "p/main.tfstate": `{"password": "CANARY-TF"}`, ".docker/config.json": `{"auths": {"r": {"auth": "CANARY-AUTH"}}}`,
		".config/gh/hosts.yml": "oauth_token: CANARY-GH\n", "notes/MEMORY.md": "password: CANARY-NOTE\n", ".secrets/db": "CANARY-DB\n",
		".kube/config": "clusters:\nusers:\n- user: {client-key-data: CANARY-KUBE}\n"}
	for rel, content := range files {
		p := filepath.Join(home, filepath.FromSlash(rel))
		if merr := os.MkdirAll(filepath.Dir(p), 0o700); merr != nil {
			t.Fatal(merr)
		}
		if werr := os.WriteFile(p, []byte(content), 0o644); werr != nil { // #nosec G306 -- group/world-readable on purpose
			t.Fatal(werr)
		}
	}
	inst := filepath.Join(t.TempDir(), "instance.json")
	cfg := `{"secrets_files": [{"host": "lab", "exec": {"type": "local"}, "roots": ["~"], "python": "` + python + `"}]}`
	if werr := os.WriteFile(inst, []byte(cfg), 0o600); werr != nil {
		t.Fatal(werr)
	}
	vars := map[string]string{"SP_RUN_DIR": run, "SP_INSTANCE": inst, "HOME": home}
	environ := []string{"HOME=" + home, "PATH=/usr/bin:/bin", "LC_ALL=C"}
	var stderr bytes.Buffer
	code := Main(context.Background(), []string{"collect"}, &rundoc.Env{Getenv: func(k string) string { return vars[k] },
		Environ: environ, Stderr: &stderr, Now: time.Now}, io.Discard)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	assertNoCanary(t, run, stderr.String())
	doc, err := os.ReadFile(filepath.Join(run, "secrets-files.findings.json"))
	if err != nil || !bytes.Contains(doc, []byte("secret.permissions_too_open")) || !bytes.Contains(doc, []byte("secret.credential_in_notes")) {
		t.Fatalf("expected findings missing: %s %v", doc, err)
	}
}

func assertNoCanary(t *testing.T, run, stderr string) {
	t.Helper()
	if strings.Contains(stderr, "CANARY") {
		t.Errorf("a file's content reached stderr: %s", stderr)
	}
	n := 0
	err := filepath.WalkDir(run, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		n++
		data, err := os.ReadFile(p) // #nosec G304 -- the test's own output
		if err != nil {
			return err
		}
		if bytes.Contains(data, []byte("CANARY")) {
			t.Errorf("a file's content reached %s", p)
		}
		if st, err := os.Stat(p); err == nil && st.Mode().Perm() != 0o600 {
			t.Errorf("%s has mode %o, want 0600", p, st.Mode().Perm())
		}
		return nil
	})
	if err != nil || n < 3 {
		t.Fatalf("walked %d output files: %v", n, err)
	}
}

// docJSON is the document as encoding/json reads it.
func docJSON(t *testing.T, d *rundoc.Document, now time.Time) map[string]any {
	t.Helper()
	data, err := pyjson.Marshal(d.Doc(now), pyjson.Options{Indent: 1, SortKeys: true, EnsureASCII: true})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}
