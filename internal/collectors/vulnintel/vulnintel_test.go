package vulnintel

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

func events(t *testing.T, s string) []*pyjson.Object {
	t.Helper()
	v, err := pyjson.Decode([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	l, _ := v.([]pyjson.Value) // test data: a list
	var out []*pyjson.Object
	for _, e := range l {
		out = append(out, obj(e))
	}
	return out
}

// TestOSVRanges: the cases of tests/test_intel.py (osvmatch.in_range).
func TestOSVRanges(t *testing.T) {
	t.Parallel()
	ev := events(t, `[{"introduced": "0"}, {"fixed": "1.4.2"}, {"introduced": "2.0.0"}, {"fixed": "2.1.0"}]`)
	for v, want := range map[string]bool{"v1.0.0": true, "v1.4.1": true, "v1.4.2": false, "v1.9.0": false, "v2.0.0": true,
		"v2.0.9-rc.1": true, "v2.1.0": false, "v2.1.0-rc.1": true} {
		if got := inRange(v, ev); got != want {
			t.Errorf("inRange(%s) = %v", v, got)
		}
	}
	if inRange("1.5.0", events(t, `[{"introduced": "1.0.0"}, {"last_affected": "1.4.0"}]`)) {
		t.Error("last_affected")
	}
	comps := components(obj(mustDecode(t, `{"components": [{"purl": "pkg:golang/example.com/lib@v1.3.0"},
		{"purl": "pkg:maven/org.x/lib@1.0?type=jar"}, {"purl": "pkg:deb/debian/openssl@3.0"}, {"purl": "pkg:npm/%40s/p@1"}]}`)))
	want := []component{{"Go", "example.com/lib", "v1.3.0"}, {"Maven", "org.x:lib", "1.0"}, {"npm", "@s/p", "1"}}
	if len(comps) != len(want) {
		t.Fatalf("components = %v", comps)
	}
	for i := range want {
		if comps[i] != want[i] {
			t.Errorf("component %d = %v, want %v", i, comps[i], want[i])
		}
	}
}

func mustDecode(t *testing.T, s string) pyjson.Value {
	t.Helper()
	v, err := pyjson.Decode([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestKernelPackages(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, src string
		kernel    bool
	}{{"linux-image-7.0.0-31-generic", "", true}, {"linux-libc-dev", "linux", true}, {"bpftool", "linux-hwe-7.0", true},
		{"linux-firmware", "linux-firmware", false}, {"openssl", "openssl", false}} {
		if got := isKernelPkg(tc.name, tc.src); got != tc.kernel {
			t.Errorf("isKernelPkg(%s, %s) = %v", tc.name, tc.src, got)
		}
	}
	if !kernelRunningPkg("linux-image-7.0.0-31-generic", "7.0.0-31-generic") ||
		!kernelRunningPkg("linux-headers-7.0.0-31", "7.0.0-31-generic") ||
		kernelRunningPkg("linux-image-7.0.0-28-generic", "7.0.0-31-generic") || kernelRunningPkg("x", "") {
		t.Error("kernelRunningPkg")
	}
}

func TestFeedURLsAreTLSOnly(t *testing.T) {
	t.Parallel()
	for raw, ok := range map[string]bool{"https://feeds.example/kev.json": true, "http://127.0.0.1:8080/x": true,
		"http://localhost/x": true, "http://feeds.example/x": false, "ftp://127.0.0.1/x": false, "https:///x": false} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := checkURL(u) == nil; got != ok {
			t.Errorf("checkURL(%s) ok=%v", raw, got)
		}
	}
}

// feedServer serves one feed; mode decides the answer. It records every request.
type feedServer struct {
	mu    sync.Mutex
	mode  string
	calls []string
}

func (s *feedServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.calls = append(s.calls, r.Method+" inm="+r.Header.Get("If-None-Match"))
	mode := s.mode
	s.mu.Unlock()
	switch {
	case mode == "outage":
		w.WriteHeader(http.StatusServiceUnavailable)
	case r.Header.Get("If-None-Match") == `"v1"` && mode == "same":
		w.WriteHeader(http.StatusNotModified)
	case mode == "corrupt":
		w.Header().Set("ETag", `"v2"`)
		_, _ = w.Write([]byte("<html>maintenance</html>"))
	default:
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write([]byte(`{"catalogVersion": "1", "vulnerabilities": [{"cveID": "CVE-1", "dateAdded": "2026-01-01"}]}`))
	}
}

func (s *feedServer) set(mode string) { s.mu.Lock(); s.mode = mode; s.mu.Unlock() }

// TestConditionalGetKeepsTheLastGoodCopy: 200 with an ETag, then a conditional GET answered 304; a corrupt payload
// and an outage keep the last good copy in use (with a warning) and never replace it; only GET is sent.
func TestConditionalGetKeepsTheLastGoodCopy(t *testing.T) {
	t.Parallel()
	fs := &feedServer{}
	srv := httptest.NewServer(fs)
	defer srv.Close()
	f := newFetcher(srv.Client(), time.Now)
	path := filepath.Join(t.TempDir(), "known_exploited_vulnerabilities.json")
	spec := &fetchSpec{url: srv.URL + "/kev.json", path: path, maxBytes: 1 << 20}
	parse := func(p string) (*kevIndex, error) {
		data, err := readAll(p, spec.maxBytes)
		if err != nil {
			return nil, err
		}
		idx, err := parseKEV(data)
		return idx, err
	}
	for _, step := range []struct{ mode, warn string }{{"", ""}, {"same", ""}, {"corrupt", "download rejected"}, {"outage", "HTTP 503"}} {
		fs.set(step.mode)
		idx, got, err := fetchParse(context.Background(), f, spec, parse)
		if err != nil || !idx.has("CVE-1") {
			t.Fatalf("%s: %v, %v", step.mode, idx, err)
		}
		if (step.warn == "") != (got.warn == "") || !strings.Contains(got.warn, step.warn) {
			t.Errorf("%s: warning %q, want %q", step.mode, got.warn, step.warn)
		}
	}
	want := []string{"GET inm=", `GET inm="v1"`, `GET inm="v1"`, `GET inm="v1"`}
	if strings.Join(fs.calls, "|") != strings.Join(want, "|") {
		t.Errorf("requests %q, want %q", fs.calls, want)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("cached copy: %v %v", fi, err)
	}
}

func TestSizeLimitsRejectDownloadsAndBombs(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("x"), 4096))
	}))
	defer srv.Close()
	spec := &fetchSpec{url: srv.URL, path: filepath.Join(t.TempDir(), "f"), maxBytes: 1024}
	_, _, err := fetchParse(context.Background(), newFetcher(srv.Client(), time.Now), spec,
		func(string) (int, error) { return 0, nil })
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("oversized download: %v", err)
	}
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	_, _ = zw.Write(make([]byte, 1<<20))
	_ = zw.Close()
	if _, err := gunzip(b.Bytes(), 1<<10); err == nil {
		t.Error("a gzip bomb was inflated past its limit")
	}
}

func TestVersionMatchesComponent(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "collectors", "vuln-intel", "VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(b)) != Version {
		t.Errorf("Version %s, VERSION file %s", Version, b)
	}
}

func TestRefusesWhatOnlyPythonServes(t *testing.T) {
	t.Parallel()
	for cfg, refused := range map[string]bool{`{"feeds": [{"type": "cisa-kev"}]}`: false,
		`{"feeds": [{"type": "vendor-advisories"}]}`: true, `{"code_repos": [{"owner": "o"}]}`: true, `{}`: false} {
		v, err := pyvalue.DecodeJSON([]byte(cfg))
		if err != nil {
			t.Fatal(err)
		}
		m, _ := v.(*pyvalue.Map) // test data: an object
		if err := refuse(m); (err != nil) != refused || (err != nil && !errors.Is(err, rundoc.ErrUsage)) {
			t.Errorf("refuse(%s) = %v", cfg, err)
		}
	}
}
