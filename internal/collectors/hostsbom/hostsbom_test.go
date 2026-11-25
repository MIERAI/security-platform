package hostsbom

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

func TestVersionMatchesTree(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "collectors", "host-sbom", "VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(b)); got != Version {
		t.Fatalf("collectors/host-sbom/VERSION %s, Version %s", got, Version)
	}
}

func TestParse(t *testing.T) {
	t.Parallel()
	kv, pkgs := parse("os.family = debian \n#x=1\n y=2\npkg\tdeb\tbash\t5.2\t\t\tamd64\npkg\tdeb\t\t1\npkg\tdeb\tshort\n" +
		"pkg\tdeb\tlib\t1.0\tsrc\t0.9\tarm64\textra\npkg x=1\n")
	if !reflect.DeepEqual(kv, map[string]string{"os.family": "debian", "pkg x": "1"}) {
		t.Errorf("kv %v", kv)
	}
	want := []pkg{{"deb", "bash", "5.2", "bash", "5.2", "amd64"}, {"deb", "lib", "1.0", "src", "0.9", "arm64"}}
	if !reflect.DeepEqual(pkgs, want) {
		t.Errorf("pkgs %+v", pkgs)
	}
}

func TestFirmware(t *testing.T) {
	t.Parallel()
	tests := []struct {
		kv   map[string]string
		want string
	}{
		{map[string]string{}, "null"},
		{map[string]string{"firmware.vendor": "v", "firmware.build_ts": "1700000000"}, `{"vendor": "v", "build_date": "2023-11-14"}`},
		{map[string]string{"firmware.build_ts": "x1"}, "null"},
		{map[string]string{"firmware.build_ts": "99999999999999"}, "null"},
		{map[string]string{"firmware.model": "m", "firmware.channel": ""}, `{"model": "m"}`},
	}
	for _, tt := range tests {
		got, err := pyjson.Marshal(rundoc.JSON(firmware(tt.kv)), pyjson.Compact())
		if err != nil || string(got) != tt.want {
			t.Errorf("firmware(%v) = %s, %v; want %s", tt.kv, got, err, tt.want)
		}
	}
}

func newRun(t *testing.T) *job {
	t.Helper()
	now := func() time.Time { return time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC) }
	return &job{Run: &rundoc.Run{Instance: pyvalue.NewMap(), Dir: t.TempDir(), Data: t.TempDir(),
		Doc: rundoc.New("host-sbom", Version, "", now)},
		env: &rundoc.Env{Stderr: &bytes.Buffer{}, Now: now, Getenv: func(string) string { return "" },
			Environ: []string{"PATH=" + t.TempDir()}}}
}

func host(t *testing.T, yaml string) *pyvalue.Map {
	t.Helper()
	v, err := pyvalue.DecodeYAML([]byte(yaml))
	m, ok := v.(*pyvalue.Map)
	if err != nil || !ok {
		t.Fatal(err)
	}
	return m
}

// TestFSSBOM: sbom_paths needs a local exec adapter, and a missing trivy is a narrow gap, not a failed run.
func TestFSSBOM(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	tests := []struct{ cfg, reason string }{
		{"{name: a, exec: {type: ssh, host: a}, sbom_paths: [" + dir + "]}", "needs a local exec adapter"},
		{"{name: a, exec: {type: local}, sbom_paths: [" + dir + "]}", "trivy is not installed"},
		{"{name: a, exec: {type: local}, sbom_paths: [" + dir + "/missing]}", ""},
		{"{name: a, exec: {type: local}}", ""},
	}
	for _, tt := range tests {
		r := newRun(t)
		if got := fsSBOM(context.Background(), r, host(t, tt.cfg), "a"); got != nil {
			t.Errorf("%s: fs_sbom %v", tt.cfg, got)
		}
		doc := docJSON(t, r.Doc, r.env.Clock()())
		cov, _ := doc["coverage"].([]any)
		if tt.reason == "" {
			if len(cov) != 0 {
				t.Errorf("%s: coverage %v", tt.cfg, cov)
			}
			continue
		}
		if len(cov) != 1 || !strings.Contains(pyvalue.Str(reasonOf(cov[0])), tt.reason) {
			t.Errorf("%s: coverage %v, want a gap with %q", tt.cfg, cov, tt.reason)
		}
	}
}

func reasonOf(c any) any {
	m, _ := c.(map[string]any)
	return m["reason"]
}

// FuzzParse: profile output of any shape (POSIX or PowerShell line ends) never yields a package without name or
// version, and every package keeps a source.
func FuzzParse(f *testing.F) {
	f.Add("os.family=windows\r\npkg\twindows-kb\tKB1\t2025-01-01\tSecurity Update\t\t\r\n")
	f.Add("pkg\tdeb\ta\t1\t\t\t\npkg\t\t\t\n=\n")
	f.Fuzz(func(t *testing.T, out string) {
		_, pkgs := parse(out)
		for _, p := range pkgs {
			if p.name == "" || p.version == "" || p.source == "" || p.sourceVersion == "" {
				t.Fatalf("package %+v", p)
			}
		}
	})
}

// FuzzMergeSBOM: CycloneDX documents of any shape merge without a panic and the result is written as JSON.
func FuzzMergeSBOM(f *testing.F) {
	f.Add(`{"bomFormat": "CycloneDX", "components": [{"name": "a"}]}`, `{"components": [{"name": "b"}]}`)
	f.Add(`{"components": 1}`, `{"components": null}`)
	f.Fuzz(func(t *testing.T, a, b string) {
		var merged *pyvalue.Map
		for _, s := range []string{a, b} {
			v, err := pyvalue.DecodeJSON([]byte(s))
			m, ok := v.(*pyvalue.Map)
			if err != nil || !ok {
				return
			}
			merged = mergeComponents(merged, m)
		}
		if _, err := pyjson.Marshal(rundoc.JSON(merged), pyjson.Compact()); err != nil {
			t.Fatal(err)
		}
	})
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
