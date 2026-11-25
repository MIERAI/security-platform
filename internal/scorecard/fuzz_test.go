package scorecard

import (
	"context"
	"io"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Every parser of external input has a fuzz test (docs/go.md): none may panic, whatever the bytes.

func FuzzTimestamp(f *testing.F) {
	for _, s := range []string{"2030-01-10", "2030-1-5T1:2:61Z", "2030-02-30", "x", "2030-01-10T", "é2030"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		v, err := timestamp(s)
		if err == nil && math.IsNaN(v) {
			t.Fatalf("timestamp(%q) = NaN", s)
		}
	})
}

func FuzzDuration(f *testing.F) {
	for _, s := range []string{"90d", " 1.5 w ", "1e3d", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if d, err := duration(s, 0); err == nil && d < 0 {
			t.Fatalf("duration(%q) = %v", s, d)
		}
	})
}

func FuzzGlob(f *testing.F) {
	for _, s := range []string{"beta.*", "[!a-c]x", "[z-a]", "[", "[]]", "a\\b", "**?"} {
		f.Add(s, "beta.x")
	}
	f.Fuzz(func(t *testing.T, pattern, id string) {
		re, err := globRegexp(pattern)
		if err != nil {
			t.Fatalf("glob %q does not compile: %v", pattern, err)
		}
		re.MatchString(id)
	})
}

func FuzzParseProm(f *testing.F) {
	for _, s := range []string{"m{a=\"1\"} 2\n", "# c\nm 1 17\n", "m{a=\"\\x4\"} 1", "m{a=\"\\777\\U0010ffff\"} nan"} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		parseProm(s)
	})
}

func FuzzParseArgs(f *testing.F) {
	f.Add("compute\x00--data\x00D\x00--now=-5")
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = ParseArgs(splitNUL(s))
	})
}

func splitNUL(s string) []string {
	var out []string
	start := 0
	for i := range len(s) {
		if s[i] == 0 {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// fuzzTree computes a scorecard from a fuzzed catalog file and a fuzzed attestations file.
func fuzzTree(t *testing.T, catalog, attestations []byte) {
	t.Helper()
	root := t.TempDir()
	product := filepath.Join(root, "product")
	data := filepath.Join(root, "data")
	for path, content := range map[string][]byte{
		filepath.Join(product, "scorecard", "VERSION"):              []byte("0.0.0\n"),
		filepath.Join(product, "scorecard", "catalog", "01-x.yaml"): catalog,
		filepath.Join(data, "attestations.yaml"):                    attestations,
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	env := Env{Stdout: io.Discard, Stderr: io.Discard, Product: product, Now: time.Now,
		GitLog: func(context.Context, string, string) string { return "" },
		Attest: func(context.Context, []string) int { return 0 }}
	Main(context.Background(), env, []string{"compute", "--data", data, "--now", testNow})
	Main(context.Background(), env, []string{"lint"})
	Main(context.Background(), env, []string{"list"})
}

const fuzzCatalog = `schema: security-platform/scorecard-catalog/v1
dimension: {id: d, order: 1, title: D, pillars: [device], applies_when: {any: [{instance: a.b}, {coverage_prefix: "c:"}]}}
controls:
  - {id: d.a, title: A, csf: PR.PS, check: attested, weight: 2.5, validity: 30d, question: "Q?"}
  - {id: d.b, title: B, csf: DE.CM, check: automated, weight: 1, source: {type: all, of: [{type: findings, max: 1}, {type: builtin, name: pillars_covered}]}}
`

const fuzzAttestations = `schema: security-platform/attestations/v1
attestations:
  d.a: {attested_by: someone, at: 2030-01-01, expires: '2030-01-20', value: no, note: x, not_applicable: y}
`

// FuzzCatalogFile: a catalog file of any content is either refused or scored, never a crash.
func FuzzCatalogFile(f *testing.F) {
	f.Add([]byte(fuzzCatalog))
	f.Add([]byte("schema: security-platform/scorecard-catalog/v1\ndimension: {id: x}\ncontrols: [{id: x.y, weight: .inf}]\n"))
	f.Fuzz(func(t *testing.T, catalog []byte) {
		fuzzTree(t, catalog, []byte(fuzzAttestations))
	})
}

// FuzzAttestationsFile: an attestations file of any content is either refused or used, never a crash.
func FuzzAttestationsFile(f *testing.F) {
	f.Add([]byte(fuzzAttestations))
	f.Add([]byte("attestations:\n  d.a: [1]\n  d.b: {attested_by: 1, at: 2030-01-01T10:00:00Z}\n"))
	f.Fuzz(func(t *testing.T, attestations []byte) {
		fuzzTree(t, []byte(fuzzCatalog), attestations)
	})
}
