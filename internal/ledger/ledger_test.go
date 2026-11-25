package ledger

import (
	"bytes"
	"crypto/sha1" // #nosec G505 -- the contract's finding id rule, not a security use
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/MIERAI/security-platform/internal/ledger/instant"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
)

const day = 86400.0

// t0 is 2026-11-01T08:00:00Z.
const t0 = 1793520000.0

// fid is the contract's id of a finding of layer host.
func fid(asset, check string) string {
	h := sha1.Sum([]byte("host|" + asset + "|" + check)) // #nosec G401 -- the contract's id rule
	return hex.EncodeToString(h[:])[:12]
}

type finding struct {
	asset, check, severity string
	kind                   string // "" = absent (LEDGER-D1)
	attrs                  map[string]any
}

type coverage struct {
	asset, status string
	checks        []string
}

func iso(t float64) string {
	return instant.ISO(t)
}

// doc builds a findings document of collector col finished at t.
func doc(col string, t float64, cov []coverage, fs []finding) []byte {
	var covs []map[string]any
	for _, c := range cov {
		m := map[string]any{"asset": c.asset, "status": c.status}
		if c.checks != nil {
			m["checks"] = c.checks
		}
		covs = append(covs, m)
	}
	var finds []map[string]any
	for _, f := range fs {
		m := map[string]any{"id": fid(f.asset, f.check), "check": f.check, "layer": "host", "asset": f.asset,
			"title": f.check, "severity": f.severity, "evidence": "raw/x", "remediation": "fix it", "needs_human": false,
			"owner": "platform", "observed_at": iso(t)}
		if f.kind != "" {
			m["kind"] = f.kind
		}
		if f.attrs != nil {
			m["attributes"] = f.attrs
		}
		finds = append(finds, m)
	}
	if covs == nil {
		covs = []map[string]any{}
	}
	if finds == nil {
		finds = []map[string]any{}
	}
	b, err := json.Marshal(map[string]any{"schema_version": "1.2", "collector": map[string]any{"name": col, "version": "1.0.0"},
		"run": map[string]any{"started_at": iso(t), "finished_at": iso(t)}, "coverage": covs, "findings": finds})
	if err != nil {
		panic(err)
	}
	return b
}

// sandbox is a data directory with numbered runs.
type sandbox struct {
	t    *testing.T
	data string
	n    int
}

func newSandbox(t *testing.T) *sandbox {
	t.Helper()
	return &sandbox{t: t, data: filepath.Join(t.TempDir(), "data")}
}

func (s *sandbox) write(rel string, data []byte) {
	s.t.Helper()
	p := filepath.Join(s.data, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		s.t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o600); err != nil {
		s.t.Fatal(err)
	}
}

// merge runs one merge of the given documents (file name -> content) at time now.
func (s *sandbox) merge(now float64, opt Options, docs map[string][]byte) (*pyjson.Object, string) {
	s.t.Helper()
	s.n++
	run := filepath.Join(s.data, "runs", "r"+string(rune('a'+s.n)))
	for name, d := range docs {
		s.write(filepath.Join("runs", "r"+string(rune('a'+s.n)), name), d)
	}
	if err := os.MkdirAll(run, 0o700); err != nil {
		s.t.Fatal(err)
	}
	var stderr bytes.Buffer
	opt.Run, opt.Data, opt.Now, opt.Version, opt.Stderr = run, s.data, now, "0.0.0-test", &stderr
	if err := Merge(opt); err != nil {
		s.t.Fatalf("Merge: %v\n%s", err, stderr.String())
	}
	return s.ledger(), stderr.String()
}

func (s *sandbox) ledger() *pyjson.Object {
	s.t.Helper()
	data, err := os.ReadFile(filepath.Join(s.data, "ledger.json"))
	if err != nil {
		s.t.Fatal(err)
	}
	v, err := pyjson.Decode(data)
	if err != nil {
		s.t.Fatal(err)
	}
	o, _ := v.(*pyjson.Object)
	return o
}

func entry(l *pyjson.Object, id string) *pyjson.Object {
	return l.Obj("entries").Obj(id)
}
