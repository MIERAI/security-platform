package findings

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
)

func TestBundledSchemaIsTheContractCopy(t *testing.T) {
	t.Parallel()
	want, err := os.ReadFile(filepath.Join("..", "..", "..", "schema", "findings-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, schemaJSON) {
		t.Fatal("internal/ledger/findings/findings-v1.schema.json differs from schema/findings-v1.schema.json: copy it")
	}
}

func newValidator(t *testing.T) *Validator {
	t.Helper()
	v, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// The expected errors are core/validate.py's output for the same documents.
// badDocument breaks most rules of the schema at once.
func badDocument() string {
	return `{"schema_version": 1, "collector": {"name": "X", "version": "1"}, "run": {},
	 "coverage": [{"asset": "a", "status": "bad", "checks": ["A"]}],
	 "findings": [{"id": "zz", "title": "` + strings.Repeat("t", 301) + `", "severity": 5, "needs_human": "no"}],
	 "metrics": [{"name": "security_x", "value": true}]}`
}

func TestValidateLikeTheReference(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, doc string
		file      string
		want      []string
	}{
		{name: "minimal", file: "minimal.json", want: nil},
		{name: "narrow gap", file: "host-with-narrow-gap.json", want: nil},
		{name: "complete scope", file: "inventory-complete-scope.json", want: nil},
		{name: "unknown major", file: "invalid-unknown-major.json",
			want: []string{"unsupported schema_version '2.0' (core accepts ['1'])"}},
		{name: "fields", file: "invalid-fields.json", want: []string{"$.findings[0]: missing needs_human",
			"$.findings[0].severity: 'urgent' not in ['critical', 'high', 'medium', 'low', 'info']"}},
		{name: "many", doc: badDocument(), want: []string{"$.schema_version: expected string", "$.collector.name: 'X' !~ ^[a-z0-9-]+$",
			`$.collector.version: '1' !~ ^[0-9]+\.[0-9]+\.[0-9]+$`, "$.run: missing started_at", "$.run: missing finished_at",
			"$.coverage[0].status: 'bad' not in ['ok', 'gap']", "$.coverage[0].checks[0]: 'A' !~ ^[a-z0-9_.*-]+$",
			"$.findings[0]: missing check", "$.findings[0]: missing layer", "$.findings[0]: missing asset",
			"$.findings[0]: missing evidence", "$.findings[0]: missing remediation", "$.findings[0]: missing owner",
			"$.findings[0]: missing observed_at", "$.findings[0].id: 'zz' !~ ^[0-9a-f]{12}$",
			"$.findings[0].title: longer than 300", "$.findings[0].severity: 5 not in ['critical', 'high', 'medium', 'low', 'info']",
			"$.findings[0].needs_human: expected boolean", "$.metrics[0].value: expected number"}},
		{name: "not an object", doc: `[1]`, want: []string{"$: expected object"}},
		{name: "date-time format (stricter than the reference)",
			doc: `{"schema_version": "1.0", "collector": {"name": "x", "version": "1.0.0"},
			 "run": {"started_at": "yesterday", "finished_at": "2026-01-01T00:00:00Z"}, "coverage": [], "findings": []}`,
			want: []string{"$.run.started_at: 'yesterday' is not an RFC 3339 date-time"}},
		{name: "python $ before a final newline", doc: `{"schema_version": "1.0\n", "collector": {"name": "x", "version": "1.0.0"},
			 "run": {"started_at": "2026-01-01T00:00:00Z", "finished_at": "2026-01-01T00:00:00Z"}, "coverage": [], "findings": []}`},
	}
	v := newValidator(t)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			doc, err := pyjson.Decode(caseDocument(t, tc.doc, tc.file))
			if err != nil {
				t.Fatal(err)
			}
			if got := v.Validate(doc); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Validate:\n got  %q\n want %q", got, tc.want)
			}
		})
	}
}

func caseDocument(t *testing.T, doc, file string) []byte {
	t.Helper()
	if file == "" {
		return []byte(doc)
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "findings", "examples", file))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// FuzzValidate: any JSON input is validated without a panic; a document that passes has the fields the ledger
// relies on, with their types.
func FuzzValidate(f *testing.F) {
	for _, name := range []string{"minimal.json", "host-with-narrow-gap.json", "invalid-fields.json"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "findings", "examples", name))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	v, err := NewValidator()
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		doc, err := pyjson.Decode(data)
		if err != nil {
			return
		}
		if len(v.Validate(doc)) > 0 {
			return
		}
		o, _ := doc.(*pyjson.Object)
		if o == nil || o.Obj("collector") == nil || o.Obj("run") == nil || o.List("coverage") == nil || o.List("findings") == nil {
			t.Fatalf("valid document without required parts: %s", data)
		}
	})
}
