// Package yamlcfg reads the YAML files of the ledger (exceptions.yaml, catalog-review.yaml, the instance config,
// the bundled SLI catalog) the way the reference reads them, through the shared pyvalue.DecodeYAML (PyYAML's
// YAML 1.1 typing, merge keys, bounded aliases), and converts the result to pyjson values: the ledger's document
// model. A YAML date or timestamp becomes its Python str() text ("2027-01-31", "2027-01-31 10:00:00+00:00"):
// the ledger only ever uses them as str(value), and records exceptions that way.
package yamlcfg

import (
	"fmt"

	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// Parse reads one YAML document. An empty document is nil.
func Parse(data []byte) (pyjson.Value, error) {
	v, err := pyvalue.DecodeYAML(data)
	if err != nil {
		return nil, fmt.Errorf("yaml: %w", err)
	}
	return convert(v), nil
}

func convert(v any) pyjson.Value {
	switch t := v.(type) {
	case *pyvalue.Map:
		o := pyjson.NewObject()
		for _, k := range t.Keys() {
			o.Set(k, convert(t.Value(k)))
		}
		return o
	case []any:
		out := make([]pyjson.Value, len(t))
		for i, x := range t {
			out[i] = convert(x)
		}
		return out
	case pyvalue.Date, pyvalue.DateTime:
		return pyvalue.Str(t)
	default:
		return t // nil, bool, int64, float64, string
	}
}
