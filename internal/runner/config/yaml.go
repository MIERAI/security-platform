// Package config reads the instance configuration (YAML or JSON) and the runner block of it
// (contracts/runner/runner-config-v1.schema.json).
//
// YAML is read with the scorecard's reader (internal/scorecard/pyvalue): typed as the reference implementation's
// PyYAML (YAML 1.1, safe_load) types it, so the same file means the same thing to the Go and the Python runner:
// unquoted yes/no/on/off are booleans, 0755 is octal, 1:30 is 90, ~ is null, timestamps are text here. Mappings keep
// their key order (jobs run in the order they are written); nesting and alias expansion are bounded.
package config

import (
	"errors"
	"fmt"

	"github.com/MIERAI/security-platform/internal/scorecard/pyvalue"
)

// Map is a mapping that remembers its key order.
type Map struct {
	Keys []string
	Vals map[string]any
}

// Get returns the value of a key (nil when absent).
func (m *Map) Get(k string) any {
	if m == nil {
		return nil
	}
	return m.Vals[k]
}

// Has reports whether the key is present.
func (m *Map) Has(k string) bool {
	if m == nil {
		return false
	}
	_, ok := m.Vals[k]
	return ok
}

// Plain converts the map (recursively) to map[string]any, the form encoding/json writes.
func (m *Map) Plain() map[string]any {
	out := make(map[string]any, len(m.Keys))
	for _, k := range m.Keys {
		out[k] = Plain(m.Vals[k])
	}
	return out
}

// Plain converts a decoded value (recursively) to plain Go maps and slices.
func Plain(v any) any {
	switch x := v.(type) {
	case *Map:
		return x.Plain()
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = Plain(e)
		}
		return out
	default:
		return v
	}
}

// ErrYAML is the error class of documents that are not valid YAML for this purpose.
var ErrYAML = errors.New("invalid YAML")

// Parse decodes one YAML (or JSON) document into nil, bool, int64, float64, string, []any and *Map.
func Parse(data []byte) (any, error) {
	v, err := pyvalue.DecodeYAML(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrYAML, err)
	}
	return convert(v), nil
}

func convert(v any) any {
	switch x := v.(type) {
	case *pyvalue.Map:
		m := &Map{Keys: x.Keys(), Vals: make(map[string]any, x.Len())}
		for _, k := range m.Keys {
			m.Vals[k] = convert(x.Value(k))
		}
		return m
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = convert(e)
		}
		return out
	case pyvalue.Date, pyvalue.DateTime:
		return pyvalue.Str(x)
	default:
		return v
	}
}
