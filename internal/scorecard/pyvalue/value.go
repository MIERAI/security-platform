// Package pyvalue is the document model of the scorecard: the values a YAML or JSON input decodes to, with the
// semantics the reference implementation gives them (contracts/scorecard/SPEC.md §6, "Values"). Inputs are
// typed only loosely by their schemas (a control's `source` is free-form evaluator parameters, an override may
// patch any key), so the Go implementation keeps them as values and interprets them the way the contract says:
// truthiness, equality, membership, conversion to text and numbers.
//
// A value is one of: nil (null), bool, int64, float64, string, []any (sequence), *Map (mapping, insertion
// order kept), Date or DateTime (YAML timestamps).
package pyvalue

import "fmt"

// Map is a mapping that keeps the insertion order of its keys. Setting an existing key keeps its position and
// replaces its value (the last duplicate key of a document wins, at the position of the first).
type Map struct {
	keys []string
	vals map[string]any
}

// NewMap returns an empty mapping.
func NewMap() *Map { return &Map{vals: map[string]any{}} }

// Get returns the value at key and whether the key is present.
func (m *Map) Get(key string) (any, bool) {
	if m == nil {
		return nil, false
	}
	v, ok := m.vals[key]
	return v, ok
}

// GetOr returns the value at key, or def when the key is absent (a present null is returned as nil).
func (m *Map) GetOr(key string, def any) any {
	if v, ok := m.Get(key); ok {
		return v
	}
	return def
}

// Value returns the value at key, nil when absent.
func (m *Map) Value(key string) any {
	v, _ := m.Get(key)
	return v
}

// Has reports whether key is present.
func (m *Map) Has(key string) bool {
	_, ok := m.Get(key)
	return ok
}

// Set sets key to v.
func (m *Map) Set(key string, v any) {
	if _, ok := m.vals[key]; !ok {
		m.keys = append(m.keys, key)
	}
	m.vals[key] = v
}

// SetDefault sets key to v when it is absent and returns the value at key.
func (m *Map) SetDefault(key string, v any) any {
	if old, ok := m.Get(key); ok {
		return old
	}
	m.Set(key, v)
	return v
}

// Keys returns the keys in insertion order (a copy).
func (m *Map) Keys() []string {
	if m == nil {
		return nil
	}
	return append([]string(nil), m.keys...)
}

// Len is the number of keys.
func (m *Map) Len() int {
	if m == nil {
		return 0
	}
	return len(m.keys)
}

// Update sets every key of other, in other's order (Python dict.update).
func (m *Map) Update(other *Map) {
	for _, k := range other.Keys() {
		m.Set(k, other.vals[k])
	}
}

// Copy returns a shallow copy.
func (m *Map) Copy() *Map {
	c := NewMap()
	c.Update(m)
	return c
}

// Date is a YAML date (2030-01-31) as the reference implementation reads it.
type Date struct{ Year, Month, Day int }

// String is the date as text (YYYY-MM-DD).
func (d Date) String() string { return fmt.Sprintf("%04d-%02d-%02d", d.Year, d.Month, d.Day) }

// DateTime is a YAML timestamp with a time of day. Text is its text form: "YYYY-MM-DD HH:MM:SS[.ffffff][+HH:MM]"
// (a space, not a T, between date and time).
type DateTime struct{ Text string }

// String is the timestamp's text form.
func (d DateTime) String() string { return d.Text }
