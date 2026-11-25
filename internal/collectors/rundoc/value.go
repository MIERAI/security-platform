package rundoc

import (
	"encoding/json"

	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// Kinds of finding (findings/1.2); Finding.Kind "" is compliance.
const (
	KindCompliance = "compliance"
	KindDetection  = "detection"
)

// Get is d.get(key) on a mapping; nil when v is not a mapping or the key is absent.
func Get(v any, key string) any {
	if m, ok := v.(*pyvalue.Map); ok {
		return m.Value(key)
	}
	return nil
}

// MapOr returns v as a mapping, or a new empty one (`x.get(k) or {}`, when the result is written to).
func MapOr(v any) *pyvalue.Map {
	if m, ok := v.(*pyvalue.Map); ok && m != nil {
		return m
	}
	return pyvalue.NewMap()
}

// Text returns v when it is text, "" for anything else (a value read where only text counts; Str is Python's
// str() of any value).
func Text(v any) string {
	s, _ := v.(string) // not text: ""
	return s
}

// StrOr returns v when it is non-empty text, def otherwise (`x.get(k) or def` for text).
func StrOr(v any, def string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return def
}

// Texts returns the text elements of a sequence; other elements are skipped.
func Texts(v any) []string {
	var out []string
	for _, e := range List(v) {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// Loose turns a value read with pyvalue (a configuration, an API answer) into plain Go JSON values: mappings
// become map[string]any, dates their text (Python's json.dumps(default=str)); JSON turns the result into a value the
// document writer accepts.
func Loose(v any) any {
	switch x := v.(type) {
	case *pyvalue.Map:
		if x == nil {
			return nil
		}
		m := make(map[string]any, x.Len())
		for _, k := range x.Keys() {
			m[k] = Loose(x.Value(k))
		}
		return m
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = Loose(e)
		}
		return out
	case pyvalue.Date:
		return x.String()
	case pyvalue.DateTime:
		return x.String()
	default:
		return v
	}
}

// JSON turns a value a collector builds for its evidence (Go maps, slices, scalars, pyvalue documents) into a JSON
// value the document writer accepts. Go maps get their keys sorted (the evidence is written with sort_keys anyway).
func JSON(v any) pyjson.Value {
	switch x := v.(type) {
	case map[string]any:
		o := pyjson.NewObject()
		for _, k := range sortedKeys(x) {
			o.Set(k, JSON(x[k]))
		}
		return o
	case map[string]string:
		o := pyjson.NewObject()
		for _, k := range sortedKeys(x) {
			o.Set(k, x[k])
		}
		return o
	case []any:
		out := make([]pyjson.Value, len(x))
		for i, e := range x {
			out[i] = JSON(e)
		}
		return out
	case []string:
		out := make([]pyjson.Value, len(x))
		for i, e := range x {
			out[i] = e
		}
		return out
	default:
		return otherJSON(v)
	}
}

// otherJSON is JSON for the remaining shapes: string lists per key, numbers read with encoding/json (written as
// their text, exactly), and documents read with pyvalue.
func otherJSON(v any) pyjson.Value {
	switch x := v.(type) {
	case map[string][]string:
		o := pyjson.NewObject()
		for _, k := range sortedKeys(x) {
			o.Set(k, JSON(x[k]))
		}
		return o
	case json.Number:
		return pyjson.BigInt(x.String())
	default:
		return documentJSON(v)
	}
}

// documentJSON is JSON for the values read with pyvalue: mappings keep their key order, dates become text.
func documentJSON(v any) pyjson.Value {
	switch x := v.(type) {
	case *pyvalue.Map:
		if x == nil {
			return nil
		}
		o := pyjson.NewObject()
		for _, k := range x.Keys() {
			o.Set(k, JSON(x.Value(k)))
		}
		return o
	case pyvalue.Date, pyvalue.DateTime:
		return Loose(x)
	default:
		return v
	}
}

// Attributes is a finding's attributes from a Go map (nil for an empty one).
func Attributes(m map[string]any) *pyjson.Object {
	if len(m) == 0 {
		return nil
	}
	o, _ := JSON(m).(*pyjson.Object) // a map[string]any is always an object
	return o
}

// Labels are metric labels from name/value pairs.
func Labels(pairs ...[2]string) map[string]string {
	m := make(map[string]string, len(pairs))
	for _, kv := range pairs {
		m[kv[0]] = kv[1]
	}
	return m
}

// FloatRepr is Python's repr(float).
func FloatRepr(v float64) string { return pyjson.FloatRepr(v) }

// Home is the user's home directory for "~" in configured paths: HOME, else USERPROFILE.
func (e *Env) Home() string {
	if h := e.Getenv("HOME"); h != "" {
		return h
	}
	return e.Getenv("USERPROFILE")
}
