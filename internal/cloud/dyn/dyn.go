// Package dyn reads loosely typed JSON (provider responses, engine outputs, the instance config) the way the
// Python implementation reads it with dict.get: a missing key, a JSON null or a value of another type than the
// one asked for gives the zero value instead of an error, and scalar values are turned into text as Python's str()
// does. Decode JSON for it with Decode (numbers stay json.Number, so "123456789012" and 123456789012 both read as
// the text 123456789012).
package dyn

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// Decode parses one JSON document (trailing white space allowed, nothing else) with numbers kept as json.Number.
func Decode(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("decode json: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("decode json: data after the document")
	}
	return v, nil
}

// Map returns v as an object, or an empty one.
func Map(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

// List returns v as an array, or nil.
func List(v any) []any {
	if l, ok := v.([]any); ok {
		return l
	}
	return nil
}

// Str is Python's str() of a JSON scalar ("" for null and for objects/arrays, which the callers never print).
func Str(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return x.String()
	case bool:
		if x {
			return "True"
		}
		return "False"
	case float64:
		return fmt.Sprint(x)
	case int:
		return fmt.Sprint(x)
	default:
		return ""
	}
}

// Truthy is Python's truth value of a JSON value.
func Truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case string:
		return x != ""
	case bool:
		return x
	case json.Number:
		f, err := x.Float64()
		return err != nil || f != 0
	case float64:
		return x != 0
	case int:
		return x != 0
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	default:
		return true
	}
}

// Text is `m.get(key) or ""` for a value that is text: the value as text when it is truthy.
func Text(m map[string]any, key string) string {
	if v := m[key]; Truthy(v) {
		return Str(v)
	}
	return ""
}

// Or returns the first non-empty string, or "".
func Or(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// Strings returns the elements of a list as text (non-scalar elements skipped).
func Strings(v any) []string {
	var out []string
	for _, e := range List(v) {
		switch e.(type) {
		case string, json.Number, bool:
			out = append(out, Str(e))
		}
	}
	return out
}

// Cut returns at most n characters (Unicode code points, as Python slices strings) of s.
func Cut(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(s) <= n {
		return s
	}
	i := 0
	for pos := range s {
		if i == n {
			return s[:pos]
		}
		i++
	}
	return s
}

// Lower is Python's str.lower() for the identifiers and labels the collector handles.
func Lower(s string) string {
	return strings.ToLower(s)
}

// ValidUTF8 replaces invalid UTF-8 like Python's decode(errors="replace").
func ValidUTF8(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	return strings.ToValidUTF8(s, "�")
}
