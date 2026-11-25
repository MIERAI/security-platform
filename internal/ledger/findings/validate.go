// Package findings validates findings documents (contracts/findings, major 1) the way the reference core
// validator does (core/validate.py), with the same error texts, so that ledger.json records the same
// `runs[].invalid` lists. It also checks `format: date-time`, which the reference skips: the ledger computes
// with these timestamps and a document it cannot date is rejected instead of breaking the merge.
//
// The schema is a copy of schema/findings-v1.schema.json (a test keeps them identical).
package findings

import (
	_ "embed" // the bundled schema
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
)

//go:embed findings-v1.schema.json
var schemaJSON []byte // never written after initialisation (go:embed)

// dateTime is the RFC 3339 date-time of the conformance harness.
var dateTime = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})$`)

// Validator checks documents against the bundled schema.
type Validator struct {
	schema   *pyjson.Object
	patterns map[string]*regexp.Regexp
}

// NewValidator compiles the bundled schema.
func NewValidator() (*Validator, error) {
	v, err := pyjson.Decode(schemaJSON)
	if err != nil {
		return nil, fmt.Errorf("bundled findings schema: %w", err)
	}
	s, ok := v.(*pyjson.Object)
	if !ok {
		return nil, fmt.Errorf("bundled findings schema: not an object")
	}
	val := &Validator{schema: s, patterns: map[string]*regexp.Regexp{}}
	if err := val.compile(s); err != nil {
		return nil, err
	}
	return val, nil
}

// compile prepares every pattern of the schema. Python's `$` (no MULTILINE) also matches before a final
// newline; Go's does not, so a trailing `$` becomes `\n?\z`.
func (v *Validator) compile(s *pyjson.Object) error {
	if p, ok := s.Get("pattern"); ok {
		ps, _ := p.(string) // schema patterns are strings
		re, err := regexp.Compile(pythonPattern(ps))
		if err != nil {
			return fmt.Errorf("bundled findings schema: pattern %q: %w", ps, err)
		}
		v.patterns[ps] = re
	}
	for _, k := range s.Keys() {
		x, _ := s.Get(k)
		if sub, ok := x.(*pyjson.Object); ok {
			if err := v.compile(sub); err != nil {
				return err
			}
		}
	}
	return nil
}

func pythonPattern(p string) string {
	if strings.HasSuffix(p, "$") && !strings.HasSuffix(p, `\$`) {
		return p[:len(p)-1] + `\n?\z`
	}
	return p
}

// Validate returns the errors of doc (empty when valid), like core/validate.py validate_findings.
func (v *Validator) Validate(doc pyjson.Value) []string {
	o, ok := doc.(*pyjson.Object)
	if !ok {
		return []string{"$: expected object"}
	}
	sv, _ := o.Get("schema_version")
	if !o.Has("schema_version") {
		sv = ""
	}
	if major, _, _ := strings.Cut(pyjson.Str(sv), "."); major != "1" {
		return []string{fmt.Sprintf("unsupported schema_version %s (core accepts ['1'])", repr(o, "schema_version"))}
	}
	return v.errors(doc, v.schema, "$")
}

// repr is Python's repr(d.get(key)).
func repr(o *pyjson.Object, key string) string {
	x, _ := o.Get(key)
	return pyjson.Repr(x)
}

func (v *Validator) errors(doc pyjson.Value, schema *pyjson.Object, path string) []string {
	if t := schema.Str("type"); t != "" && !hasType(doc, t) {
		return []string{path + ": expected " + t}
	}
	var out []string
	if enum, ok := schema.Get("enum"); ok && !inEnum(doc, enum) {
		out = append(out, fmt.Sprintf("%s: %s not in %s", path, pyjson.Repr(doc), pyjson.Repr(enum)))
	}
	if s, ok := doc.(string); ok {
		out = append(out, v.stringErrors(s, schema, path)...)
	}
	switch t := doc.(type) {
	case *pyjson.Object:
		out = append(out, v.objectErrors(t, schema, path)...)
	case []pyjson.Value:
		if items := schema.Obj("items"); items != nil {
			for i, x := range t {
				out = append(out, v.errors(x, items, fmt.Sprintf("%s[%d]", path, i))...)
			}
		}
	}
	return out
}

func (v *Validator) stringErrors(s string, schema *pyjson.Object, path string) []string {
	var out []string
	if p := schema.Str("pattern"); p != "" && !v.patterns[p].MatchString(s) {
		out = append(out, fmt.Sprintf("%s: %s !~ %s", path, pyjson.Repr(s), p))
	}
	if m, ok := schema.Get("maxLength"); ok {
		if n, isInt := pyjson.Int(m); isInt && int64(utf8.RuneCountInString(s)) > n {
			out = append(out, fmt.Sprintf("%s: longer than %d", path, n))
		}
	}
	if schema.Str("format") == "date-time" && !dateTime.MatchString(s) {
		out = append(out, fmt.Sprintf("%s: %s is not an RFC 3339 date-time", path, pyjson.Repr(s)))
	}
	return out
}

func (v *Validator) objectErrors(o, schema *pyjson.Object, path string) []string {
	var out []string
	for _, r := range schema.List("required") {
		if name, _ := r.(string); !o.Has(name) {
			out = append(out, path+": missing "+name)
		}
	}
	props := schema.Obj("properties")
	extra := schema.Obj("additionalProperties")
	for _, k := range o.Keys() {
		x, _ := o.Get(k)
		switch {
		case props != nil && props.Has(k):
			out = append(out, v.errors(x, props.Obj(k), path+"."+k)...)
		case extra != nil:
			out = append(out, v.errors(x, extra, path+"."+k)...)
		}
	}
	return out
}

func hasType(doc pyjson.Value, t string) bool {
	switch t {
	case "object":
		_, ok := doc.(*pyjson.Object)
		return ok
	case "array":
		_, ok := doc.([]pyjson.Value)
		return ok
	case "string":
		_, ok := doc.(string)
		return ok
	case "boolean":
		_, ok := doc.(bool)
		return ok
	case "number":
		return pyjson.IsNumber(doc)
	case "integer":
		return pyjson.IsInteger(doc)
	default:
		return true
	}
}

// inEnum is Python's `doc in enum` for the string enums of the schema.
func inEnum(doc, enum pyjson.Value) bool {
	s, ok := doc.(string)
	return ok && pyjson.Contains(enum, s)
}
