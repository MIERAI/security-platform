// Package config reads the instance configuration (YAML or JSON) and the runner block of it
// (contracts/runner/runner-config-v1.schema.json).
//
// YAML is resolved the way the reference implementation's PyYAML (YAML 1.1, safe_load) resolves it, so the same
// file means the same thing to both runners: unquoted yes/no/on/off are booleans, 0755 is octal, 1:30 is 90, ~ is
// null. Mappings keep their key order (jobs run in the order they are written). Timestamps stay strings.
package config

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
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

// maxDepth bounds nesting (and alias expansion) so a hostile document cannot exhaust the stack.
const maxDepth = 64

// maxNodes bounds the number of values produced, so alias expansion ("billion laughs") stays small.
const maxNodes = 200000

// PyYAML's implicit resolvers (yaml/resolver.py), YAML 1.1. Compiled once, never written.
var (
	reBool  = regexp.MustCompile(`^(?:yes|Yes|YES|no|No|NO|true|True|TRUE|false|False|FALSE|on|On|ON|off|Off|OFF)$`)
	reFloat = regexp.MustCompile(`^(?:[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?|\.[0-9][0-9_]*(?:[eE][-+][0-9]+)?` +
		`|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$`)
	reInt = regexp.MustCompile(`^(?:[-+]?0b[0-1_]+|[-+]?0[0-7_]+|[-+]?(?:0|[1-9][0-9_]*)|[-+]?0x[0-9a-fA-F_]+` +
		`|[-+]?[1-9][0-9_]*(?::[0-5]?[0-9])+)$`)
	reNull = regexp.MustCompile(`^(?:~|null|Null|NULL|)$`)
)

// Parse decodes one YAML (or JSON) document into nil, bool, int64, float64, string, []any and *Map.
func Parse(data []byte) (any, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrYAML, err)
	}
	if doc.Kind == 0 || len(doc.Content) == 0 {
		return nil, nil // an empty document is null, as safe_load returns None
	}
	budget := maxNodes
	return convert(doc.Content[0], 0, &budget)
}

func convert(n *yaml.Node, depth int, budget *int) (any, error) {
	*budget--
	if depth > maxDepth || *budget < 0 {
		return nil, fmt.Errorf("%w: nested too deeply or too large", ErrYAML)
	}
	switch n.Kind {
	case yaml.AliasNode:
		return convert(n.Alias, depth+1, budget)
	case yaml.MappingNode:
		return convertMap(n, depth, budget)
	case yaml.SequenceNode:
		out := make([]any, 0, len(n.Content))
		for _, c := range n.Content {
			v, err := convert(c, depth+1, budget)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case yaml.ScalarNode:
		return scalar(n), nil
	case yaml.DocumentNode:
		if len(n.Content) == 0 {
			return nil, nil
		}
		return convert(n.Content[0], depth+1, budget)
	default:
		return nil, fmt.Errorf("%w: unexpected node at line %d", ErrYAML, n.Line)
	}
}

func convertMap(n *yaml.Node, depth int, budget *int) (*Map, error) {
	m := &Map{Vals: map[string]any{}}
	var merges []*Map
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, vn := n.Content[i], n.Content[i+1]
		v, err := convert(vn, depth+1, budget)
		if err != nil {
			return nil, err
		}
		if k.Kind == yaml.ScalarNode && k.Tag == "!!merge" {
			merges = append(merges, mergeSources(v)...)
			continue
		}
		key, err := convert(k, depth+1, budget)
		if err != nil {
			return nil, err
		}
		m.set(keyString(key), v, true)
	}
	for _, src := range merges { // explicit keys win over merged ones; earlier merges win over later ones
		for _, k := range src.Keys {
			m.set(k, src.Vals[k], false)
		}
	}
	return m, nil
}

// set adds a key (at the end, when new); an existing key is replaced only with overwrite.
func (m *Map) set(k string, v any, overwrite bool) {
	if !m.Has(k) {
		m.Keys = append(m.Keys, k)
	} else if !overwrite {
		return
	}
	m.Vals[k] = v
}

func mergeSources(v any) []*Map {
	switch x := v.(type) {
	case *Map:
		return []*Map{x}
	case []any:
		var out []*Map
		for _, e := range x {
			if m, ok := e.(*Map); ok {
				out = append(out, m)
			}
		}
		return out
	default:
		return nil
	}
}

// keyString is the key as the runner looks it up: non-string keys are written as Python's str() would.
func keyString(k any) string {
	switch x := k.(type) {
	case string:
		return x
	case nil:
		return "None"
	case bool:
		if x {
			return "True"
		}
		return "False"
	default:
		return fmt.Sprint(x)
	}
}

func scalar(n *yaml.Node) any {
	if n.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle|yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
		return n.Value
	}
	if n.Style&yaml.TaggedStyle != 0 {
		switch n.Tag {
		case "!!null", "!!bool", "!!int", "!!float":
			return Resolve(n.Value)
		default:
			return n.Value // !!str, or a tag safe_load would refuse: the text is the safest reading
		}
	}
	return Resolve(n.Value)
}

// Resolve applies PyYAML's implicit resolvers to a plain (unquoted) scalar.
func Resolve(s string) any {
	switch {
	case reNull.MatchString(s):
		return nil
	case reBool.MatchString(s):
		c := strings.ToLower(s)
		return c == "yes" || c == "true" || c == "on"
	case reInt.MatchString(s):
		if v, ok := parseInt11(s); ok {
			return v
		}
	case reFloat.MatchString(s):
		if v, ok := parseFloat11(s); ok {
			return v
		}
	}
	return s
}

func splitSign(s string) (int64, string) {
	switch {
	case strings.HasPrefix(s, "-"):
		return -1, s[1:]
	case strings.HasPrefix(s, "+"):
		return 1, s[1:]
	}
	return 1, s
}

// parseInt11 is PyYAML's construct_yaml_int. Values beyond int64 stay strings (Python would keep a big int).
func parseInt11(s string) (int64, bool) {
	sign, v := splitSign(strings.ReplaceAll(s, "_", ""))
	var n int64
	var err error
	switch {
	case v == "0":
		return 0, true
	case strings.HasPrefix(v, "0b"):
		n, err = strconv.ParseInt(v[2:], 2, 64)
	case strings.HasPrefix(v, "0x"):
		n, err = strconv.ParseInt(v[2:], 16, 64)
	case strings.HasPrefix(v, "0"):
		n, err = strconv.ParseInt(v[1:], 8, 64)
	case strings.Contains(v, ":"):
		n, err = sexagesimal(v)
	default:
		n, err = strconv.ParseInt(v, 10, 64)
	}
	if err != nil || v == "" {
		return 0, false
	}
	return sign * n, true
}

func sexagesimal(v string) (int64, error) {
	var n int64
	for _, part := range strings.Split(v, ":") {
		d, err := strconv.ParseInt(part, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("sexagesimal %q: %w", v, err)
		}
		if n > math.MaxInt64/60 {
			return 0, fmt.Errorf("sexagesimal %q: %w", v, strconv.ErrRange)
		}
		n = n*60 + d
	}
	return n, nil
}

// parseFloat11 is PyYAML's construct_yaml_float.
func parseFloat11(s string) (float64, bool) {
	sign, v := splitSign(strings.ToLower(strings.ReplaceAll(s, "_", "")))
	fs := float64(sign)
	switch {
	case v == ".inf":
		return fs * math.Inf(1), true
	case v == ".nan":
		return math.NaN(), true
	case strings.Contains(v, ":"):
		parts := strings.Split(v, ":")
		total := 0.0
		for _, p := range parts {
			d, err := strconv.ParseFloat(p, 64)
			if err != nil {
				return 0, false
			}
			total = total*60 + d
		}
		return fs * total, true
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0, false
	}
	return fs * f, true
}
