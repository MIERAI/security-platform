// Package yamlcfg reads the YAML files operators write (exceptions.yaml, catalog-review.yaml, the instance
// config) and the bundled SLI catalog into pyjson values, with YAML 1.2 core-schema semantics: block and flow
// style, anchors, aliases and merge keys; `yes`/`no` and unquoted dates stay strings. Mapping keys are their
// text (a finding id written without quotes is still that id). Alias expansion is bounded, so a small hostile
// file cannot expand into gigabytes.
//
// The parser is go.yaml.in/yaml/v3 (docs/go.md, "Dependencies"); this package only converts its node tree.
package yamlcfg

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
)

// MaxNodes bounds the number of values a document may expand into (aliases included).
const MaxNodes = 1_000_000

// maxDepth bounds nesting (aliases included).
const maxDepth = 200

// Errors of Parse.
var (
	ErrMultipleDocuments = errors.New("yaml: expected a single document")
	ErrTooLarge          = errors.New("yaml: document expands into too many values")
	ErrUnsupportedKey    = errors.New("yaml: mapping keys must be scalars")
)

// Parse reads one YAML document. An empty document is nil.
func Parse(data []byte) (pyjson.Value, error) {
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, nil
		}
		return nil, fmt.Errorf("yaml: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, ErrMultipleDocuments
	}
	c := &converter{}
	return c.value(&doc, 0)
}

type converter struct {
	nodes int
}

func (c *converter) value(n *yaml.Node, depth int) (pyjson.Value, error) {
	c.nodes++
	if c.nodes > MaxNodes || depth > maxDepth {
		return nil, ErrTooLarge
	}
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) == 0 {
			return nil, nil
		}
		return c.value(n.Content[0], depth+1)
	case yaml.AliasNode:
		return c.value(n.Alias, depth+1)
	case yaml.SequenceNode:
		return c.sequence(n, depth)
	case yaml.MappingNode:
		return c.mapping(n, depth)
	case yaml.ScalarNode:
		return scalar(n)
	default:
		return nil, fmt.Errorf("yaml: unexpected node kind %d at line %d", n.Kind, n.Line)
	}
}

func (c *converter) sequence(n *yaml.Node, depth int) (pyjson.Value, error) {
	out := make([]pyjson.Value, 0, len(n.Content))
	for _, item := range n.Content {
		v, err := c.value(item, depth+1)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// mapping builds an object; merge keys (`<<: *base`) contribute the keys the mapping does not set itself,
// first, as PyYAML orders them.
func (c *converter) mapping(n *yaml.Node, depth int) (pyjson.Value, error) {
	out := pyjson.NewObject()
	if err := c.merges(n, out, depth); err != nil {
		return nil, err
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if isMerge(k) {
			continue
		}
		key, err := keyText(k)
		if err != nil {
			return nil, err
		}
		val, err := c.value(v, depth+1)
		if err != nil {
			return nil, err
		}
		out.Set(key, val)
	}
	return out, nil
}

func (c *converter) merges(n *yaml.Node, out *pyjson.Object, depth int) error {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if !isMerge(n.Content[i]) {
			continue
		}
		v, err := c.value(n.Content[i+1], depth+1)
		if err != nil {
			return err
		}
		if err := mergeInto(out, v); err != nil {
			return fmt.Errorf("yaml: line %d: %w", n.Content[i].Line, err)
		}
	}
	return nil
}

// mergeInto applies one merge value: a mapping, or a list of mappings where earlier ones win.
func mergeInto(out *pyjson.Object, v pyjson.Value) error {
	switch t := v.(type) {
	case *pyjson.Object:
		for _, k := range t.Keys() {
			if !out.Has(k) {
				x, _ := t.Get(k)
				out.Set(k, x)
			}
		}
		return nil
	case []pyjson.Value:
		for _, item := range t {
			m, ok := item.(*pyjson.Object)
			if !ok {
				return errors.New("a merge list holds only mappings")
			}
			if err := mergeInto(out, m); err != nil {
				return err
			}
		}
		return nil
	default:
		return errors.New("a merge key needs a mapping or a list of mappings")
	}
}

func isMerge(k *yaml.Node) bool {
	return k.Kind == yaml.ScalarNode && k.ShortTag() == "!!merge"
}

func keyText(k *yaml.Node) (string, error) {
	if k.Kind == yaml.AliasNode && k.Alias != nil {
		k = k.Alias
	}
	if k.Kind != yaml.ScalarNode {
		return "", fmt.Errorf("line %d: %w", k.Line, ErrUnsupportedKey)
	}
	return k.Value, nil
}

// scalar resolves a scalar with the YAML 1.2 core schema; timestamps and unknown tags stay text.
func scalar(n *yaml.Node) (pyjson.Value, error) {
	switch n.ShortTag() {
	case "!!null":
		return nil, nil
	case "!!bool":
		var b bool
		if err := n.Decode(&b); err != nil {
			return nil, fmt.Errorf("yaml: line %d: %w", n.Line, err)
		}
		return b, nil
	case "!!int":
		var i int64
		if err := n.Decode(&i); err == nil {
			return i, nil
		}
		return n.Value, nil // beyond 64 bits: kept as text
	case "!!float":
		var f float64
		if err := n.Decode(&f); err != nil {
			return nil, fmt.Errorf("yaml: line %d: %w", n.Line, err)
		}
		return f, nil
	default:
		return n.Value, nil
	}
}
