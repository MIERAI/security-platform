package pyvalue

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

// maxNodes bounds the number of values a YAML document may expand to (aliases are copied), so that a small
// file cannot make the reader allocate without limit ("billion laughs").
const maxNodes = 1 << 20

// DecodeYAML decodes one YAML document the way the contract reads YAML (SPEC §6): plain scalars are typed by
// the YAML 1.1 rules (yes/no/on/off are booleans, 0777 is octal, 1:30 is sexagesimal, 2030-01-31 is a date, a
// float needs a dot), quoted scalars are text, mappings keep their order, `<<` merges. An empty document is nil.
// Explicit tags other than the standard scalar, sequence and mapping tags are errors.
func DecodeYAML(data []byte) (any, error) {
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("%w: not UTF-8", ErrDocument)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var root yaml.Node
	if err := dec.Decode(&root); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, nil
		}
		return nil, fmt.Errorf("%w: %w", ErrDocument, err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: expected a single document", ErrDocument)
	}
	b := builder{budget: maxNodes}
	return b.node(&root, 0)
}

type builder struct{ budget int }

func (b *builder) node(n *yaml.Node, depth int) (any, error) {
	b.budget--
	if b.budget < 0 || depth > maxDepth {
		return nil, fmt.Errorf("%w: document too large or nested too deeply", ErrDocument)
	}
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) == 0 {
			return nil, nil
		}
		return b.node(n.Content[0], depth+1)
	case yaml.AliasNode:
		return b.node(n.Alias, depth+1)
	case yaml.SequenceNode:
		return b.sequence(n, depth)
	case yaml.MappingNode:
		return b.mapping(n, depth)
	case yaml.ScalarNode:
		return scalar(n)
	}
	return nil, fmt.Errorf("%w: unexpected node kind %d", ErrDocument, n.Kind)
}

func (b *builder) sequence(n *yaml.Node, depth int) (any, error) {
	if err := checkTag(n, "!!seq"); err != nil {
		return nil, err
	}
	out := make([]any, 0, len(n.Content))
	for _, c := range n.Content {
		v, err := b.node(c, depth+1)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// mapping builds a mapping; `<<: *anchor` (or a sequence of anchors) merges, its keys first and the mapping's
// own keys over them.
func (b *builder) mapping(n *yaml.Node, depth int) (any, error) {
	if err := checkTag(n, "!!map"); err != nil {
		return nil, err
	}
	merged, own := NewMap(), NewMap()
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if isMergeKey(k) {
			if err := b.merge(merged, v, depth); err != nil {
				return nil, err
			}
			continue
		}
		if err := b.pair(own, k, v, depth); err != nil {
			return nil, err
		}
	}
	merged.Update(own)
	return merged, nil
}

func (b *builder) pair(m *Map, k, v *yaml.Node, depth int) error {
	key, err := b.node(k, depth+1)
	if err != nil {
		return err
	}
	if hashable(key) != nil {
		return fmt.Errorf("%w: found unhashable key", ErrDocument)
	}
	val, err := b.node(v, depth+1)
	if err != nil {
		return err
	}
	m.Set(Str(key), val)
	return nil
}

func isMergeKey(k *yaml.Node) bool {
	return k.Kind == yaml.ScalarNode && k.Tag == "!!merge" && k.Value == "<<"
}

func (b *builder) merge(dst *Map, v *yaml.Node, depth int) error {
	val, err := b.node(v, depth+1)
	if err != nil {
		return err
	}
	sources := []any{val}
	if l, ok := val.([]any); ok {
		sources = l
	}
	// earlier sources win over later ones: apply them last
	for i := len(sources) - 1; i >= 0; i-- {
		m, ok := sources[i].(*Map)
		if !ok {
			return fmt.Errorf("%w: a merge key needs mappings", ErrDocument)
		}
		dst.Update(m)
	}
	return nil
}

func checkTag(n *yaml.Node, want string) error {
	if n.Style&yaml.TaggedStyle != 0 && n.Tag != want {
		return fmt.Errorf("%w: unsupported tag %s", ErrDocument, n.Tag)
	}
	return nil
}
