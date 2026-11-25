package k8s

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

// count is one key of a PolicyReport summary, in document order (the reference adds them up per key in the order
// it meets them, and emits its metrics in that order).
type count struct {
	key   string
	value float64
	isInt bool
}

// orderedCounts is a JSON object of numbers that keeps its key order.
type orderedCounts []count

// UnmarshalJSON reads an object of numbers (null: empty).
func (o *orderedCounts) UnmarshalJSON(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("summary: %w", err)
	}
	if tok == nil {
		*o = nil
		return nil
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return errors.New("summary: not an object")
	}
	var out orderedCounts
	for dec.More() {
		c, err := nextCount(dec)
		if err != nil {
			return err
		}
		out = out.set(c)
	}
	*o = out
	return nil
}

func nextCount(dec *json.Decoder) (count, error) {
	kt, err := dec.Token()
	if err != nil {
		return count{}, fmt.Errorf("summary: %w", err)
	}
	key, _ := kt.(string) // object keys are always strings
	vt, err := dec.Token()
	if err != nil {
		return count{}, fmt.Errorf("summary: %w", err)
	}
	n, ok := vt.(json.Number)
	if !ok {
		return count{}, fmt.Errorf("summary: %q is not a number", key)
	}
	if i, perr := strconv.ParseInt(n.String(), 10, 64); perr == nil {
		return count{key: key, value: float64(i), isInt: true}, nil
	}
	f, err := n.Float64()
	if err != nil {
		return count{}, fmt.Errorf("summary: %q: %w", key, err)
	}
	return count{key: key, value: f}, nil
}

// set adds c, or replaces the value of an earlier equal key in place (the last duplicate wins, as in Python).
func (o orderedCounts) set(c count) orderedCounts {
	for i := range o {
		if o[i].key == c.key {
			o[i] = c
			return o
		}
	}
	return append(o, c)
}
