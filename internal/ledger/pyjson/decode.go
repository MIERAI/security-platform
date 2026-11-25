package pyjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// MaxDepth bounds the nesting of a decoded document (Python's json module stops near its recursion limit, 1000).
const MaxDepth = 900

// ErrTooDeep is returned for a document nested deeper than MaxDepth.
var ErrTooDeep = errors.New("json: nested too deeply")

// ErrTrailingData is returned when something follows the document (Python: "Extra data").
var ErrTrailingData = errors.New("json: extra data after the document")

// Decode parses one JSON document. Objects keep their key order; a repeated key keeps its first position and
// its last value (as Python's json.load).
func Decode(data []byte) (Value, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := decodeValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, ErrTrailingData
	}
	return v, nil
}

func decodeValue(dec *json.Decoder, depth int) (Value, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("json: %w", err)
	}
	switch t := tok.(type) {
	case json.Delim:
		if depth >= MaxDepth {
			return nil, ErrTooDeep
		}
		if t == '{' {
			return decodeObject(dec, depth+1)
		}
		return decodeArray(dec, depth+1)
	case json.Number:
		return number(string(t)), nil
	default:
		return t, nil // string, bool or nil
	}
}

func decodeObject(dec *json.Decoder, depth int) (Value, error) {
	o := NewObject()
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("json: %w", err)
		}
		key, _ := tok.(string) // the decoder only yields string keys inside an object
		v, err := decodeValue(dec, depth)
		if err != nil {
			return nil, err
		}
		o.Set(key, v)
	}
	if _, err := dec.Token(); err != nil { // the closing brace
		return nil, fmt.Errorf("json: %w", err)
	}
	return o, nil
}

func decodeArray(dec *json.Decoder, depth int) (Value, error) {
	out := []Value{}
	for dec.More() {
		v, err := decodeValue(dec, depth)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	if _, err := dec.Token(); err != nil { // the closing bracket
		return nil, fmt.Errorf("json: %w", err)
	}
	return out, nil
}

// number converts a JSON number literal as Python does: a literal with a fraction or exponent is a float
// (overflowing to infinity), anything else an integer of any size.
func number(s string) Value {
	if strings.ContainsAny(s, ".eE") {
		f, err := strconv.ParseFloat(s, 64)
		if err != nil && !errors.Is(err, strconv.ErrRange) {
			return s // unreachable for a literal the decoder accepted
		}
		return f // out of range: ±Inf, like Python's float()
	}
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		return i
	}
	return BigInt(strings.TrimPrefix(s, "+"))
}
