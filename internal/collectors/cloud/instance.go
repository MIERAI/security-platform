package cloud

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/MIERAI/security-platform/internal/cloud/dyn"
)

const maxInstanceFile = 16 << 20

// errNotJSON: the instance config is not JSON (YAML needs the Python implementation for now).
var errNotJSON = errors.New("the instance config is not JSON: the Go cloud collector reads JSON instance configs " +
	"(JSON is YAML too: convert it, or run the Python collector)")

// instanceConfig is the instance's `cloud` section, with the order of its `engines` keys (the default engine list
// is that order, as in the Python implementation).
type instanceConfig struct {
	cloud       map[string]any
	engineOrder []string
}

func parseInstance(data []byte) (instanceConfig, error) {
	v, err := dyn.Decode(data)
	if err != nil {
		return instanceConfig{}, errNotJSON
	}
	root, ok := v.(map[string]any)
	if !ok {
		return instanceConfig{}, fmt.Errorf("the instance config is not an object")
	}
	order, err := objectKeys(data, "cloud", "engines")
	if err != nil {
		return instanceConfig{}, errNotJSON
	}
	return instanceConfig{cloud: dyn.Map(root["cloud"]), engineOrder: order}, nil
}

// objectKeys returns the keys of the object at path, in document order (nil when there is none).
func objectKeys(data []byte, path ...string) ([]string, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	for _, key := range path {
		found, err := descend(dec, key)
		if err != nil || !found {
			return nil, err
		}
	}
	return keysHere(dec)
}

// descend moves the decoder into the value of key in the object that starts at the next token.
func descend(dec *json.Decoder, key string) (bool, error) {
	tok, err := dec.Token()
	if err != nil {
		return false, fmt.Errorf("instance json: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return false, nil
	}
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			return false, fmt.Errorf("instance json: %w", err)
		}
		if k == key {
			return true, nil
		}
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return false, fmt.Errorf("instance json: %w", err)
		}
	}
	return false, nil
}

func keysHere(dec *json.Decoder) ([]string, error) {
	tok, err := dec.Token()
	if errors.Is(err, io.EOF) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("instance json: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, nil
	}
	var keys []string
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("instance json: %w", err)
		}
		keys = append(keys, dyn.Str(k))
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return nil, fmt.Errorf("instance json: %w", err)
		}
	}
	return keys, nil
}
