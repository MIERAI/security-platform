package cloud

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/MIERAI/security-platform/internal/cloud/dyn"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

const maxInstanceFile = 16 << 20

// instanceConfig is the instance's `cloud` section, with the order of its `engines` keys (the default engine list
// is that order, as in the Python implementation).
type instanceConfig struct {
	cloud       map[string]any
	engineOrder []string
}

// parseInstance reads the instance config as the Python implementation does (PyYAML safe_load: YAML 1.1 typing;
// a JSON file is YAML too), through pyvalue, the YAML reading every Go component shares.
func parseInstance(data []byte) (instanceConfig, error) {
	v, err := pyvalue.DecodeYAML(data)
	if err != nil {
		return instanceConfig{}, fmt.Errorf("the instance config is not YAML/JSON: %w", err)
	}
	root, ok := v.(*pyvalue.Map)
	if !ok {
		return instanceConfig{}, fmt.Errorf("the instance config is not a mapping")
	}
	cloudSection, _ := root.Value("cloud").(*pyvalue.Map) // absent or not a mapping: no cloud section
	var order []string
	if cloudSection != nil {
		if engines, isMap := cloudSection.Value("engines").(*pyvalue.Map); isMap {
			order = engines.Keys()
		}
	}
	return instanceConfig{cloud: dyn.Map(loose(cloudSection)), engineOrder: order}, nil
}

// loose turns a pyvalue document into the loose JSON shape the collector reads (dyn): mappings become
// map[string]any, numbers json.Number with Python's str() of the value, dates their text.
func loose(v any) any {
	switch x := v.(type) {
	case *pyvalue.Map:
		if x == nil {
			return nil
		}
		m := make(map[string]any, x.Len())
		for _, k := range x.Keys() {
			m[k] = loose(x.Value(k))
		}
		return m
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = loose(e)
		}
		return out
	case int64:
		return json.Number(strconv.FormatInt(x, 10))
	case float64:
		return json.Number(pyjson.FloatRepr(x))
	case pyvalue.Date:
		return x.String()
	case pyvalue.DateTime:
		return x.String()
	default:
		return v
	}
}
