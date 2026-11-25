// Package prom renders Prometheus text exposition exactly as the reference's sdk render() does: HELP and TYPE
// at the first sample of a family (counter when the name ends in _total, else gauge), labels sorted by key with
// backslashes, quotes and newlines neutralised, integers as integers and floats as %g.
package prom

import (
	"sort"
	"strconv"
	"strings"

	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
)

// Series is one sample.
type Series struct {
	Name   string
	Labels map[string]string
	Value  pyjson.Value // int64 or float64
	Help   string
}

// Render returns the text of the series in order.
func Render(series []Series) string {
	var b strings.Builder
	seen := map[string]bool{}
	for _, s := range series {
		if !seen[s.Name] {
			seen[s.Name] = true
			if s.Help != "" {
				b.WriteString("# HELP " + s.Name + " " + s.Help + "\n")
			}
			b.WriteString("# TYPE " + s.Name + " " + typeOf(s.Name) + "\n")
		}
		b.WriteString(s.Name + labels(s.Labels) + " " + value(s.Value) + "\n")
	}
	if len(series) == 0 {
		return "\n" // "\n".join([]) + "\n"
	}
	return b.String()
}

func typeOf(name string) string {
	if strings.HasSuffix(name, "_total") {
		return "counter"
	}
	return "gauge"
}

func labels(l map[string]string) string {
	if len(l) == 0 {
		return ""
	}
	keys := make([]string, 0, len(l))
	for k := range l {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	r := strings.NewReplacer(`\`, "/", `"`, "'", "\n", " ")
	for i, k := range keys {
		parts[i] = k + `="` + r.Replace(l[k]) + `"`
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func value(v pyjson.Value) string {
	switch t := v.(type) {
	case float64:
		return pyjson.FormatG(t)
	case int64:
		return strconv.FormatInt(t, 10)
	default:
		return pyjson.Str(v)
	}
}
