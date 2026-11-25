// Package promtext renders and merges Prometheus text-format metrics exactly as the reference implementation does
// (sdk spsdk.render and runner.merge_families), so the published file is the same whichever runner wrote it.
package promtext

import (
	"sort"
	"strconv"
	"strings"

	"github.com/MIERAI/security-platform/internal/runner/pyfmt"
)

// Value is a sample value: an integer is written as is, a float with six significant digits (Python's {v:g}).
type Value struct {
	Int     int64
	Float   float64
	IsFloat bool
}

// Int returns an integer value.
func Int(v int64) Value { return Value{Int: v} }

// Float returns a float value.
func Float(v float64) Value { return Value{Float: v, IsFloat: true} }

func (v Value) String() string {
	if v.IsFloat {
		return pyfmt.FormatG(v.Float)
	}
	return strconv.FormatInt(v.Int, 10)
}

// Series is one sample with its family's help text.
type Series struct {
	Name   string
	Labels map[string]string
	Value  Value
	Help   string
}

// Render writes the series: HELP (when given) and TYPE once per family, in the order the families first appear;
// TYPE is counter for a name ending in _total, gauge otherwise. Label values are made safe as the reference does
// (backslash to slash, double quote to single quote, newline to space).
func Render(series []Series) string {
	var b strings.Builder
	seen := map[string]bool{}
	for _, s := range series {
		if !seen[s.Name] {
			seen[s.Name] = true
			if s.Help != "" {
				b.WriteString("# HELP " + s.Name + " " + s.Help + "\n")
			}
			typ := "gauge"
			if strings.HasSuffix(s.Name, "_total") {
				typ = "counter"
			}
			b.WriteString("# TYPE " + s.Name + " " + typ + "\n")
		}
		b.WriteString(s.Name + labels(s.Labels) + " " + s.Value.String() + "\n")
	}
	return b.String()
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
	r := strings.NewReplacer(`\`, "/", `"`, "'", "\n", " ")
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + `="` + r.Replace(l[k]) + `"`
	}
	return "{" + strings.Join(parts, ",") + "}"
}

type family struct {
	help, typ string
	samples   []string
	seen      map[string]bool
}

type families struct {
	byName map[string]*family
	order  []string
}

func (fs *families) get(n string) *family {
	f, ok := fs.byName[n]
	if !ok {
		f = &family{seen: map[string]bool{}}
		fs.byName[n] = f
		fs.order = append(fs.order, n)
	}
	return f
}

// Merge groups concatenated text by family: the first HELP and TYPE line of each family, then its samples
// without duplicates, families in order of first appearance; blank lines dropped.
func Merge(text string) string {
	fs := &families{byName: map[string]*family{}}
	for _, line := range strings.Split(text, "\n") {
		switch {
		case strings.TrimSpace(line) == "":
		case strings.HasPrefix(line, "# HELP ") || strings.HasPrefix(line, "# TYPE "):
			addMeta(fs, line)
		default:
			f := fs.get(sampleName(line))
			if !f.seen[line] {
				f.seen[line] = true
				f.samples = append(f.samples, line)
			}
		}
	}
	var out []string
	for _, n := range fs.order {
		f := fs.byName[n]
		for _, meta := range []string{f.help, f.typ} {
			if meta != "" {
				out = append(out, meta)
			}
		}
		out = append(out, f.samples...)
	}
	return strings.Join(out, "\n") + "\n"
}

func addMeta(fs *families, line string) {
	words := strings.Fields(line)
	if len(words) < 3 {
		return // "# HELP" without a name: the reference raises here; such a line is dropped
	}
	f := fs.get(words[2])
	if strings.HasPrefix(line, "# HELP ") {
		if f.help == "" {
			f.help = line
		}
		return
	}
	if f.typ == "" {
		f.typ = line
	}
}

// sampleName is the metric name of a sample line: up to the first '{', then up to the first whitespace.
func sampleName(line string) string {
	head, _, _ := strings.Cut(line, "{")
	if w := strings.Fields(head); len(w) > 0 {
		return w[0]
	}
	return head
}
