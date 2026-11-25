package promtext

import (
	"strings"
	"testing"
)

func TestRender(t *testing.T) {
	t.Parallel()
	got := Render([]Series{
		{Name: "x_total", Labels: map[string]string{"b": "2", "a": `q"u\o` + "\nte"}, Value: Int(3), Help: "Things"},
		{Name: "x_total", Labels: map[string]string{"a": "1"}, Value: Int(4), Help: "ignored"},
		{Name: "y", Value: Float(12.25)},
		{Name: "z", Value: Float(1234567.0), Help: "big"},
	})
	want := `# HELP x_total Things
# TYPE x_total counter
x_total{a="q'u/o te",b="2"} 3
x_total{a="1"} 4
# TYPE y gauge
y 12.25
# HELP z big
# TYPE z gauge
z 1.23457e+06
`
	if got != want {
		t.Errorf("Render =\n%s\nwant\n%s", got, want)
	}
}

func TestMerge(t *testing.T) {
	t.Parallel()
	in := "# HELP a A\n# TYPE a gauge\na 1\n\n# HELP b B\nb{x=\"1\"} 2\n# HELP a again\n# TYPE a counter\na 1\na{y=\"2\"} 3\n# HELP\n"
	// "# HELP" without a name is not a HELP line: like the reference, it is kept as a sample of family "#"
	want := "# HELP a A\n# TYPE a gauge\na 1\na{y=\"2\"} 3\n# HELP b B\nb{x=\"1\"} 2\n# HELP\n"
	if got := Merge(in); got != want {
		t.Errorf("Merge =\n%q\nwant\n%q", got, want)
	}
}

// FuzzMerge: merging never panics and is idempotent.
func FuzzMerge(f *testing.F) {
	for _, s := range []string{"# HELP a x\na 1\n", "a{b=\"{\"} 1\n a 2", "# TYPE\n#\n{} 1", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		once := Merge(s)
		if twice := Merge(once); twice != once {
			t.Fatalf("not idempotent:\n%q\n%q", once, twice)
		}
		if !strings.HasSuffix(once, "\n") {
			t.Fatalf("no final newline: %q", once)
		}
	})
}
