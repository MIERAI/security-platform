package explain

import (
	"errors"
	"regexp"
	"strings"
	"testing"
)

func TestEmbeddedTexts(t *testing.T) {
	t.Parallel()
	x, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range x.Checks() {
		if msg := entryProblem(x.Explain(c)); msg != "" {
			t.Errorf("%s: %s", c, msg)
		}
	}
	if len(x.Checks()) < 100 || x.Layer("host") == "" || x.Severity("critical") == "" || x.Layer("nope") != "" {
		t.Fatal("the embedded data lost entries")
	}
}

// entryProblem says what is wrong with an entry: a missing answer, a placeholder left, an address in the text.
func entryProblem(e Entry) string {
	ip := regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	all := e.What + e.Why + e.Fix + e.Verify
	switch {
	case e.What == "" || e.Why == "" || e.Fix == "" || e.Verify == "":
		return "incomplete entry"
	case strings.Contains(all, "{next_scan}"):
		return "placeholder left"
	case ip.MatchString(all):
		return "an address in the text"
	}
	return ""
}

func TestExplainFallbacks(t *testing.T) {
	t.Parallel()
	x, err := Parse([]byte(`{"schema": "security-platform/explanations/v1", "next_scan": "NEXT.",
		"checks": {"a.exact": {"what": "W", "why": "Y", "fix": "F", "verify": "V {next_scan}"}},
		"families": [{"prefix": "a.", "what": "family a", "why": "fy", "fix": "ff"}, {"prefix": "a", "what": "later"}],
		"layers": {"host": "the machine"}, "severities": {"high": "this week"}}`))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		check string
		want  Entry
	}{
		{"a.exact", Entry{"W", "Y", "F", "V NEXT."}},
		{"a.other", Entry{"family a", "fy", "ff", "NEXT."}},
		{"ab", Entry{"later", "", "", "NEXT."}},
		{"zzz", Entry{Verify: "NEXT."}},
	}
	for _, tc := range tests {
		if got := x.Explain(tc.check); got != tc.want {
			t.Errorf("Explain(%q) = %+v, want %+v", tc.check, got, tc.want)
		}
	}
	if x.Headline("zzz", "fallback") != "fallback" || x.Headline("a.exact", "f") != "W" {
		t.Error("Headline")
	}
}

func TestParseRejects(t *testing.T) {
	t.Parallel()
	for _, doc := range []string{"", "[]", `{"schema": "other/v1", "next_scan": "x"}`,
		`{"schema": "security-platform/explanations/v1"}`, `{"schema": "security-platform/explanations/v1", "next_scan": 1}`} {
		if _, err := Parse([]byte(doc)); !errors.Is(err, ErrData) {
			t.Errorf("Parse(%q) = %v, want ErrData", doc, err)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add(data)
	f.Add([]byte(`{"schema": "security-platform/explanations/v1", "next_scan": "n", "families": [{"prefix": ""}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		x, err := Parse(b)
		if err != nil {
			return
		}
		e := x.Explain("some.check")
		if e.Verify == "" {
			t.Fatal("an explanation always says how to verify")
		}
		_ = x.Headline("x", "y")
	})
}
