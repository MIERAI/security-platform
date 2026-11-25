package agentclaude

import (
	"slices"
	"strings"
	"testing"
)

func FuzzParseSettings(f *testing.F) {
	for _, s := range []string{`{}`, `{"permissions": {"allow": ["Bash(*)", "Read(~/x)"], "deny": ["Read(~/.ssh/**)"]}}`,
		`{"hooks": {"Stop": [], "Pre": [{"a": 1}]}, "cleanupPeriodDays": 7.9, "env": {"A": "b"}}`, `[1]`, `{"permissions": 1}`,
		`{"cleanupPeriodDays": "1_0"}`, `{"env": 0, "hooks": false}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		d, err := ParseSettings(data)
		if err != nil {
			return
		}
		n := 0
		for _, k := range d.broadOrder {
			if d.broadCount[k] <= 0 {
				t.Fatalf("broad %q counted %d", k, d.broadCount[k])
			}
			n += d.broadCount[k]
		}
		if n > len(d.allow)*len(broadRules()) {
			t.Fatalf("%d broad matches for %d rules", n, len(d.allow))
		}
	})
}

// FuzzScanText: any text scans without failing, the classes are the known ones, and nothing of the input comes back.
func FuzzScanText(f *testing.F) {
	gh, pw, _ := canaries()
	for _, s := range []string{"", "a\nb", "password: " + pw + "\n" + gh, "token=" + pw + "中", "\r\r\n\xff\xfe secret:　aaaaaaaa"} {
		f.Add(s)
	}
	known := []string{ClassGitHub, ClassAWS, ClassSlack, ClassSecretKey, ClassGoogle, ClassPrivateKey, ClassAssignment}
	f.Fuzz(func(t *testing.T, text string) {
		n, classes := ScanText(text)
		if n < 0 || n > len(SplitLines(text)) {
			t.Fatalf("%d lines of %d", n, len(SplitLines(text)))
		}
		if (n == 0) != (len(classes) == 0) {
			t.Fatalf("%d lines, classes %v", n, classes)
		}
		if !slices.IsSorted(classes) {
			t.Fatalf("unsorted %v", classes)
		}
		for _, c := range classes {
			if !slices.Contains(known, c) {
				t.Fatalf("class %q", c)
			}
		}
		if strings.Contains(strings.Join(classes, ""), "C0nf") {
			t.Fatal("input text in the classes")
		}
	})
}
