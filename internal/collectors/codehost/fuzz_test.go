package codehost

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func FuzzFnmatchCase(f *testing.F) {
	for _, s := range [][2]string{{"release/v1", "release/*"}, {"a", "[!a-c]"}, {"x", "[]x]"}, {"[", "[!"}, {"ab", "*?*"}} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, name, pattern string) {
		if !utf8.ValidString(name) || !utf8.ValidString(pattern) {
			return // names and patterns come from decoded JSON: always valid UTF-8 (as Python's str)
		}
		got := FnmatchCase(name, pattern)
		if !strings.ContainsAny(pattern, "*?[") && got != (name == pattern) {
			t.Fatalf("literal %q vs %q: %v", pattern, name, got)
		}
		if FnmatchCase(name, "*") != true {
			t.Fatal(`"*" must match everything`)
		}
		if strings.HasPrefix(pattern, "*") && !FnmatchCase(name, pattern) && FnmatchCase(name, pattern[1:]) {
			t.Fatalf("*%q is narrower than %q for %q", pattern[1:], pattern[1:], name)
		}
	})
}

func FuzzNextLink(f *testing.F) {
	for _, s := range []string{`<https://a/b?page=2>; rel="next"`, `<x>; rel="last", <y>; rel=next`, `<<>>; rel="next"`, ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, v string) {
		got := NextLink([]string{v})
		if got != "" && !strings.Contains(v, "<"+got+">") {
			t.Fatalf("%q is not a <target> of %q", got, v)
		}
	})
}

func FuzzQuote(f *testing.F) {
	f.Add("a b/c")
	f.Fuzz(func(t *testing.T, s string) {
		q := Quote(s)
		if strings.ContainsAny(q, " ?#\"<>") {
			t.Fatalf("unescaped in %q", q)
		}
	})
}
