package scorecard

import (
	"fmt"
	"regexp"
	"strings"
)

// globRegexp compiles an instance's id pattern (SPEC §3, not_applicable): `*` any text (slashes and newlines
// included), `?` one character, `[abc]` / `[a-z]` / `[!a-z]` one character of / not of a set, everything else
// literal (no escape character). A `[` without a closing `]` is literal; a range whose start is after its end is
// empty and removed; `-` first, last or right after a range is literal. Case-sensitive, whole id.
// Python's fnmatch.fnmatchcase.
func globRegexp(pattern string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString(`(?s)^`)
	p := []rune(pattern)
	for i := 0; i < len(p); i++ {
		switch p[i] {
		case '*':
			for i+1 < len(p) && p[i+1] == '*' {
				i++
			}
			b.WriteString(`.*`)
		case '?':
			b.WriteString(`.`)
		case '[':
			end := classEnd(p, i+1)
			if end < 0 {
				b.WriteString(`\[`)
				continue
			}
			b.WriteString(charClass(p[i+1 : end]))
			i = end
		default:
			b.WriteString(regexp.QuoteMeta(string(p[i])))
		}
	}
	b.WriteString(`$`)
	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil, fmt.Errorf("pattern %q: %w", pattern, err)
	}
	return re, nil
}

// classEnd is the index of the `]` closing a set that starts at p[start] (after the `[`), or -1. A `]` right
// after `[` or `[!` belongs to the set.
func classEnd(p []rune, start int) int {
	j := start
	if j < len(p) && p[j] == '!' {
		j++
	}
	if j < len(p) && p[j] == ']' {
		j++
	}
	for j < len(p) && p[j] != ']' {
		j++
	}
	if j >= len(p) {
		return -1
	}
	return j
}

// charClass turns the inside of a set into a regular expression: a set that is empty after removing reversed
// ranges never matches; a negated empty set matches any character.
func charClass(stuff []rune) string {
	negated := len(stuff) > 0 && stuff[0] == '!'
	if negated {
		stuff = stuff[1:]
	}
	items := classItems(stuff)
	switch {
	case items == "" && negated:
		return `.`
	case items == "":
		return `[^\x00-\x{10FFFF}]`
	case negated:
		return `[^` + items + `]`
	}
	return `[` + items + `]`
}

func classItems(stuff []rune) string {
	var b strings.Builder
	for i := 0; i < len(stuff); i++ {
		lo := stuff[i]
		if i+2 < len(stuff) && stuff[i+1] == '-' {
			hi := stuff[i+2]
			i += 2
			if lo <= hi {
				b.WriteString(classRune(lo) + "-" + classRune(hi))
			}
			continue
		}
		b.WriteString(classRune(lo))
	}
	return b.String()
}

func classRune(r rune) string {
	return fmt.Sprintf(`\x{%x}`, r)
}
