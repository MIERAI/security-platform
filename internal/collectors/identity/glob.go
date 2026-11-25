package identity

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// The local stores are configured as Python glob patterns; this is glob.glob's behaviour: `*`, `?` and `[...]`
// (with `!` negation) per path component, names starting with "." only matched by a pattern that starts with ".",
// a pattern without magic returned as is when it exists, results sorted.

func hasMagic(s string) bool { return strings.ContainsAny(s, "*?[") }

// pyGlob returns the sorted matches of one pattern.
func pyGlob(pattern string) []string {
	out := globPath(pattern, false)
	sort.Strings(out)
	return out
}

func globPath(pattern string, dirOnly bool) []string {
	if !hasMagic(pattern) {
		if exists(pattern, dirOnly || strings.HasSuffix(pattern, "/")) {
			return []string{pattern}
		}
		return nil
	}
	dir, base := filepath.Split(pattern)
	dir = strings.TrimSuffix(dir, "/")
	if dir == "" && strings.HasPrefix(pattern, "/") {
		dir = "/"
	}
	dirs := []string{dir}
	if hasMagic(dir) {
		dirs = globPath(dir, true)
	}
	var out []string
	for _, d := range dirs {
		for _, name := range globNames(d, base, dirOnly) {
			out = append(out, joinPy(d, name))
		}
	}
	return out
}

// exists is os.path.lexists, or os.path.isdir when only a directory will do.
func exists(p string, dirOnly bool) bool {
	if dirOnly {
		fi, err := os.Stat(p)
		return err == nil && fi.IsDir()
	}
	_, err := os.Lstat(p)
	return err == nil
}

// joinPy is os.path.join(dir, name) ("" dir: name alone).
func joinPy(dir, name string) string {
	if dir == "" {
		return name
	}
	if strings.HasSuffix(dir, "/") {
		return dir + name
	}
	return dir + "/" + name
}

func globNames(dir, base string, dirOnly bool) []string {
	if !hasMagic(base) {
		if base == "" && exists(dir, true) || base != "" && exists(joinPy(dir, base), false) {
			return []string{base}
		}
		return nil
	}
	rx, err := fnmatchRegexp(base)
	if err != nil {
		return nil
	}
	entries, err := os.ReadDir(orDot(dir))
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if name := e.Name(); matchName(name, base, rx) && (!dirOnly || exists(joinPy(dir, name), true)) {
			out = append(out, name)
		}
	}
	return out
}

// matchName: a hidden name only matches a pattern that starts with ".".
func matchName(name, pattern string, rx *regexp.Regexp) bool {
	hidden := strings.HasPrefix(name, ".") && !strings.HasPrefix(pattern, ".")
	return !hidden && rx.MatchString(name)
}

// fnmatchRegexp is fnmatch.translate: `*` any text, `?` one character, `[...]` a class (`!` negates), an
// unterminated `[` a literal.
func fnmatchRegexp(pat string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString(`(?s)^`)
	rs := []rune(pat)
	for i := 0; i < len(rs); i++ {
		switch c := rs[i]; c {
		case '*':
			b.WriteString(`.*`)
		case '?':
			b.WriteString(`.`)
		case '[':
			j := classEnd(rs, i+1)
			if j < 0 {
				b.WriteString(`\[`)
				continue
			}
			b.WriteString(classRegexp(rs[i+1 : j]))
			i = j
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString(`$`)
	return regexp.Compile(b.String())
}

// classEnd is the index of the `]` that closes a class starting at i (a `]` right after `[` or `[!` is literal).
func classEnd(rs []rune, i int) int {
	j := i
	if j < len(rs) && rs[j] == '!' {
		j++
	}
	if j < len(rs) && rs[j] == ']' {
		j++
	}
	for ; j < len(rs); j++ {
		if rs[j] == ']' {
			return j
		}
	}
	return -1
}

func classRegexp(body []rune) string {
	var b strings.Builder
	b.WriteByte('[')
	if len(body) > 0 && body[0] == '!' {
		b.WriteByte('^')
		body = body[1:]
	} else if len(body) > 0 && body[0] == '^' {
		b.WriteString(`\^`)
		body = body[1:]
	}
	for _, r := range body {
		if r == '\\' || r == '[' || r == ']' || r == '^' {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	b.WriteByte(']')
	return b.String()
}

// orDot is the directory to list: "" is the working directory.
func orDot(dir string) string {
	if dir == "" {
		return "."
	}
	return dir
}
