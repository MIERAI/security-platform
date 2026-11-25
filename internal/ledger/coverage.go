package ledger

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// umbrellaTypes: an ok entry of the key type also covers assets of these types with the same scope (§3.3).
func umbrellaTypes() map[string][]string {
	return map[string][]string{
		"host":        {"secret-file"},
		"k8s-cluster": {"k8s-workload", "k8s-namespace", "k8s-identity", "k8s-cluster", "cis"},
	}
}

const separators = ":/@"

// scope splits an asset into its type and the part of the rest up to the first separator.
func scope(asset string) (typ, sc string) {
	typ, rest, _ := strings.Cut(asset, ":")
	if i := strings.IndexAny(rest, separators); i >= 0 {
		return typ, rest[:i]
	}
	return typ, rest
}

type typeScope struct{ typ, scope string }

// Coverage is a set of coverage assets with the matching rules of §3: exact, prefix ending before a separator,
// umbrella types. A lookup costs O(len(asset)).
type Coverage struct {
	exact    map[string]bool
	umbrella map[typeScope]bool
	subtypes map[string][]string
}

// NewCoverage indexes assets.
func NewCoverage(assets []string) *Coverage {
	c := &Coverage{exact: map[string]bool{}, umbrella: map[typeScope]bool{}, subtypes: umbrellaTypes()}
	for _, a := range assets {
		c.exact[a] = true
		typ, sc := scope(a)
		if _, ok := c.subtypes[typ]; ok {
			c.umbrella[typeScope{typ, sc}] = true
		}
	}
	return c
}

// Empty reports whether the set has no asset.
func (c *Coverage) Empty() bool {
	return len(c.exact) == 0
}

// Covers reports whether an entry of the set matches asset.
func (c *Coverage) Covers(asset string) bool {
	if c.exact[asset] {
		return true
	}
	for i := 0; i < len(asset); i++ {
		if strings.IndexByte(separators, asset[i]) >= 0 && c.exact[asset[:i]] {
			return true
		}
	}
	typ, sc := scope(asset)
	for ct, subs := range c.subtypes {
		if c.umbrella[typeScope{ct, sc}] && contains(subs, typ) {
			return true
		}
	}
	return false
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// fnmatch is Python's fnmatch.fnmatchcase: `*` matches anything (also `/`), `?` one character, `[...]` a
// class (`[!...]` negated); everything else is literal.
func fnmatch(name, pattern string) bool {
	re, err := regexp.Compile(translate(pattern))
	return err == nil && re.MatchString(name)
}

func translate(pat string) string {
	var b strings.Builder
	b.WriteString(`\A(?s:`)
	for i := 0; i < len(pat); {
		switch c := pat[i]; c {
		case '*':
			b.WriteString(".*")
			i++
		case '?':
			b.WriteString(".")
			i++
		case '[':
			i = class(&b, pat, i)
		default:
			_, size := utf8.DecodeRuneInString(pat[i:])
			b.WriteString(regexp.QuoteMeta(pat[i : i+size]))
			i += size
		}
	}
	b.WriteString(`)\z`)
	return b.String()
}

// class translates the bracket expression starting at pat[i] ("[" literal when unterminated) and returns the
// index after it.
func class(b *strings.Builder, pat string, i int) int {
	j := i + 1
	if j < len(pat) && pat[j] == '!' {
		j++
	}
	if j < len(pat) && pat[j] == ']' {
		j++
	}
	for j < len(pat) && pat[j] != ']' {
		j++
	}
	if j >= len(pat) {
		b.WriteString(`\[`)
		return i + 1
	}
	body := strings.ReplaceAll(pat[i+1:j], `\`, `\\`)
	if strings.HasPrefix(body, "!") {
		body = "^" + body[1:]
	} else if strings.HasPrefix(body, "^") {
		body = `\` + body
	}
	b.WriteString("[" + body + "]")
	return j + 1
}
