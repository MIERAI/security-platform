package cloud

import (
	"errors"
	"strings"
)

// ShellSplit splits a command line like Python's shlex.split (POSIX mode): white space separates words, single
// quotes keep everything literally, double quotes keep everything but a backslash before " \ $ `, and a backslash
// outside quotes escapes the next character. It runs nothing.
func ShellSplit(s string) ([]string, error) {
	var sp splitter
	for _, r := range s {
		sp.next(r)
	}
	if sp.quote != 0 || sp.escaped {
		return nil, errors.New("unterminated quote or escape")
	}
	sp.endWord()
	return sp.words, nil
}

type splitter struct {
	words   []string
	cur     strings.Builder
	inWord  bool
	quote   rune
	escaped bool
}

func (sp *splitter) next(r rune) {
	switch {
	case sp.escaped:
		if sp.quote == '"' && !strings.ContainsRune("\"\\$`\n", r) {
			sp.cur.WriteRune('\\')
		}
		sp.cur.WriteRune(r)
		sp.escaped = false
	case sp.quote != 0:
		sp.quoted(r)
	case r == '\\':
		sp.escaped, sp.inWord = true, true
	case r == '\'' || r == '"':
		sp.quote, sp.inWord = r, true
	case isSpace(r):
		sp.endWord()
	default:
		sp.cur.WriteRune(r)
		sp.inWord = true
	}
}

func (sp *splitter) quoted(r rune) {
	switch {
	case r == sp.quote:
		sp.quote = 0
	case r == '\\' && sp.quote == '"':
		sp.escaped = true
	default:
		sp.cur.WriteRune(r)
	}
}

func (sp *splitter) endWord() {
	if sp.inWord {
		sp.words = append(sp.words, sp.cur.String())
		sp.cur.Reset()
		sp.inWord = false
	}
}

// ShellQuote quotes one word like Python's shlex.quote.
func ShellQuote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, r := range s {
		if !isShellSafe(r) {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

func isShellSafe(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("@%+=:,./-_", r)
}

func isSpace(r rune) bool { return r == ' ' || r == '\t' || r == '\n' || r == '\r' }
