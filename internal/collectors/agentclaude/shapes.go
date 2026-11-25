package agentclaude

import (
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// Credential shapes (collectors/agent-claude-code SECRET_SHAPES), one expression per class so that a finding can
// say WHICH kind of credential a memory file holds without ever reading out the value. Case-insensitive, as the
// reference compiles them (re.I). Never written after initialisation.
var (
	shapeGitHub     = regexp.MustCompile(`(?i)gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}`)
	shapeAWS        = regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`)
	shapeSlack      = regexp.MustCompile(`(?i)xox[abpr]-[A-Za-z0-9-]{10,}`)
	shapeSecretKey  = regexp.MustCompile(`(?i)sk-[A-Za-z0-9_-]{32,}`)
	shapeGoogle     = regexp.MustCompile(`(?i)AIza[0-9A-Za-z_-]{35}`)
	shapePrivateKey = regexp.MustCompile(`(?i)-{5}BEGIN [A-Z ]*PRIVATE KEY-{5}`)
	// a keyword, a separator and 8+ credential characters; the reference's negative lookahead (the value must end
	// at white space, the end of the line or , ; ) ） 。 ，) is checked in code: RE2 has no lookahead.
	shapeAssignment = regexp.MustCompile(`(?i)(?:password|passwd|密码|口令|token|secret)` + pySpace + `*[:=：]` + pySpace +
		`*[A-Za-z0-9!@#%^&*._+/=-]{8,}`)
)

// pySpace is Python's \s for text patterns (str.isspace), not RE2's ASCII \s.
const pySpace = `[\t\n\x0b\x0c\r \x1c-\x1f\x{85}\x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}]`

// Pattern classes reported for memory files.
const (
	ClassGitHub     = "github-token"
	ClassAWS        = "aws-access-key-id"
	ClassSlack      = "slack-token"
	ClassSecretKey  = "api-secret-key"
	ClassGoogle     = "google-api-key"
	ClassPrivateKey = "private-key"
	ClassAssignment = "credential-assignment"
)

type shape struct {
	class string
	re    *regexp.Regexp
}

func shapes() []shape {
	return []shape{{ClassGitHub, shapeGitHub}, {ClassAWS, shapeAWS}, {ClassSlack, shapeSlack},
		{ClassSecretKey, shapeSecretKey}, {ClassGoogle, shapeGoogle}, {ClassPrivateKey, shapePrivateKey}}
}

// LineClasses returns the credential classes one line matches, sorted; nil for a line without a credential shape.
// Only the classes leave this function, never the matched text.
func LineClasses(line string) []string {
	var out []string
	for _, s := range shapes() {
		if s.re.MatchString(line) {
			out = append(out, s.class)
		}
	}
	if assignment(line) {
		out = append(out, ClassAssignment)
	}
	sort.Strings(out)
	return out
}

// assignment is the keyword alternative with the reference's lookahead: the value run must be followed by the end
// of the line, white space or one of , ; ) ） 。 ，. The run is maximal (greedy), so a match that fails the check
// cannot succeed with a shorter run, and a later keyword inside it ends at the same place: checking every
// non-overlapping match is exact.
func assignment(line string) bool {
	for _, m := range shapeAssignment.FindAllStringIndex(line, -1) {
		if m[1] == len(line) {
			return true
		}
		r, _ := utf8.DecodeRuneInString(line[m[1]:])
		if isPySpace(r) || strings.ContainsRune(",;)）。，", r) {
			return true
		}
	}
	return false
}

func isPySpace(r rune) bool {
	return r >= 0x2000 && r <= 0x200a ||
		strings.ContainsRune("\t\n\v\f\r \x1c\x1d\x1e\x1f\u0085\u00a0\u1680\u2028\u2029\u202f\u205f\u3000", r)
}

// SplitLines splits text as Python's text mode reads it (universal newlines: \n, \r\n and \r end a line), keeping
// nothing of the line ends; a final line without an end is a line too.
func SplitLines(text string) []string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	if text == "" {
		return nil
	}
	lines := strings.Split(text, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}
