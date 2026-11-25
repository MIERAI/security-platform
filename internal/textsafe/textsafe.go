// Package textsafe makes text read from files or other programs safe to print on a terminal.
package textsafe

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Line returns s unchanged when it is valid UTF-8 made of printable characters (spaces included), and its
// Go-quoted form otherwise, so that control characters (terminal escape sequences, carriage returns, newlines)
// read from a file can never act on the terminal or forge extra output lines.
func Line(s string) string {
	if utf8.ValidString(s) && strings.IndexFunc(s, notPrintable) < 0 {
		return s
	}
	return strconv.Quote(s)
}

func notPrintable(r rune) bool {
	return !unicode.IsPrint(r) && r != ' '
}
