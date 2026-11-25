package codehost

// FnmatchCase is Python's fnmatch.fnmatchcase(name, pattern): "*" any text (also "/"), "?" one character, "[seq]" /
// "[!seq]" a character class with ranges; a "[" without its "]" is an ordinary character. Branch protection rules of
// Gitea name their branches with such patterns ("release/*").
func FnmatchCase(name, pattern string) bool {
	return match([]rune(name), []rune(pattern))
}

func match(name, pat []rune) bool {
	// iterative matching with backtracking to the last "*": linear in practice, no recursion depth
	n, p, star, mark := 0, 0, -1, 0
	for n < len(name) {
		if p < len(pat) {
			if pat[p] == '*' {
				star, mark = p, n
				p++
				continue
			}
			if width, ok := single(name[n], pat[p:]); ok {
				n++
				p += width
				continue
			}
		}
		if star < 0 {
			return false
		}
		mark++
		n, p = mark, star+1
	}
	for p < len(pat) && pat[p] == '*' {
		p++
	}
	return p == len(pat)
}

// single matches one character against the pattern element at pat[0]; it returns the element's width.
func single(c rune, pat []rune) (width int, ok bool) {
	switch pat[0] {
	case '?':
		return 1, true
	case '[':
		if w, in, isClass := class(c, pat); isClass {
			return w, in
		}
		return 1, c == '['
	default:
		return 1, c == pat[0]
	}
}

// class reads "[...]" at pat[0]: its width, whether c is in it, and whether it is a class at all (closed by "]").
func class(c rune, pat []rune) (width int, in, isClass bool) {
	i := 1
	negate := i < len(pat) && pat[i] == '!'
	if negate {
		i++
	}
	start := i
	for ; i < len(pat); i++ {
		if pat[i] == ']' && i > start {
			break
		}
	}
	if i >= len(pat) {
		return 0, false, false
	}
	return i + 1, inClass(c, pat[start:i]) != negate, true
}

// inClass reports whether c is in a class body: single characters and a-z ranges.
func inClass(c rune, body []rune) bool {
	for j := 0; j < len(body); j++ {
		if j+2 < len(body) && body[j+1] == '-' {
			if body[j] <= c && c <= body[j+2] {
				return true
			}
			j += 2
			continue
		}
		if body[j] == c {
			return true
		}
	}
	return false
}
