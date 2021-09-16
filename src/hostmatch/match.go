// Package hostmatch implements simple wildcard matching for hostnames. Only the wildcard '*' is supported, which matches
// all characters except for '.' (dot), including empty. Matching is greedy, it will stop only at the next unmatched rune.
package hostmatch

const (
	wildcardRune = '*'
	stopRune     = '.'
)

type match interface {
	match(input []rune) (n int, match, rem []rune, ok bool)
}

func matchUntil(input []rune, until rune) (n int, match, rem []rune, ok bool) {
	for n, r := range input {
		if r == until {
			return n, input[:n], input[n:], true
		}
	}
	return len(input), input[:], input[len(input):], true
}

type wildcard struct{}

func (m wildcard) match(input []rune) (n int, match, rem []rune, ok bool) {
	return matchUntil(input, stopRune)
}

type starsearch struct{}

func (m starsearch) match(input []rune) (n int, match, rem []rune, ok bool) {
	return matchUntil(input, wildcardRune)
}

type literal []rune

func (m literal) match(input []rune) (n int, match, rem []rune, ok bool) {
	if len(input) < len(m) {
		return 0, nil, nil, false
	}
	for i, r := range m {
		if r != input[i] {
			return 0, nil, nil, false
		}
	}
	return len(m), input[:len(m)], input[len(m):], true
}

// Pattern contains a pattern to match against.
type Pattern []match

// Compile a string into a matching pattern. Supports one wildcard (*) that stops at (.) and is greedy.
func Compile(patternString string) Pattern {
	ret := make(Pattern, 0, 3)
	ps := []rune(patternString)
	for len(ps) > 0 {
		if ps[0] == wildcardRune {
			ret = append(ret, wildcard{})
			ps = ps[1:]
			continue
		}
		_, m, r, _ := starsearch{}.match(ps)
		if len(m) == 0 {
			break
		}
		ps = r
		ret = append(ret, literal(m))
	}
	return ret
}

// Match s to the compiled pattern.
func (p Pattern) Match(s string) bool {
	ps := []rune(s)
	for _, m := range p {
		_, _, r, ok := m.match(ps)
		if !ok {
			return false
		}
		ps = r
	}
	return len(ps) == 0
}
