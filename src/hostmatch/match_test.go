package hostmatch

import (
	"testing"
)

func TestMatchersWildcard(t *testing.T) {
	var matcher match
	td := []rune(".here")
	tdT := []rune(".here")
	tdN := 0
	matcher = wildcard{}
	n, _, r, _ := matcher.match(td)
	if n != tdN {
		t.Error("wildcard empty: n")
	}
	if string(r) != string(tdT) {
		t.Error("wildcard empty: remainder")
	}
	td = []rune("not.here")
	tdN = 3
	matcher = wildcard{}
	n, _, r, _ = matcher.match(td)
	if n != tdN {
		t.Error("wildcard: n")
	}
	if string(r) != string(tdT) {
		t.Error("wildcard: remainder")
	}
}

func TestMatchersLiteral(t *testing.T) {
	var matcher match
	td := []rune("not.here")
	tdT := []rune(".here")
	tdN := 3
	matcher = literal("not")
	n, _, rem, ok := matcher.match(td)
	if !ok {
		t.Error("literal not matched")
	}
	if n != tdN {
		t.Error("literal: n")
	}
	if string(rem) != string(tdT) {
		t.Error("literal: remainder")
	}
	if _, _, _, ok := matcher.match([]rune("abyzz")); ok {
		t.Error("literal: wrong match")
	}
}
