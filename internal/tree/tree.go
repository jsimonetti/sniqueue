package tree

import (
	"unicode"

	"github.com/Lochnair/go-patricia/patricia"
)

type Tree struct {
	domainTrie *patricia.Trie
	size       int
}

func New() Tree {
	return Tree{
		domainTrie: patricia.NewTrie(),
	}
}
func (t *Tree) Size() int {
	return t.size
}

func (t *Tree) Match(domainName string) bool {
	if len(domainName) < 1 {
		return false
	}
	reversedDomain := Reverse(domainName)
	_, _, found, leftover := t.domainTrie.FindSubtree(patricia.Prefix(reversedDomain))

	/*
	 * Match is true if either the domain matches perfectly in the Trie
	 * or if the first character of the leftover is a wildcard
	 */
	return found || (len(leftover) > 0 && leftover[0] == 42)
}

func (t *Tree) Append(list []string) *Tree {
	for _, domain := range list {
		reversedDomain := Reverse(domain)
		t.domainTrie.Insert(patricia.Prefix(reversedDomain), 0)
		t.size++
	}
	return t
}

// Reverse reverses the input while respecting UTF8 encoding and combined characters
func Reverse(text string) string {
	textRunes := []rune(text)
	textRunesLength := len(textRunes)
	if textRunesLength <= 1 {
		return text
	}

	i, j := 0, 0
	for i < textRunesLength && j < textRunesLength {
		j = i + 1
		for j < textRunesLength && IsMark(textRunes[j]) {
			j++
		}

		if IsMark(textRunes[j-1]) {
			// Reverses Combined Characters
			reverse(textRunes[i:j], j-i)
		}

		i = j
	}

	// Reverses the entire array
	reverse(textRunes, textRunesLength)

	return string(textRunes)
}

func IsMark(r rune) bool {
	return unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Me, r) || unicode.Is(unicode.Mc, r)
}

func reverse(runes []rune, length int) {
	for i, j := 0, length-1; i < length/2; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
}
