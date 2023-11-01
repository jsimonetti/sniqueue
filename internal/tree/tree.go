package tree

import (
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
