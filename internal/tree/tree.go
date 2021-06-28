package tree

import (
	"github.com/Lochnair/go-patricia/patricia"
	"github.com/shomali11/util/xstrings"
)

type Tree struct {
	domainTrie *patricia.Trie
}

func (t *Tree) Match(domainName string) bool {
	if len(domainName) < 1 {
		return false
	}
	reversedDomain := xstrings.Reverse(domainName)
	_, _, found, leftover := t.domainTrie.FindSubtree(patricia.Prefix(reversedDomain))

	/*
	 * Match is true if either the domain matches perfectly in the Trie
	 * or if the first character of the leftover is a wildcard
	 */
	return found || (len(leftover) > 0 && leftover[0] == 42)
}

var list = []string{
	"dns.google",
	"dns64.dns.google",
	"dns.google.com",
	"google-public-dns-a.google.com",
	"google-public-dns-b.google.com",
}

var domainTrie *patricia.Trie

func New() Tree {
	t := Tree{
		domainTrie: patricia.NewTrie(),
	}
	for _, domain := range list {
		reversedDomain := xstrings.Reverse(domain)
		t.domainTrie.Insert(patricia.Prefix(reversedDomain), 0)
	}
	return t
}
