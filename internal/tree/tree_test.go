package tree

import (
	"testing"
)

func TestTree_Match(t *testing.T) {
	tree := testTree(t)
	tests := []struct {
		name  string
		tree  Tree
		sni   string
		found bool
	}{
		{
			name:  "Not in list",
			tree:  tree,
			sni:   "www.startpage.com",
			found: false,
		},
		{
			name:  "Not in list empty",
			tree:  tree,
			sni:   "",
			found: false,
		},
		{
			name:  "Exact in list",
			tree:  tree,
			sni:   "dns.google",
			found: true,
		},
		{
			name:  "Wildcard in list",
			tree:  tree,
			sni:   "google.com",
			found: true,
		},
		{
			name:  "Exact in list after append",
			tree:  *tree.Append([]string{"github.com"}),
			sni:   "github.com",
			found: true,
		},
		{
			name:  "Wildcard in list after append",
			tree:  *tree.Append([]string{"*.github.com"}),
			sni:   "raw.github.com",
			found: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t1 *testing.T) {
			if found := tt.tree.Match(tt.sni); found != tt.found {
				t1.Errorf("Match(%s) = %v, want %v", tt.sni, found, tt.found)
			}
		})
	}
}

func testTree(t *testing.T) Tree {
	t.Helper()
	tree := New()
	tree.Append(list)
	return tree
}

var list = []string{
	"dns.google",
	"*.google.com",
	"dns.google.com",
}
