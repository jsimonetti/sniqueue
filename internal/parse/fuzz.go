//go:build gofuzz
// +build gofuzz

package parse

// FuzzParse will fuzz the packet parser
func FuzzParse(data []byte) int {
	if _, err := Parse(data); err != nil {
		return 0
	}

	return 1
}
