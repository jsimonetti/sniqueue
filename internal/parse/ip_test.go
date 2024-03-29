package parse

import (
	"net"
	"testing"

	"github.com/jsimonetti/sniqueue/internal/parse/tls"

	"github.com/google/go-cmp/cmp"
)

var result networkLayer

// from fib_test.go
func Benchmark_parse4(b *testing.B) {
	payload := []byte{
		0x45, 0x00, 0x01, 0x19, 0x00, 0x00, 0x40, 0x00,
		0x40, 0x06, 0x23, 0x3b, 0x0a, 0x0a, 0x01, 0x90,
		0x0a, 0x0a, 0x01, 0x01,

		0xfa, 0x73, 0x01, 0xbb, 0xe8, 0x87, 0x5c, 0x96,
		0x50, 0xdf, 0x80, 0x15, 0x80, 0x18, 0x08, 0x0a,
		0x26, 0x90, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a,
		0x05, 0xf7, 0x1a, 0x26, 0x0d, 0xdf, 0x62, 0x02,

		0x16, 0x03, 0x01, 0x00, 0xe0, 0x01, 0x00, 0x00,
		0xdc, 0x03, 0x03, 0x6b, 0x49, 0xe4, 0x9b, 0x42,
		0xb8, 0x4e, 0xee, 0x60, 0x25, 0x3e, 0xb1, 0x82,
		0x81, 0xeb, 0x82, 0xa3, 0xd2, 0x0b, 0x13, 0xc7,
		0x9e, 0x16, 0x79, 0x80, 0x41, 0x2f, 0x96, 0x46,
		0x11, 0x78, 0x9d, 0x00, 0x00, 0x5c, 0xc0, 0x30,
		0xc0, 0x2c, 0xc0, 0x28, 0xc0, 0x24, 0xc0, 0x14,
		0xc0, 0x0a, 0x00, 0x9f, 0x00, 0x6b, 0x00, 0x39,
		0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xff, 0x85,
		0x00, 0xc4, 0x00, 0x88, 0x00, 0x81, 0x00, 0x9d,
		0x00, 0x3d, 0x00, 0x35, 0x00, 0xc0, 0x00, 0x84,
		0xc0, 0x2f, 0xc0, 0x2b, 0xc0, 0x27, 0xc0, 0x23,
		0xc0, 0x13, 0xc0, 0x09, 0x00, 0x9e, 0x00, 0x67,
		0x00, 0x33, 0x00, 0xbe, 0x00, 0x45, 0x00, 0x9c,
		0x00, 0x3c, 0x00, 0x2f, 0x00, 0xba, 0x00, 0x41,
		0xc0, 0x11, 0xc0, 0x07, 0x00, 0x05, 0x00, 0x04,
		0xc0, 0x12, 0xc0, 0x08, 0x00, 0x16, 0x00, 0x0a,
		0x00, 0xff, 0x01, 0x00, 0x00, 0x57, 0x00, 0x00,
		0x00, 0x0f, 0x00, 0x0d, 0x00, 0x00, 0x0a, 0x64,
		0x6e, 0x73, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
		0x65, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00,
		0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00,
		0x17, 0x00, 0x18, 0x00, 0x0d, 0x00, 0x1c, 0x00,
		0x1a, 0x06, 0x01, 0x06, 0x03, 0xef, 0xef, 0x05,
		0x01, 0x05, 0x03, 0x04, 0x01, 0x04, 0x03, 0xee,
		0xee, 0xed, 0xed, 0x03, 0x01, 0x03, 0x03, 0x02,
		0x01, 0x02, 0x03, 0x00, 0x10, 0x00, 0x0e, 0x00,
		0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74,
		0x70, 0x2f, 0x31, 0x2e, 0x31,
	}
	packet := make([]byte, 1500)
	copy(packet, payload)
	// run the Parse function b.N times
	var got networkLayer
	for n := 0; n < b.N; n++ {
		got, _ = Parse(packet)
	}
	result = got
}

func Benchmark_parse6(b *testing.B) {
	payload := []byte{
		0x60, 0x0d, 0x05, 0x00, 0x05, 0x3a, 0x11, 0x40, // IPv6
		0x2a, 0x02, 0xa4, 0x5c, 0x19, 0xf4, 0x00, 0x10,
		0x8c, 0x72, 0x51, 0x8d, 0xfc, 0x5b, 0xd3, 0xd3,
		0x26, 0x04, 0x55, 0x00, 0x00, 0x03, 0x00, 0x0d,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d,

		0xce, 0x60, 0x01, 0xbb, 0x05, 0x3a, 0x11, 0xa3, // UDP

		0xc3, 0x00, 0x00, 0x00, 0x01, 0x08, 0xc3, 0xc3, // QUIC
		0xa5, 0x0f, 0xa4, 0x2a, 0xe0, 0x7d, 0x00, 0x00,
		0x45, 0x20, 0xd8, 0xff, 0xdf, 0xb7, 0x64, 0x5e,
		0x79, 0xb0, 0xe7, 0xf6, 0xd7, 0x89, 0x23, 0x86,
		0x43, 0xc4, 0x87, 0x12, 0x5e, 0xfb, 0xe7, 0x1c,
		0x3a, 0xf7, 0x8d, 0xb3, 0xc6, 0x4f, 0xc1, 0x9b,
		0xbc, 0x3f, 0x15, 0x60, 0xb9, 0x9d, 0x38, 0x4f,
		0x15, 0x5f, 0x98, 0xf3, 0x46, 0x57, 0xd9, 0x68,
		0x93, 0x8f, 0xda, 0x81, 0x80, 0x1b, 0xfd, 0x3f,
		0xbe, 0xd7, 0x2a, 0x0c, 0xbb, 0x0e, 0x58, 0x71,
		0xa9, 0x9b, 0x2f, 0x6a, 0x7a, 0xa4, 0x0e, 0xe4,
		0x84, 0x02, 0xae, 0x34, 0x51, 0xb3, 0x81, 0xfe,
		0x98, 0xd8, 0xd3, 0xb2, 0xe2, 0xd1, 0x46, 0x79,
		0xc0, 0x0e, 0x6a, 0xcc, 0x46, 0xe7, 0x36, 0xb9,
		0xf1, 0x25, 0xd2, 0x1b, 0x51, 0x1f, 0x39, 0x9e,
		0x43, 0xee, 0xa7, 0x9b, 0xe5, 0xfd, 0x7e, 0xf8,
		0x62, 0xf5, 0x86, 0x7f, 0x8e, 0x4c, 0xf8, 0x61,
		0x34, 0x48, 0x88, 0xd5, 0x55, 0x89, 0x1f, 0xe9,
		0x4d, 0xb0, 0xf8, 0xb5, 0x3c, 0x05, 0xf2, 0x9c,
		0xe9, 0x9b, 0x8c, 0x96, 0xd3, 0xc7, 0x45, 0x80,
		0xf5, 0xc1, 0x3d, 0x0d, 0x22, 0x68, 0x82, 0x87,
		0xbf, 0xc7, 0x64, 0x39, 0xf6, 0xf3, 0x51, 0x3a,
		0xb3, 0xfd, 0x98, 0x2f, 0xf1, 0x5f, 0x53, 0x6f,
		0xbb, 0x35, 0xec, 0x22, 0x37, 0xbd, 0x8d, 0x1a,
		0x3e, 0x3a, 0xab, 0x5f, 0x81, 0xa9, 0x0d, 0x03,
		0xdd, 0x0b, 0x3c, 0x5d, 0xf6, 0xf8, 0x35, 0x5d,
		0xd4, 0x91, 0x9c, 0x28, 0xc4, 0xb2, 0x49, 0x51,
		0x4a, 0xf0, 0x73, 0x3e, 0xc5, 0xcf, 0xe8, 0x16,
		0xe0, 0x75, 0xf6, 0xf4, 0xf8, 0xe4, 0xa5, 0x6b,
		0xcb, 0x7c, 0x4f, 0x7d, 0x2c, 0x9b, 0x22, 0x49,
		0xf8, 0x79, 0x4a, 0xc5, 0xd8, 0xe2, 0xe3, 0xff,
		0xa2, 0x75, 0x3a, 0x61, 0xea, 0x1e, 0xb8, 0x14,
		0x92, 0x11, 0x09, 0x4e, 0x35, 0x89, 0x07, 0x66,
		0x29, 0xdf, 0xce, 0xaa, 0xd6, 0x27, 0x5a, 0x5a,
		0xf2, 0x3b, 0xf0, 0x75, 0x7a, 0x47, 0x14, 0xa0,
		0x61, 0xf3, 0x78, 0x81, 0x60, 0x89, 0x8d, 0x31,
		0x64, 0xa4, 0x7c, 0x78, 0x0c, 0x90, 0x3b, 0xf0,
		0xbe, 0x47, 0xda, 0xe9, 0xab, 0x18, 0x89, 0xb1,
		0xb2, 0x6e, 0xc7, 0x9b, 0x01, 0x20, 0xe6, 0x21,
		0xda, 0x46, 0x1f, 0xef, 0x6c, 0x6c, 0x59, 0x67,
		0xb0, 0x88, 0x21, 0x00, 0xc8, 0x8e, 0x14, 0xe0,
		0x25, 0x92, 0x0d, 0xcb, 0x88, 0xe5, 0x91, 0xcf,
		0x9c, 0xd8, 0xc1, 0xc4, 0x58, 0xea, 0xa5, 0x40,
		0x5a, 0x5a, 0xf8, 0x46, 0x8f, 0x25, 0x0d, 0x86,
		0x22, 0x1c, 0xbc, 0xe8, 0x9d, 0x1b, 0x8b, 0xc6,
		0x43, 0xd3, 0x24, 0x40, 0x4d, 0x12, 0xa3, 0x4c,
		0x87, 0xa0, 0xa4, 0x2b, 0x94, 0x28, 0x42, 0x9e,
		0xc9, 0xc8, 0xec, 0x81, 0x6a, 0xb4, 0xe4, 0xd7,
		0xab, 0x25, 0xc3, 0x98, 0xa3, 0x8f, 0x65, 0x05,
		0x46, 0x4a, 0x29, 0x20, 0xb5, 0x20, 0x2a, 0xb3,
		0x2b, 0x71, 0x7e, 0x30, 0x79, 0x13, 0x52, 0xf1,
		0xb5, 0xf2, 0xa5, 0xf6, 0x7e, 0xcb, 0x56, 0x3a,
		0xbc, 0xa8, 0x44, 0xcc, 0x66, 0x4d, 0xa6, 0xfe,
		0x57, 0xd9, 0xaa, 0x65, 0x68, 0x44, 0x19, 0x1a,
		0xc1, 0x4f, 0x16, 0xc3, 0x68, 0x6e, 0xf0, 0x46,
		0xf2, 0x03, 0x24, 0x02, 0xcb, 0xbe, 0x13, 0x1f,
		0x3e, 0x2d, 0xcc, 0xe4, 0x3e, 0x0b, 0xf4, 0xb8,
		0x5f, 0x0a, 0x41, 0x16, 0x75, 0xd6, 0x01, 0x2f,
		0xaa, 0xb4, 0x27, 0x2d, 0xc7, 0xf2, 0x4a, 0x49,
		0xba, 0xe9, 0x35, 0x6d, 0x19, 0x5b, 0x46, 0x33,
		0xb6, 0x60, 0xe0, 0x51, 0x47, 0x42, 0x51, 0x5b,
		0x26, 0xc5, 0x7e, 0x11, 0x46, 0x82, 0x2f, 0xc7,
		0x26, 0x02, 0x2e, 0x71, 0x02, 0xfb, 0x34, 0xfc,
		0x9d, 0x86, 0xde, 0x99, 0xd1, 0xe0, 0xaf, 0x9a,
		0x3d, 0xd9, 0xcf, 0xf0, 0x80, 0x86, 0xa5, 0x75,
		0xc5, 0xf0, 0x1f, 0x4f, 0x2f, 0x33, 0x92, 0x0f,
		0x49, 0xd2, 0x98, 0xb4, 0xe2, 0x0d, 0x96, 0x38,
		0xbb, 0x65, 0x9b, 0x40, 0x11, 0xee, 0x1b, 0xe1,
		0xba, 0x48, 0x9a, 0x85, 0xee, 0xac, 0xee, 0xbe,
		0xf9, 0xb7, 0x33, 0x3a, 0xd4, 0xd4, 0xaf, 0xe8,
		0x2c, 0x67, 0x49, 0x6f, 0xf4, 0x12, 0xc9, 0x3c,
		0xb0, 0x7f, 0xbb, 0x79, 0x51, 0x7f, 0x3d, 0x64,
		0xbb, 0x13, 0xfb, 0x14, 0xc4, 0x87, 0x6d, 0x72,
		0x30, 0x35, 0x1f, 0x1c, 0xd9, 0x3b, 0xf9, 0xac,
		0xac, 0x0b, 0xae, 0xe8, 0x2c, 0xc9, 0xef, 0xbc,
		0x83, 0x5b, 0x4d, 0x74, 0xcb, 0x3e, 0xa1, 0x46,
		0xb2, 0xa8, 0x33, 0x5d, 0x8e, 0xa9, 0x2d, 0x99,
		0xef, 0x9d, 0x4f, 0x7d, 0xdc, 0xaf, 0x64, 0xec,
		0x9f, 0xc8, 0x5f, 0x48, 0x4e, 0xeb, 0xb9, 0x0a,
		0x77, 0x92, 0x95, 0x3d, 0x66, 0x55, 0x03, 0xd5,
		0xd4, 0xb1, 0xda, 0x9b, 0xd5, 0xbd, 0x5c, 0x64,
		0x9f, 0xac, 0x48, 0xa7, 0x01, 0x67, 0x8b, 0xfc,
		0x61, 0x4c, 0xef, 0xca, 0x0c, 0x9c, 0x79, 0xea,
		0x69, 0x3e, 0x0d, 0x21, 0xda, 0x83, 0xca, 0xc6,
		0x63, 0xe8, 0x45, 0xab, 0xcf, 0x08, 0xf4, 0xfd,
		0x1e, 0x4f, 0x10, 0x00, 0x68, 0x5f, 0x0a, 0xc1,
		0x09, 0xde, 0xc0, 0x53, 0x38, 0x0e, 0x0d, 0xa7,
		0xdf, 0x01, 0xcc, 0x38, 0x18, 0xc3, 0xd7, 0x25,
		0x22, 0x00, 0x7d, 0xff, 0x13, 0x19, 0x60, 0x98,
		0xb9, 0xab, 0x8e, 0xbd, 0x7d, 0x12, 0xf0, 0x7e,
		0x1c, 0x43, 0xde, 0xcf, 0x2e, 0x57, 0x75, 0x56,
		0xcc, 0xa9, 0xf5, 0xec, 0xbe, 0xe6, 0x95, 0x52,
		0x12, 0xcf, 0xcb, 0xac, 0xea, 0x5f, 0x3d, 0xd7,
		0x67, 0x97, 0x14, 0x0b, 0x16, 0xa8, 0xe2, 0x30,
		0x8e, 0xa4, 0xed, 0x26, 0x70, 0xb3, 0xff, 0x0b,
		0xd3, 0x63, 0xb3, 0xad, 0xab, 0xa5, 0xe4, 0x35,
		0xb2, 0x09, 0xca, 0x1a, 0x5c, 0x04, 0x5c, 0xc6,
		0xaf, 0x63, 0xad, 0x50, 0x43, 0xc9, 0xcf, 0xfa,
		0xf7, 0x45, 0x8c, 0x1f, 0xaf, 0xb4, 0x09, 0xc2,
		0x51, 0xc6, 0xd5, 0x59, 0xef, 0x97, 0xd6, 0xf4,
		0xbe, 0x2b, 0x92, 0xd5, 0x8e, 0x7e, 0xc7, 0x5a,
		0xf0, 0xea, 0x61, 0xc9, 0x07, 0x14, 0xeb, 0xff,
		0x7e, 0x00, 0x03, 0xf4, 0x9c, 0xb5, 0x5c, 0x85,
		0x10, 0x04, 0x0b, 0xf7, 0x69, 0x91, 0xbc, 0x58,
		0xb9, 0xeb, 0xb2, 0x32, 0xa9, 0x64, 0x2e, 0x59,
		0x56, 0xab, 0x2a, 0x9e, 0x26, 0x38, 0xc3, 0x02,
		0xf4, 0xa2, 0x5c, 0xdc, 0xff, 0x8a, 0x10, 0xe7,
		0xe9, 0xa4, 0xbf, 0xfc, 0xbf, 0xea, 0x56, 0x49,
		0xcd, 0x44, 0xf2, 0xa2, 0x28, 0xcf, 0x45, 0x73,
		0xbd, 0x4a, 0x5c, 0x79, 0x66, 0xf5, 0x5a, 0x2a,
		0xcc, 0x38, 0x9f, 0xbd, 0x8e, 0x61, 0x2f, 0xfc,
		0xfc, 0x8b, 0x68, 0xf4, 0x80, 0x42, 0x6f, 0x61,
		0x9b, 0x72, 0x44, 0x99, 0x23, 0x89, 0xaf, 0xec,
		0x52, 0x3b, 0x8e, 0x8c, 0x21, 0xfa, 0x8e, 0x24,
		0x37, 0xbd, 0x27, 0xfa, 0xc7, 0x43, 0xa3, 0xce,
		0x15, 0x07, 0xd7, 0xa2, 0x07, 0x56, 0xdc, 0x68,
		0x4e, 0x62, 0x3a, 0x76, 0x97, 0x3c, 0x0d, 0xf7,
		0x1c, 0xcb, 0x12, 0x6e, 0xcf, 0xcc, 0x70, 0x17,
		0x93, 0xc8, 0x88, 0xdd, 0x45, 0x22, 0xc3, 0x19,
		0xe0, 0x19, 0xb3, 0xa2, 0xc5, 0x29, 0x84, 0x51,
		0x38, 0x6c, 0x73, 0xf7, 0x31, 0x76, 0xaf, 0xc0,
		0xd6, 0x8b, 0x13, 0x8a, 0x82, 0x10, 0x70, 0x7e,
		0xef, 0xc0, 0xe8, 0xfc, 0xc8, 0x84, 0x38, 0x65,
		0x1d, 0x57, 0x45, 0x63, 0xf5, 0xc8, 0xfd, 0x15,
		0x23, 0x54, 0xca, 0x82, 0x5b, 0x25, 0x22, 0x61,
		0x85, 0xcb, 0xfa, 0xab, 0x1a, 0x76, 0xed, 0xd5,
		0x27, 0xf0, 0x13, 0x6c, 0x49, 0x35, 0x83, 0xf2,
		0x3b, 0xf4, 0xbf, 0xa5, 0xef, 0x33, 0xaf, 0xbd,
		0xb5, 0x31, 0x92, 0x01, 0xd7, 0x96, 0x16, 0x81,
		0x2d, 0x8c, 0x0d, 0x1f, 0x06, 0xba, 0xdd, 0xa4,
		0x84, 0x14, 0x65, 0x92, 0x30, 0xbb, 0x7c, 0x9e,
		0x82, 0x8a, 0x4a, 0xf7, 0xea, 0x8f, 0x40, 0x5e,
		0xd4, 0xdf, 0x66, 0xb2, 0xda, 0xd7, 0x23, 0x95,
		0x8c, 0x48, 0x8c, 0xb1, 0x9c, 0xb6, 0x71, 0x26,
		0xb9, 0xa4, 0x7f, 0xb4, 0x68, 0x60, 0x8f, 0x03,
		0x8e, 0x5d, 0x4a, 0x75, 0xd4, 0x65, 0x46, 0xf8,
		0xef, 0xf8, 0xbd, 0x7e, 0x61, 0xcb, 0x30, 0x5d,
		0xb2, 0xba, 0x86, 0xe2, 0xda, 0xf4, 0x62, 0x97,
		0x83, 0x15, 0xa2, 0xa5, 0x44, 0xf5, 0x51, 0xb5,
		0x08, 0x0b, 0xaf, 0x68, 0xe4, 0x06, 0x31, 0x3e,
		0x25, 0x28, 0x00, 0x46, 0x17, 0x5f, 0xf1, 0xe5,
		0xac, 0x6f, 0xed, 0xc7, 0x7e, 0xcc, 0xa6, 0x4f,
		0xac, 0x60, 0x3a, 0x8b, 0x90, 0x9a, 0x40, 0x4c,
		0x0d, 0xe7, 0xea, 0xa5, 0xb9, 0x25, 0x25, 0x5c,
		0xc3, 0x3b, 0xe3, 0x7a, 0x3d, 0x2d, 0xfc, 0xc9,
		0x50, 0x11, 0x7b, 0x0e, 0xe7, 0x66, 0x35, 0xaf,
		0x4b, 0x53, 0xbd, 0x9c, 0x18, 0x97, 0xd5, 0x37,
		0x95, 0x51, 0x75, 0xb0, 0xa3, 0x15, 0xc0, 0xed,
		0xe8, 0xdb, 0x7f, 0xa9, 0x7e, 0x68, 0x4a, 0xcf,
		0x5f, 0x57, 0x0f, 0xc6, 0x97, 0xab, 0xad, 0x0c,
		0x3f, 0x3b, 0x5e, 0xc7, 0x45, 0x97, 0xa6, 0xf9,
		0x98, 0xde, 0x78, 0x2a, 0x15, 0xf0, 0x9e, 0xdd,
		0x0c, 0xc7, 0x2b, 0x32, 0x11, 0x59, 0xf5, 0xe5,
		0x50, 0xb8, 0x3b, 0xc5, 0x8e, 0x39, 0x09, 0x6b,
		0xfa, 0x89, 0x07, 0x85, 0xd9, 0xaa, 0x7b, 0x75,
		0xc3, 0xe3, 0x40, 0x44, 0x68, 0xc5, 0x87, 0x0b,
		0xc2, 0xda, 0xe9, 0x87, 0x3f, 0x29, 0xf7, 0xed,
		0xdc, 0x61, 0xb4, 0x7d, 0x1a, 0x23, 0x70, 0x55,
		0x7d, 0xbf, 0xb5, 0x61, 0x26, 0x44, 0x3d, 0xea,
		0xb6, 0xe1, 0xc7, 0xed, 0x6b, 0x58, 0x3b, 0xd5,
		0x59, 0x56, 0x6d, 0x47, 0xe3, 0x01, 0xb9, 0xe1,
		0xf0, 0xdc, 0x9a, 0xdf, 0x16, 0x81, 0x62, 0xff,
		0x3e, 0x8a, 0xef, 0x28, 0xd6, 0x0c, 0x85, 0x49,
		0x5b, 0x52, 0xcc, 0x48, 0x8c, 0x2a, 0x2e, 0x9c,
		0x28, 0xf5, 0x1f, 0xcc, 0x24, 0xf7, 0xa3, 0xd8,
		0x4b, 0x43, 0x28, 0x90, 0x59, 0x17, 0x4a, 0xfe,
		0x56, 0x8b,
	}
	packet := make([]byte, 1500)
	copy(packet, payload)
	// run the Parse function b.N times
	var got networkLayer
	for n := 0; n < b.N; n++ {
		got, _ = Parse(packet)
	}
	result = got
}

func Test_parse(t *testing.T) {

	tests := []struct {
		name    string
		want    networkLayer
		payload []byte
		wantErr bool
	}{
		{
			name:    "Empty packet",
			payload: []byte{},
			wantErr: true,
		},
		{
			name: "IPv4 packet",
			want: &IPv4{
				Inet: Inet{
					IPVersion:      4,
					IPHeaderLength: 5,
					Length:         281,
					Protocol:       6,
					Source:         net.IP{0xa, 0xa, 0x1, 0x90},
					Destination:    net.IP{0xa, 0xa, 0x1, 0x1},
					Transport: &TCP{
						SourcePort:      64115,
						DestinationPort: 443,
						Hello:           tls.ClientHello{SNI: "dns.google"},
					},
				},
			},
			payload: []byte{
				0x45, 0x00, 0x01, 0x19, 0x00, 0x00, 0x40, 0x00,
				0x40, 0x06, 0x23, 0x3b, 0x0a, 0x0a, 0x01, 0x90,
				0x0a, 0x0a, 0x01, 0x01,

				0xfa, 0x73, 0x01, 0xbb, 0xe8, 0x87, 0x5c, 0x96,
				0x50, 0xdf, 0x80, 0x15, 0x80, 0x18, 0x08, 0x0a,
				0x26, 0x90, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a,
				0x05, 0xf7, 0x1a, 0x26, 0x0d, 0xdf, 0x62, 0x02,

				0x16, 0x03, 0x01, 0x00, 0xe0, 0x01, 0x00, 0x00,
				0xdc, 0x03, 0x03, 0x6b, 0x49, 0xe4, 0x9b, 0x42,
				0xb8, 0x4e, 0xee, 0x60, 0x25, 0x3e, 0xb1, 0x82,
				0x81, 0xeb, 0x82, 0xa3, 0xd2, 0x0b, 0x13, 0xc7,
				0x9e, 0x16, 0x79, 0x80, 0x41, 0x2f, 0x96, 0x46,
				0x11, 0x78, 0x9d, 0x00, 0x00, 0x5c, 0xc0, 0x30,
				0xc0, 0x2c, 0xc0, 0x28, 0xc0, 0x24, 0xc0, 0x14,
				0xc0, 0x0a, 0x00, 0x9f, 0x00, 0x6b, 0x00, 0x39,
				0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xff, 0x85,
				0x00, 0xc4, 0x00, 0x88, 0x00, 0x81, 0x00, 0x9d,
				0x00, 0x3d, 0x00, 0x35, 0x00, 0xc0, 0x00, 0x84,
				0xc0, 0x2f, 0xc0, 0x2b, 0xc0, 0x27, 0xc0, 0x23,
				0xc0, 0x13, 0xc0, 0x09, 0x00, 0x9e, 0x00, 0x67,
				0x00, 0x33, 0x00, 0xbe, 0x00, 0x45, 0x00, 0x9c,
				0x00, 0x3c, 0x00, 0x2f, 0x00, 0xba, 0x00, 0x41,
				0xc0, 0x11, 0xc0, 0x07, 0x00, 0x05, 0x00, 0x04,
				0xc0, 0x12, 0xc0, 0x08, 0x00, 0x16, 0x00, 0x0a,
				0x00, 0xff, 0x01, 0x00, 0x00, 0x57, 0x00, 0x00,
				0x00, 0x0f, 0x00, 0x0d, 0x00, 0x00, 0x0a, 0x64,
				0x6e, 0x73, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
				0x65, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00,
				0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00,
				0x17, 0x00, 0x18, 0x00, 0x0d, 0x00, 0x1c, 0x00,
				0x1a, 0x06, 0x01, 0x06, 0x03, 0xef, 0xef, 0x05,
				0x01, 0x05, 0x03, 0x04, 0x01, 0x04, 0x03, 0xee,
				0xee, 0xed, 0xed, 0x03, 0x01, 0x03, 0x03, 0x02,
				0x01, 0x02, 0x03, 0x00, 0x10, 0x00, 0x0e, 0x00,
				0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74,
				0x70, 0x2f, 0x31, 0x2e, 0x31,
			},
			wantErr: false,
		},
		{
			name: "IPv6 QUIC",
			want: &IPv6{
				Inet: Inet{
					IPVersion:      6,
					IPHeaderLength: 0,
					Length:         1338,
					Protocol:       17,
					Source:         net.ParseIP("2a02:a45c:19f4:10:8c72:518d:fc5b:d3d3"),
					Destination:    net.ParseIP("2604:5500:3:d::d"),
					Transport: &UDP{
						SourcePort:      52832,
						DestinationPort: 443,
						Hello:           tls.ClientHello{SNI: "r2---sn-fxc25nn-nwje.googlevideo.com"},
					},
				},
			},
			payload: []byte{
				0x60, 0x0d, 0x05, 0x00, 0x05, 0x3a, 0x11, 0x40, // IPv6
				0x2a, 0x02, 0xa4, 0x5c, 0x19, 0xf4, 0x00, 0x10,
				0x8c, 0x72, 0x51, 0x8d, 0xfc, 0x5b, 0xd3, 0xd3,
				0x26, 0x04, 0x55, 0x00, 0x00, 0x03, 0x00, 0x0d,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d,

				0xce, 0x60, 0x01, 0xbb, 0x05, 0x3a, 0x11, 0xa3, // UDP

				0xc3, 0x00, 0x00, 0x00, 0x01, 0x08, 0xc3, 0xc3, // QUIC
				0xa5, 0x0f, 0xa4, 0x2a, 0xe0, 0x7d, 0x00, 0x00,
				0x45, 0x20, 0xd8, 0xff, 0xdf, 0xb7, 0x64, 0x5e,
				0x79, 0xb0, 0xe7, 0xf6, 0xd7, 0x89, 0x23, 0x86,
				0x43, 0xc4, 0x87, 0x12, 0x5e, 0xfb, 0xe7, 0x1c,
				0x3a, 0xf7, 0x8d, 0xb3, 0xc6, 0x4f, 0xc1, 0x9b,
				0xbc, 0x3f, 0x15, 0x60, 0xb9, 0x9d, 0x38, 0x4f,
				0x15, 0x5f, 0x98, 0xf3, 0x46, 0x57, 0xd9, 0x68,
				0x93, 0x8f, 0xda, 0x81, 0x80, 0x1b, 0xfd, 0x3f,
				0xbe, 0xd7, 0x2a, 0x0c, 0xbb, 0x0e, 0x58, 0x71,
				0xa9, 0x9b, 0x2f, 0x6a, 0x7a, 0xa4, 0x0e, 0xe4,
				0x84, 0x02, 0xae, 0x34, 0x51, 0xb3, 0x81, 0xfe,
				0x98, 0xd8, 0xd3, 0xb2, 0xe2, 0xd1, 0x46, 0x79,
				0xc0, 0x0e, 0x6a, 0xcc, 0x46, 0xe7, 0x36, 0xb9,
				0xf1, 0x25, 0xd2, 0x1b, 0x51, 0x1f, 0x39, 0x9e,
				0x43, 0xee, 0xa7, 0x9b, 0xe5, 0xfd, 0x7e, 0xf8,
				0x62, 0xf5, 0x86, 0x7f, 0x8e, 0x4c, 0xf8, 0x61,
				0x34, 0x48, 0x88, 0xd5, 0x55, 0x89, 0x1f, 0xe9,
				0x4d, 0xb0, 0xf8, 0xb5, 0x3c, 0x05, 0xf2, 0x9c,
				0xe9, 0x9b, 0x8c, 0x96, 0xd3, 0xc7, 0x45, 0x80,
				0xf5, 0xc1, 0x3d, 0x0d, 0x22, 0x68, 0x82, 0x87,
				0xbf, 0xc7, 0x64, 0x39, 0xf6, 0xf3, 0x51, 0x3a,
				0xb3, 0xfd, 0x98, 0x2f, 0xf1, 0x5f, 0x53, 0x6f,
				0xbb, 0x35, 0xec, 0x22, 0x37, 0xbd, 0x8d, 0x1a,
				0x3e, 0x3a, 0xab, 0x5f, 0x81, 0xa9, 0x0d, 0x03,
				0xdd, 0x0b, 0x3c, 0x5d, 0xf6, 0xf8, 0x35, 0x5d,
				0xd4, 0x91, 0x9c, 0x28, 0xc4, 0xb2, 0x49, 0x51,
				0x4a, 0xf0, 0x73, 0x3e, 0xc5, 0xcf, 0xe8, 0x16,
				0xe0, 0x75, 0xf6, 0xf4, 0xf8, 0xe4, 0xa5, 0x6b,
				0xcb, 0x7c, 0x4f, 0x7d, 0x2c, 0x9b, 0x22, 0x49,
				0xf8, 0x79, 0x4a, 0xc5, 0xd8, 0xe2, 0xe3, 0xff,
				0xa2, 0x75, 0x3a, 0x61, 0xea, 0x1e, 0xb8, 0x14,
				0x92, 0x11, 0x09, 0x4e, 0x35, 0x89, 0x07, 0x66,
				0x29, 0xdf, 0xce, 0xaa, 0xd6, 0x27, 0x5a, 0x5a,
				0xf2, 0x3b, 0xf0, 0x75, 0x7a, 0x47, 0x14, 0xa0,
				0x61, 0xf3, 0x78, 0x81, 0x60, 0x89, 0x8d, 0x31,
				0x64, 0xa4, 0x7c, 0x78, 0x0c, 0x90, 0x3b, 0xf0,
				0xbe, 0x47, 0xda, 0xe9, 0xab, 0x18, 0x89, 0xb1,
				0xb2, 0x6e, 0xc7, 0x9b, 0x01, 0x20, 0xe6, 0x21,
				0xda, 0x46, 0x1f, 0xef, 0x6c, 0x6c, 0x59, 0x67,
				0xb0, 0x88, 0x21, 0x00, 0xc8, 0x8e, 0x14, 0xe0,
				0x25, 0x92, 0x0d, 0xcb, 0x88, 0xe5, 0x91, 0xcf,
				0x9c, 0xd8, 0xc1, 0xc4, 0x58, 0xea, 0xa5, 0x40,
				0x5a, 0x5a, 0xf8, 0x46, 0x8f, 0x25, 0x0d, 0x86,
				0x22, 0x1c, 0xbc, 0xe8, 0x9d, 0x1b, 0x8b, 0xc6,
				0x43, 0xd3, 0x24, 0x40, 0x4d, 0x12, 0xa3, 0x4c,
				0x87, 0xa0, 0xa4, 0x2b, 0x94, 0x28, 0x42, 0x9e,
				0xc9, 0xc8, 0xec, 0x81, 0x6a, 0xb4, 0xe4, 0xd7,
				0xab, 0x25, 0xc3, 0x98, 0xa3, 0x8f, 0x65, 0x05,
				0x46, 0x4a, 0x29, 0x20, 0xb5, 0x20, 0x2a, 0xb3,
				0x2b, 0x71, 0x7e, 0x30, 0x79, 0x13, 0x52, 0xf1,
				0xb5, 0xf2, 0xa5, 0xf6, 0x7e, 0xcb, 0x56, 0x3a,
				0xbc, 0xa8, 0x44, 0xcc, 0x66, 0x4d, 0xa6, 0xfe,
				0x57, 0xd9, 0xaa, 0x65, 0x68, 0x44, 0x19, 0x1a,
				0xc1, 0x4f, 0x16, 0xc3, 0x68, 0x6e, 0xf0, 0x46,
				0xf2, 0x03, 0x24, 0x02, 0xcb, 0xbe, 0x13, 0x1f,
				0x3e, 0x2d, 0xcc, 0xe4, 0x3e, 0x0b, 0xf4, 0xb8,
				0x5f, 0x0a, 0x41, 0x16, 0x75, 0xd6, 0x01, 0x2f,
				0xaa, 0xb4, 0x27, 0x2d, 0xc7, 0xf2, 0x4a, 0x49,
				0xba, 0xe9, 0x35, 0x6d, 0x19, 0x5b, 0x46, 0x33,
				0xb6, 0x60, 0xe0, 0x51, 0x47, 0x42, 0x51, 0x5b,
				0x26, 0xc5, 0x7e, 0x11, 0x46, 0x82, 0x2f, 0xc7,
				0x26, 0x02, 0x2e, 0x71, 0x02, 0xfb, 0x34, 0xfc,
				0x9d, 0x86, 0xde, 0x99, 0xd1, 0xe0, 0xaf, 0x9a,
				0x3d, 0xd9, 0xcf, 0xf0, 0x80, 0x86, 0xa5, 0x75,
				0xc5, 0xf0, 0x1f, 0x4f, 0x2f, 0x33, 0x92, 0x0f,
				0x49, 0xd2, 0x98, 0xb4, 0xe2, 0x0d, 0x96, 0x38,
				0xbb, 0x65, 0x9b, 0x40, 0x11, 0xee, 0x1b, 0xe1,
				0xba, 0x48, 0x9a, 0x85, 0xee, 0xac, 0xee, 0xbe,
				0xf9, 0xb7, 0x33, 0x3a, 0xd4, 0xd4, 0xaf, 0xe8,
				0x2c, 0x67, 0x49, 0x6f, 0xf4, 0x12, 0xc9, 0x3c,
				0xb0, 0x7f, 0xbb, 0x79, 0x51, 0x7f, 0x3d, 0x64,
				0xbb, 0x13, 0xfb, 0x14, 0xc4, 0x87, 0x6d, 0x72,
				0x30, 0x35, 0x1f, 0x1c, 0xd9, 0x3b, 0xf9, 0xac,
				0xac, 0x0b, 0xae, 0xe8, 0x2c, 0xc9, 0xef, 0xbc,
				0x83, 0x5b, 0x4d, 0x74, 0xcb, 0x3e, 0xa1, 0x46,
				0xb2, 0xa8, 0x33, 0x5d, 0x8e, 0xa9, 0x2d, 0x99,
				0xef, 0x9d, 0x4f, 0x7d, 0xdc, 0xaf, 0x64, 0xec,
				0x9f, 0xc8, 0x5f, 0x48, 0x4e, 0xeb, 0xb9, 0x0a,
				0x77, 0x92, 0x95, 0x3d, 0x66, 0x55, 0x03, 0xd5,
				0xd4, 0xb1, 0xda, 0x9b, 0xd5, 0xbd, 0x5c, 0x64,
				0x9f, 0xac, 0x48, 0xa7, 0x01, 0x67, 0x8b, 0xfc,
				0x61, 0x4c, 0xef, 0xca, 0x0c, 0x9c, 0x79, 0xea,
				0x69, 0x3e, 0x0d, 0x21, 0xda, 0x83, 0xca, 0xc6,
				0x63, 0xe8, 0x45, 0xab, 0xcf, 0x08, 0xf4, 0xfd,
				0x1e, 0x4f, 0x10, 0x00, 0x68, 0x5f, 0x0a, 0xc1,
				0x09, 0xde, 0xc0, 0x53, 0x38, 0x0e, 0x0d, 0xa7,
				0xdf, 0x01, 0xcc, 0x38, 0x18, 0xc3, 0xd7, 0x25,
				0x22, 0x00, 0x7d, 0xff, 0x13, 0x19, 0x60, 0x98,
				0xb9, 0xab, 0x8e, 0xbd, 0x7d, 0x12, 0xf0, 0x7e,
				0x1c, 0x43, 0xde, 0xcf, 0x2e, 0x57, 0x75, 0x56,
				0xcc, 0xa9, 0xf5, 0xec, 0xbe, 0xe6, 0x95, 0x52,
				0x12, 0xcf, 0xcb, 0xac, 0xea, 0x5f, 0x3d, 0xd7,
				0x67, 0x97, 0x14, 0x0b, 0x16, 0xa8, 0xe2, 0x30,
				0x8e, 0xa4, 0xed, 0x26, 0x70, 0xb3, 0xff, 0x0b,
				0xd3, 0x63, 0xb3, 0xad, 0xab, 0xa5, 0xe4, 0x35,
				0xb2, 0x09, 0xca, 0x1a, 0x5c, 0x04, 0x5c, 0xc6,
				0xaf, 0x63, 0xad, 0x50, 0x43, 0xc9, 0xcf, 0xfa,
				0xf7, 0x45, 0x8c, 0x1f, 0xaf, 0xb4, 0x09, 0xc2,
				0x51, 0xc6, 0xd5, 0x59, 0xef, 0x97, 0xd6, 0xf4,
				0xbe, 0x2b, 0x92, 0xd5, 0x8e, 0x7e, 0xc7, 0x5a,
				0xf0, 0xea, 0x61, 0xc9, 0x07, 0x14, 0xeb, 0xff,
				0x7e, 0x00, 0x03, 0xf4, 0x9c, 0xb5, 0x5c, 0x85,
				0x10, 0x04, 0x0b, 0xf7, 0x69, 0x91, 0xbc, 0x58,
				0xb9, 0xeb, 0xb2, 0x32, 0xa9, 0x64, 0x2e, 0x59,
				0x56, 0xab, 0x2a, 0x9e, 0x26, 0x38, 0xc3, 0x02,
				0xf4, 0xa2, 0x5c, 0xdc, 0xff, 0x8a, 0x10, 0xe7,
				0xe9, 0xa4, 0xbf, 0xfc, 0xbf, 0xea, 0x56, 0x49,
				0xcd, 0x44, 0xf2, 0xa2, 0x28, 0xcf, 0x45, 0x73,
				0xbd, 0x4a, 0x5c, 0x79, 0x66, 0xf5, 0x5a, 0x2a,
				0xcc, 0x38, 0x9f, 0xbd, 0x8e, 0x61, 0x2f, 0xfc,
				0xfc, 0x8b, 0x68, 0xf4, 0x80, 0x42, 0x6f, 0x61,
				0x9b, 0x72, 0x44, 0x99, 0x23, 0x89, 0xaf, 0xec,
				0x52, 0x3b, 0x8e, 0x8c, 0x21, 0xfa, 0x8e, 0x24,
				0x37, 0xbd, 0x27, 0xfa, 0xc7, 0x43, 0xa3, 0xce,
				0x15, 0x07, 0xd7, 0xa2, 0x07, 0x56, 0xdc, 0x68,
				0x4e, 0x62, 0x3a, 0x76, 0x97, 0x3c, 0x0d, 0xf7,
				0x1c, 0xcb, 0x12, 0x6e, 0xcf, 0xcc, 0x70, 0x17,
				0x93, 0xc8, 0x88, 0xdd, 0x45, 0x22, 0xc3, 0x19,
				0xe0, 0x19, 0xb3, 0xa2, 0xc5, 0x29, 0x84, 0x51,
				0x38, 0x6c, 0x73, 0xf7, 0x31, 0x76, 0xaf, 0xc0,
				0xd6, 0x8b, 0x13, 0x8a, 0x82, 0x10, 0x70, 0x7e,
				0xef, 0xc0, 0xe8, 0xfc, 0xc8, 0x84, 0x38, 0x65,
				0x1d, 0x57, 0x45, 0x63, 0xf5, 0xc8, 0xfd, 0x15,
				0x23, 0x54, 0xca, 0x82, 0x5b, 0x25, 0x22, 0x61,
				0x85, 0xcb, 0xfa, 0xab, 0x1a, 0x76, 0xed, 0xd5,
				0x27, 0xf0, 0x13, 0x6c, 0x49, 0x35, 0x83, 0xf2,
				0x3b, 0xf4, 0xbf, 0xa5, 0xef, 0x33, 0xaf, 0xbd,
				0xb5, 0x31, 0x92, 0x01, 0xd7, 0x96, 0x16, 0x81,
				0x2d, 0x8c, 0x0d, 0x1f, 0x06, 0xba, 0xdd, 0xa4,
				0x84, 0x14, 0x65, 0x92, 0x30, 0xbb, 0x7c, 0x9e,
				0x82, 0x8a, 0x4a, 0xf7, 0xea, 0x8f, 0x40, 0x5e,
				0xd4, 0xdf, 0x66, 0xb2, 0xda, 0xd7, 0x23, 0x95,
				0x8c, 0x48, 0x8c, 0xb1, 0x9c, 0xb6, 0x71, 0x26,
				0xb9, 0xa4, 0x7f, 0xb4, 0x68, 0x60, 0x8f, 0x03,
				0x8e, 0x5d, 0x4a, 0x75, 0xd4, 0x65, 0x46, 0xf8,
				0xef, 0xf8, 0xbd, 0x7e, 0x61, 0xcb, 0x30, 0x5d,
				0xb2, 0xba, 0x86, 0xe2, 0xda, 0xf4, 0x62, 0x97,
				0x83, 0x15, 0xa2, 0xa5, 0x44, 0xf5, 0x51, 0xb5,
				0x08, 0x0b, 0xaf, 0x68, 0xe4, 0x06, 0x31, 0x3e,
				0x25, 0x28, 0x00, 0x46, 0x17, 0x5f, 0xf1, 0xe5,
				0xac, 0x6f, 0xed, 0xc7, 0x7e, 0xcc, 0xa6, 0x4f,
				0xac, 0x60, 0x3a, 0x8b, 0x90, 0x9a, 0x40, 0x4c,
				0x0d, 0xe7, 0xea, 0xa5, 0xb9, 0x25, 0x25, 0x5c,
				0xc3, 0x3b, 0xe3, 0x7a, 0x3d, 0x2d, 0xfc, 0xc9,
				0x50, 0x11, 0x7b, 0x0e, 0xe7, 0x66, 0x35, 0xaf,
				0x4b, 0x53, 0xbd, 0x9c, 0x18, 0x97, 0xd5, 0x37,
				0x95, 0x51, 0x75, 0xb0, 0xa3, 0x15, 0xc0, 0xed,
				0xe8, 0xdb, 0x7f, 0xa9, 0x7e, 0x68, 0x4a, 0xcf,
				0x5f, 0x57, 0x0f, 0xc6, 0x97, 0xab, 0xad, 0x0c,
				0x3f, 0x3b, 0x5e, 0xc7, 0x45, 0x97, 0xa6, 0xf9,
				0x98, 0xde, 0x78, 0x2a, 0x15, 0xf0, 0x9e, 0xdd,
				0x0c, 0xc7, 0x2b, 0x32, 0x11, 0x59, 0xf5, 0xe5,
				0x50, 0xb8, 0x3b, 0xc5, 0x8e, 0x39, 0x09, 0x6b,
				0xfa, 0x89, 0x07, 0x85, 0xd9, 0xaa, 0x7b, 0x75,
				0xc3, 0xe3, 0x40, 0x44, 0x68, 0xc5, 0x87, 0x0b,
				0xc2, 0xda, 0xe9, 0x87, 0x3f, 0x29, 0xf7, 0xed,
				0xdc, 0x61, 0xb4, 0x7d, 0x1a, 0x23, 0x70, 0x55,
				0x7d, 0xbf, 0xb5, 0x61, 0x26, 0x44, 0x3d, 0xea,
				0xb6, 0xe1, 0xc7, 0xed, 0x6b, 0x58, 0x3b, 0xd5,
				0x59, 0x56, 0x6d, 0x47, 0xe3, 0x01, 0xb9, 0xe1,
				0xf0, 0xdc, 0x9a, 0xdf, 0x16, 0x81, 0x62, 0xff,
				0x3e, 0x8a, 0xef, 0x28, 0xd6, 0x0c, 0x85, 0x49,
				0x5b, 0x52, 0xcc, 0x48, 0x8c, 0x2a, 0x2e, 0x9c,
				0x28, 0xf5, 0x1f, 0xcc, 0x24, 0xf7, 0xa3, 0xd8,
				0x4b, 0x43, 0x28, 0x90, 0x59, 0x17, 0x4a, 0xfe,
				0x56, 0x8b,
			},
			wantErr: true, // to skip quic for now
		},
		{
			name:    "IPv4 SYN",
			wantErr: true,
			payload: []byte{
				0x45, 0x00, 0x00, 0x3c, 0x14, 0xd6, 0x40, 0x00,
				0x3f, 0x06, 0x53, 0x28, 0x0a, 0x0a, 0x01, 0x0a,
				0xc0, 0xa8, 0x08, 0x02,

				0xe0, 0x2c, 0x01, 0xbb, 0x2e, 0xfd, 0x89, 0x0d,
				0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0xfa, 0xf0,
				0xc9, 0xb2, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4,
				0x04, 0x02, 0x08, 0x0a, 0x8d, 0x98, 0x88, 0x14,

				0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x06,
			},
		},
		{
			name:    "IPv4 SYN/ACK",
			wantErr: true,
			payload: []byte{
				0x45, 0x00, 0x00, 0x34, 0x14, 0xd7, 0x40, 0x00,
				0x3f, 0x06, 0x53, 0x2f, 0x0a, 0x0a, 0x01, 0x0a,
				0xc0, 0xa8, 0x08, 0x02,

				0xe0, 0x2c, 0x01, 0xbb, 0x2e, 0xfd, 0x89, 0x0e,
				0xdf, 0xfa, 0x87, 0x25, 0x80, 0x10, 0x03, 0xec,
				0x8f, 0x77, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a,
				0x8d, 0x98, 0x88, 0x1d, 0xa9, 0x93, 0x4f, 0x3e,
			},
		},
		{
			name: "IPv4 FIN",
			payload: []byte{
				0x45, 0x00, 0x00, 0x34, 0x14, 0xe5, 0x40, 0x00,
				0x3f, 0x06, 0x53, 0x21, 0x0a, 0x0a, 0x01, 0x0a,
				0xc0, 0xa8, 0x08, 0x02,

				0xe0, 0x2c, 0x01, 0xbb, 0x2e, 0xfd, 0x8c, 0x58,
				0xdf, 0xfa, 0x91, 0xd2, 0x80, 0x10, 0x03, 0xea,
				0x80, 0x64, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a,
				0x8d, 0x98, 0x88, 0xac, 0xa9, 0x93, 0x4f, 0xcd,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got networkLayer
			var err error
			if got, err = Parse(tt.payload); err != nil {
				if tt.wantErr {
					return
				}
				t.Errorf("parse() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}
