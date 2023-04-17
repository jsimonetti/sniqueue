package quic

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParseHeader(t *testing.T) {
	tests := []struct {
		name    string
		b       *bytes.Reader
		want    *Header
		wantErr bool
	}{
		{
			name: "Draft27 Facebook",
			b: bytes.NewReader([]byte{
				0xc6, 0xfa, 0xce, 0xb0, 0x02, 0x08, 0x4a, 0xaf, 0x2d, 0x9e, 0xdd, 0xac, 0x80, 0x59, 0x00, 0x00,
				0x44, 0xbe, 0x9d, 0x71, 0x8b, 0xa7, 0x87, 0xb4, 0x29, 0x41, 0x49, 0x5b, 0x61, 0x9d, 0xef, 0xec,
				0x2f, 0x8b, 0x23, 0x8e, 0x2b, 0xba, 0x22, 0x1c, 0x43, 0x24, 0x61, 0xaf, 0x1f, 0x3a, 0x0f, 0x47,
				0xa0, 0x44, 0xea, 0x3a, 0x5f, 0x7c, 0x09, 0xbe, 0x80, 0x5f, 0xdf, 0x7c, 0xe8, 0x7a, 0xd1, 0x3c,
				0x61, 0xc1, 0x71, 0x3f, 0x7b, 0x01, 0x27, 0x7b, 0x7c, 0x83, 0xc0, 0x12, 0xeb, 0x62, 0xae, 0x51,
				0x64, 0x08, 0xb0, 0x7b, 0x14, 0xe9, 0x52, 0x2c, 0x1c, 0x0d, 0x5d, 0x21, 0x8f, 0xcc, 0x2e, 0xff,
				0x7c, 0xf0, 0x89, 0x78, 0xbe, 0x54, 0x89, 0xf3, 0x13, 0x9d, 0x1b, 0xb1, 0x22, 0xba, 0x04, 0xc3,
				0x47, 0xcb, 0xd3, 0xbb, 0x99, 0x0c, 0x3d, 0x1b, 0xfd, 0xae, 0x3d, 0x44, 0x30, 0x92, 0x4a, 0xce,
				0x96, 0x20, 0x7e, 0x35, 0x6e, 0x25, 0x07, 0x7e, 0x34, 0x93, 0xcb, 0xb0, 0xde, 0x4a, 0xf1, 0xf2,
				0xdf, 0xd6, 0x99, 0xfe, 0x54, 0x10, 0x9b, 0x3a, 0x26, 0x4a, 0x16, 0x4c, 0x19, 0x58, 0x77, 0xca,
				0xa0, 0xa4, 0x96, 0x5f, 0xd4, 0xba, 0xc7, 0xb1, 0x6e, 0x60, 0x6b, 0x6c, 0xb4, 0xdc, 0xa1, 0xea,
				0x96, 0x9a, 0x67, 0xbc, 0x7a, 0x58, 0x8c, 0xac, 0x26, 0xc2, 0x01, 0x04, 0x05, 0x9e, 0x93, 0x44,
				0x32, 0xee, 0x41, 0x6d, 0x25, 0x15, 0x04, 0x34, 0xee, 0x73, 0x80, 0x9a, 0xd3, 0x1d, 0x7e, 0x86,
				0xbc, 0x3a, 0x6c, 0x48, 0xa7, 0x8a, 0x17, 0x5b, 0xbf, 0xb2, 0x63, 0x7c, 0x3b, 0x18, 0xce, 0xde,
				0x08, 0x11, 0xfd, 0x19, 0x1b, 0xc6, 0x8e, 0x8e, 0xe6, 0xc2, 0x54, 0x87, 0x2d, 0xe9, 0xf2, 0x8c,
				0x6f, 0xe8, 0x7a, 0x46, 0x4c, 0x9e, 0x6f, 0xaf, 0x68, 0x32, 0x85, 0xbd, 0x59, 0x74, 0xd1, 0xa3,
				0x8d, 0x66, 0x2f, 0x73, 0x49, 0x4b, 0xc2, 0xf5, 0xd2, 0x0b, 0x5b, 0x1f, 0x3f, 0xb0, 0xd0, 0xb1,
				0x90, 0x00, 0x56, 0x15, 0xf5, 0x9a, 0x80, 0xe8, 0x6a, 0xfb, 0x77, 0x4b, 0x97, 0x01, 0xe2, 0xd6,
				0x39, 0x44, 0x25, 0x76, 0xb8, 0x62, 0xf5, 0x0e, 0xfe, 0xa1, 0xb1, 0x27, 0x6d, 0xf6, 0x01, 0xb4,
				0x85, 0xb1, 0xe8, 0x86, 0xbb, 0x9a, 0xaa, 0xf4, 0xed, 0x6f, 0x03, 0xd5, 0x21, 0x01, 0xc7, 0x85,
				0x93, 0x71, 0x40, 0x2b, 0xa7, 0x3f, 0xc3, 0xe1, 0xed, 0x1d, 0x21, 0x62, 0xc3, 0x6a, 0x88, 0x45,
				0x9b, 0xb5, 0x8c, 0x8f, 0xc5, 0x66, 0x07, 0x3f, 0xc5, 0x10, 0xbb, 0x7e, 0x5d, 0x12, 0x1f, 0x4d,
				0x0a, 0xc5, 0x28, 0xc7, 0xa5, 0xcd, 0xfb, 0x3c, 0x81, 0xc8, 0xca, 0x58, 0xe0, 0x6e, 0xe8, 0x25,
				0x02, 0xde, 0x72, 0x71, 0x8f, 0x0c, 0xb7, 0x4d, 0x42, 0x8f, 0xba, 0xe5, 0x50, 0xe7, 0x82, 0xd3,
				0x2f, 0xb3, 0x34, 0x23, 0x76, 0x49, 0x89, 0x95, 0x2c, 0x6a, 0x36, 0x87, 0xcf, 0xa2, 0x91, 0x48,
				0xb8, 0x94, 0xdb, 0x50, 0x06, 0x43, 0x0b, 0xe4, 0xa5, 0xca, 0x9f, 0x64, 0x59, 0x41, 0xd1, 0xe4,
				0x1c, 0x1f, 0xcb, 0x83, 0x0c, 0x79, 0xea, 0xc0, 0x01, 0x6b, 0xb9, 0xab, 0x07, 0x60, 0xf1, 0xd2,
				0xd9, 0x8a, 0x16, 0x6f, 0x56, 0x29, 0x01, 0xf1, 0x6c, 0xbe, 0x1c, 0x18, 0xfd, 0x92, 0x93, 0x6f,
				0x0b, 0x40, 0x7c, 0x96, 0xef, 0x39, 0x7e, 0x1b, 0x81, 0xe7, 0xea, 0xb2, 0xef, 0x89, 0x60, 0x15,
				0x82, 0x09, 0x1b, 0x18, 0xf2, 0x9e, 0xbb, 0x7c, 0x4b, 0x6b, 0xbe, 0x2b, 0xc6, 0x59, 0x42, 0x8b,
				0x3a, 0x10, 0x7b, 0x11, 0x4f, 0xaf, 0x95, 0xdc, 0x4f, 0x35, 0x6b, 0x1a, 0xd2, 0x80, 0xb0, 0xfc,
				0x4d, 0xaf, 0x51, 0x54, 0x3c, 0xc6, 0xe2, 0x4d, 0x2a, 0x96, 0x37, 0x14, 0x31, 0xf6, 0x5c, 0x98,
				0xaa, 0x0b, 0x9c, 0x21, 0x7e, 0x0b, 0x40, 0x08, 0x0d, 0x37, 0x5b, 0xd1, 0xa9, 0xe4, 0x29, 0x64,
				0xbf, 0x41, 0xee, 0x3c, 0x12, 0x04, 0xe8, 0xca, 0x3d, 0xee, 0x01, 0xd4, 0x30, 0x84, 0x44, 0xdd,
				0x4f, 0x89, 0x27, 0x43, 0x8e, 0x67, 0x48, 0xcd, 0x92, 0x49, 0x7b, 0x87, 0x0a, 0x4f, 0x9e, 0x06,
				0x26, 0xc9, 0x7a, 0x8b, 0xa8, 0x46, 0x49, 0x10, 0x6d, 0x70, 0xeb, 0x3d, 0x05, 0xf9, 0x5b, 0x53,
				0x0b, 0x03, 0x0d, 0x4e, 0x58, 0x42, 0x2d, 0x8f, 0x82, 0xaf, 0xa2, 0xd1, 0xa0, 0x9f, 0x6e, 0x4a,
				0x08, 0xd5, 0xf0, 0xcd, 0xe8, 0x65, 0x88, 0x83, 0xf7, 0x21, 0xcf, 0x26, 0x37, 0x93, 0x80, 0xd5,
				0xe7, 0x49, 0xfe, 0xc7, 0x20, 0xbf, 0x7d, 0xb9, 0xc7, 0xea, 0xda, 0x0d, 0xa4, 0xa9, 0x9f, 0x6d,
				0xea, 0x44, 0xca, 0xee, 0xbd, 0x85, 0xbf, 0x07, 0x22, 0x8a, 0xd6, 0x1f, 0x11, 0xc0, 0x12, 0x4b,
				0x97, 0x99, 0x3f, 0x10, 0x10, 0xde, 0x03, 0x23, 0xe0, 0x1b, 0x35, 0x8f, 0x0b, 0xae, 0x9a, 0xae,
				0xae, 0xea, 0xaa, 0xc6, 0xfd, 0x39, 0x6a, 0x83, 0xc4, 0xeb, 0x63, 0x65, 0xe5, 0x69, 0x5b, 0x96,
				0xcd, 0x6a, 0xd3, 0x37, 0xe4, 0xf2, 0x1d, 0xa0, 0x6a, 0x17, 0x3e, 0xfb, 0x10, 0x71, 0x5c, 0xd4,
				0x8d, 0x8a, 0x79, 0x98, 0xd6, 0x88, 0x1b, 0x8b, 0x74, 0x36, 0x8b, 0xe4, 0xf8, 0x93, 0x82, 0xd5,
				0x8e, 0xcc, 0x7c, 0x78, 0x57, 0x86, 0xc2, 0x48, 0xf9, 0xc3, 0x87, 0x95, 0xeb, 0x14, 0x34, 0xe2,
				0x5a, 0x28, 0xa8, 0x04, 0x0a, 0xc7, 0xbb, 0x4d, 0x3f, 0x27, 0x36, 0x41, 0x83, 0xf8, 0x52, 0x26,
				0xe3, 0x7d, 0xc7, 0x4c, 0x3d, 0x26, 0xaf, 0x9f, 0x52, 0x08, 0x92, 0x37, 0x47, 0xf5, 0x0e, 0xee,
				0x1b, 0xe7, 0x7f, 0xd9, 0xa4, 0xb1, 0x94, 0xe2, 0x69, 0xc2, 0x90, 0x0e, 0x9a, 0x86, 0xb2, 0x4b,
				0xda, 0xd2, 0x33, 0x8b, 0x4e, 0x29, 0x29, 0xf4, 0x4d, 0xcd, 0xb7, 0x87, 0xed, 0x0d, 0x9f, 0xb1,
				0x9c, 0xb5, 0x67, 0xad, 0xbc, 0xc1, 0x64, 0x2e, 0xe7, 0x9e, 0xf5, 0x14, 0x01, 0xc6, 0xeb, 0x74,
				0x75, 0xea, 0xdf, 0x59, 0xe0, 0xf2, 0x3f, 0x6c, 0x67, 0x46, 0xba, 0xdc, 0x39, 0x15, 0x7c, 0xf3,
				0xe7, 0xe7, 0xd9, 0xf3, 0x15, 0x13, 0x28, 0x8e, 0x51, 0x3c, 0xb0, 0x79, 0x0b, 0xf2, 0xbc, 0xe0,
				0x4f, 0xe1, 0x14, 0x34, 0x86, 0xb4, 0xe0, 0x9f, 0x3e, 0xec, 0x15, 0x58, 0xdf, 0x69, 0xa4, 0xc9,
				0x80, 0x0f, 0x05, 0x55, 0x8c, 0xb7, 0xee, 0xca, 0x3b, 0x02, 0x7d, 0x7a, 0x52, 0x36, 0x89, 0xd7,
				0x22, 0xe5, 0xde, 0xbc, 0xed, 0xdf, 0xcc, 0x08, 0x21, 0x8b, 0xe2, 0xde, 0x7f, 0x9c, 0x41, 0xf0,
				0x50, 0x24, 0xd5, 0x9d, 0x01, 0x3d, 0x88, 0xdc, 0xd2, 0x1b, 0x21, 0xa0, 0x66, 0xb9, 0xe8, 0xee,
				0x2e, 0x94, 0xca, 0xd4, 0x44, 0xf9, 0x4e, 0xe1, 0x5a, 0x44, 0xf4, 0xcd, 0xd6, 0x8f, 0x41, 0x72,
				0x91, 0x17, 0x74, 0x75, 0x3d, 0xd6, 0xab, 0xb2, 0x5f, 0x38, 0x46, 0x05, 0x38, 0xc1, 0x7a, 0x53,
				0xe0, 0xfa, 0x37, 0x58, 0xbc, 0xfa, 0xf5, 0x25, 0x07, 0x02, 0x43, 0x59, 0x75, 0x01, 0x2c, 0x12,
				0xcf, 0xa7, 0x53, 0x4c, 0xd8, 0x87, 0x10, 0xd9, 0x22, 0x28, 0xfa, 0x49, 0x27, 0x45, 0xca, 0x29,
				0xf5, 0x52, 0x9e, 0x6a, 0xa7, 0xd4, 0x01, 0x40, 0x8c, 0x45, 0xc0, 0x81, 0xac, 0x41, 0x9e, 0x3d,
				0x00, 0xd5, 0x5f, 0x48, 0xae, 0x64, 0x23, 0x0c, 0xb7, 0x29, 0x0b, 0x26, 0x92, 0xab, 0xb5, 0xfa,
				0x92, 0x4e, 0xb6, 0xe5, 0xf2, 0x36, 0x05, 0xf0, 0xab, 0x00, 0x16, 0x67, 0x7f, 0x99, 0x18, 0xba,
				0x93, 0x47, 0x95, 0x01, 0xf4, 0x15, 0x2a, 0x04, 0xad, 0xf0, 0x0a, 0x9c, 0x70, 0xdb, 0x25, 0x1d,
				0xdb, 0xf7, 0x04, 0x34, 0x67, 0xee, 0xec, 0xc0, 0xbd, 0x7e, 0x81, 0x54, 0x8a, 0xd9, 0x34, 0x29,
				0x38, 0xc3, 0xd1, 0x14, 0x1d, 0xb3, 0x28, 0x23, 0xa1, 0xf6, 0x71, 0x52, 0x04, 0x14, 0xd3, 0xda,
				0x98, 0x26, 0x4e, 0x87, 0xd8, 0xc8, 0x84, 0x91, 0x50, 0xb9, 0x35, 0x83, 0x43, 0x57, 0x58, 0x6f,
				0x24, 0x53, 0x2c, 0x6f, 0xd2, 0x3f, 0x47, 0x7a, 0x3d, 0x92, 0xf5, 0x2f, 0x07, 0x01, 0x77, 0x2c,
				0xe2, 0xf9, 0x6f, 0xb7, 0x38, 0x79, 0x4d, 0xd5, 0x5c, 0xb2, 0xec, 0xfa, 0xb9, 0x82, 0xc1, 0xde,
				0x5a, 0xb8, 0x8c, 0x74, 0x32, 0x49, 0x53, 0xa0, 0xfe, 0x8d, 0x0b, 0x86, 0x56, 0x60, 0x90, 0x10,
				0x27, 0x1f, 0x4a, 0x19, 0x99, 0xfe, 0x3e, 0x8b, 0xdf, 0x6d, 0x29, 0x3a, 0xbe, 0x7e, 0xf2, 0x88,
				0x6a, 0xa6, 0x57, 0xcd, 0x67, 0x5a, 0x11, 0xd3, 0xc4, 0x89, 0xc7, 0xc2, 0xaa, 0xd2, 0x13, 0x04,
				0x9b, 0x8f, 0x69, 0x10, 0xc9, 0x34, 0x27, 0x11, 0x9d, 0xc9, 0x24, 0x0e, 0xa9, 0x89, 0x0c, 0xb2,
				0x2e, 0x99, 0xae, 0x6a, 0xcf, 0x95, 0x05, 0xba, 0x64, 0x45, 0x92, 0x75, 0x55, 0x1d, 0x02, 0xd9,
				0x95, 0x24, 0x2a, 0x8c, 0x13, 0xfb, 0x0f, 0xd3, 0x4c, 0xf7, 0xad, 0x0a, 0x40, 0xee, 0x0c, 0x85,
				0xb2, 0x0f, 0x92, 0x20, 0xdf, 0xd8, 0xa9, 0x89, 0xff, 0xb8, 0x52, 0x05, 0x09, 0x2b, 0x45, 0xf5,
				0x31, 0x98, 0xfc, 0x7e, 0x91, 0xab, 0xeb, 0x29, 0xf6, 0xac, 0xcd, 0x6b, 0x79, 0x06, 0x07, 0xd3,
			}),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseHeader(tt.b)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseHeader() error = %v, wantErr %v", err, tt.wantErr)
				return
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
