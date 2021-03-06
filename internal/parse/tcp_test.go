package parse

import (
	"testing"

	"github.com/jsimonetti/sniqueue/internal/parse/tls"

	"github.com/google/go-cmp/cmp"
)

func TestTCP_unmarshal(t *testing.T) {
	tests := []struct {
		name    string
		want    *TCP
		payload []byte
		wantErr bool
	}{
		{
			name:    "Empty",
			payload: []byte{},
			wantErr: true,
		},
		{
			name: "GoodIPv4",
			payload: []byte{
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
			want: &TCP{
				SourcePort:      64115,
				DestinationPort: 443,
				Hello:           tls.ClientHello{SNI: "dns.google"},
			},
		},
		{
			name: "TCP teardown (RST/FIN)",
			payload: []byte{
				0x91, 0x0c, 0x01, 0xbb, 0x98, 0x85, 0xe8, 0x62,
				0x9b, 0x80, 0xd7, 0xc4, 0x80, 0x10, 0x03, 0xea,
				0x00, 0xef, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a,
				0xd9, 0xbd, 0x93, 0x50, 0xd9, 0x01, 0xd1, 0x20,
			},
			wantErr: true,
			want: &TCP{
				SourcePort:      37132,
				DestinationPort: 443,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := &TCP{}
			if err := got.unmarshal(tt.payload); err != nil {
				if tt.wantErr {
					return
				}
				t.Fatalf("Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
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
