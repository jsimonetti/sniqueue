package parse

import (
	"testing"

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
			name:    "GoodIPv4",
			payload: goodIPv4[20:],
			wantErr: false,
			want: &TCP{
				SourcePort:      64115,
				DestinationPort: 443,
				Hello:           clientHello{SNI: "dns.google"},
			},
		},
		{
			name:    "TCP teardown (RST/FIN)",
			payload: []byte{0x91, 0xc, 0x1, 0xbb, 0x98, 0x85, 0xe8, 0x62, 0x9b, 0x80, 0xd7, 0xc4, 0x80, 0x10, 0x3, 0xea, 0x0, 0xef, 0x0, 0x0, 0x1, 0x1, 0x8, 0xa, 0xd9, 0xbd, 0x93, 0x50, 0xd9, 0x1, 0xd1, 0x20},
			wantErr: false,
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
				if !tt.wantErr {
					t.Errorf("unmarshal() error = %v, wantErr %v", err, tt.wantErr)
				}
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
