package parse

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestUDP_unmarshal(t *testing.T) {
	tests := []struct {
		name    string
		want    *UDP
		payload []byte
		wantErr bool
	}{
		{
			name:    "Empty",
			payload: []byte{},
			wantErr: true,
		},
		{
			name:    "IETF QUIC",
			payload: goodUDPQUICInitial,
			wantErr: false,
			want: &UDP{
				SourcePort:      52832,
				DestinationPort: 443,
				Hello: clientHello{
					SNI: "r2---sn-fxc25nn-nwje.googlevideo.com",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := &UDP{}
			if err := got.unmarshal(tt.payload); err != nil {
				if tt.wantErr {
					return
				}
				t.Fatalf("unmarshal() error = %v, wantErr %v", err, tt.wantErr)
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}
