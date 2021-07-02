package parse

import (
	"testing"

	"github.com/jsimonetti/sniqueue/internal/parse/quic"

	"github.com/google/go-cmp/cmp"
)

func TestQuic_unmarshal(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		want    *Quic
		wantErr bool
	}{
		{
			name:    "Version1",
			payload: goodQUICInitial,
			want: &Quic{
				Header: &quic.ExtendedHeader{
					Header: quic.Header{
						TypeByte:         192,
						IsLongHeader:     true,
						ParsedLen:        19,
						DestConnectionID: []uint8{0xc3, 0xc3, 0xa5, 0x0f, 0xa4, 0x2a, 0xe0, 0x7d},
						Version:          1,
						Length:           1312,
						Token:            []uint8{},
					},
					PacketNumberLen: 1,
					PacketNumber:    1,
				},
				Hello: quickHelloMsg{SNI: "r2---sn-fxc25nn-nwje.googlevideo.com"},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := &Quic{}
			if err := got.unmarshal(tt.payload); err != nil {
				if tt.wantErr {
					return
				}
				t.Fatalf("unmarshal() error = %v, wantErr %v", err, tt.wantErr)
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
