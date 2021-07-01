package parse

import (
	"net"
	"testing"

	"github.com/google/go-cmp/cmp"
)

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
						Hello:           clientHello{SNI: "dns.google"},
					},
				},
			},
			payload: goodIPv4,
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
						Hello:           clientHello{SNI: "r2---sn-fxc25nn-nwje.googlevideo.com"},
					},
				},
			},
			payload: goodIPv6QUICInitial,
			wantErr: true, // to skip quic for now
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
				t.Fatalf("parse() error = %v, wantErr %v", err, tt.wantErr)
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
