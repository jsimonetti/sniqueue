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
