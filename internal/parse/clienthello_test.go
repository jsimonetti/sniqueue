package parse

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func Test_clientHello_unmarshal(t *testing.T) {

	tests := []struct {
		name    string
		want    *clientHello
		payload []byte
		wantErr bool
	}{

		{
			name:    "Empty",
			payload: []byte{},
			wantErr: true,
		},
		{
			name: "Good",
			want: &clientHello{
				SNI: "dns.google",
			},
			payload: goodIPv4[52:],
			wantErr: false,
		},
		{
			name: "Good No SNI",
			want: &clientHello{
				SNI: "",
			},
			payload: goodIPv4NoSNI[52:],
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := &clientHello{}

			if err := got.unmarshal(tt.payload); err != nil {
				if !tt.wantErr {
					t.Errorf("unmarshal() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
			if tt.wantErr {
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("unexpected first message bytes (-want +got):\n%s", diff)
			}
		})
	}
}
