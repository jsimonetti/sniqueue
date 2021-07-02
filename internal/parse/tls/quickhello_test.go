package tls

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func Test_quickHelloMsg_unmarshal(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		want    *QuickHelloMsg
		wantErr bool
	}{
		// TODO: Add test cases.
		{
			name:    "Empty",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := &QuickHelloMsg{}

			if err := got.Unmarshal(tt.payload); err != nil {
				if tt.wantErr {
					return
				}
				t.Fatalf("Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
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
