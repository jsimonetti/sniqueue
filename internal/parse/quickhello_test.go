package parse

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func Test_quickHelloMsg_unmarshal(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		want    *quickHelloMsg
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
			got := &quickHelloMsg{}

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
				t.Fatalf("unexpected first message bytes (-want +got):\n%s", diff)
			}
		})
	}
}
