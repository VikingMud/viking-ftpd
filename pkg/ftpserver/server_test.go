package ftpserver

import (
	"os"
	"testing"
)

func TestClampPerm(t *testing.T) {
	tests := []struct {
		in   os.FileMode
		want os.FileMode
	}{
		{os.ModePerm, 0644}, // ftpserverlib passes 0777 for uploads
		{0777, 0644},        // no world/group write
		{0666, 0644},        // typical create mode
		{0600, 0600},        // already restrictive, unchanged
		{0640, 0640},        // group-read preserved
		{0000, 0000},        // no bits
	}
	for _, tc := range tests {
		if got := clampPerm(tc.in); got != tc.want {
			t.Errorf("clampPerm(%o) = %o, want %o", tc.in, got, tc.want)
		}
	}
}
