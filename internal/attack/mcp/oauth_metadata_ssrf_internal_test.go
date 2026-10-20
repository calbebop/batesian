package mcp

import "testing"

func TestPrivateCallbackDestination(t *testing.T) {
	for _, tc := range []struct {
		url     string
		private bool
	}{
		{"http://127.0.0.1:9000", true},
		{"http://10.1.2.3:9000", true},
		{"http://169.254.1.2:9000", true},
		{"http://[::1]:9000", true},
		{"https://192.0.2.1/callback", false},
		{"https://oob.example.com/callback", false},
	} {
		if got := privateCallbackDestination(tc.url); got != tc.private {
			t.Errorf("privateCallbackDestination(%q) = %t, want %t", tc.url, got, tc.private)
		}
	}
}
