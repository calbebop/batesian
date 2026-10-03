package a2a

import "testing"

func TestPrivatePushCallbackURL(t *testing.T) {
	tests := []struct {
		url     string
		private bool
	}{
		{"http://127.0.0.1:8080/hook", true},
		{"http://10.1.2.3/hook", true},
		{"http://172.16.0.1/hook", true},
		{"http://172.31.255.255/hook", true},
		{"http://172.32.0.1/hook", false},
		{"http://192.168.1.1/hook", true},
		{"http://169.254.169.254/hook", true},
		{"http://[::1]:8080/hook", true},
		{"http://[fd00::1]/hook", true},
		{"http://[fe80::1]/hook", true},
		{"http://[::ffff:127.0.0.1]/hook", true},
		{"http://[::ffff:8.8.8.8]/hook", false},
		{"http://localhost/hook", true},
		{"http://service.localhost./hook", true},
		{"http://0.0.0.0/hook", true},
		{"https://203.0.113.10/hook", false},
		{"https://[2001:db8::1]/hook", false},
		{"https://webhook.example/hook", false},
		{"https://localhost.example/hook", false},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			if got := privatePushCallbackURL(tt.url); got != tt.private {
				t.Errorf("privatePushCallbackURL(%q) = %v, want %v", tt.url, got, tt.private)
			}
		})
	}
}
