package a2a

import "testing"

func TestA2AVersionHeaders(t *testing.T) {
	extra := map[string]string{
		"A2A-Version": "9.9",
		"a2a-version": "8.8",
		"X-Tenant":    "tenant-a",
	}
	for _, tc := range []struct{ version, want string }{
		{"1.0", "1.0"},
		{"", ""},
	} {
		headers := a2aVersionHeaders(extra, tc.version)
		if headers["A2A-Version"] != tc.want || headers["a2a-version"] != "" || headers["X-Tenant"] != "tenant-a" {
			t.Fatalf("version %q: headers=%v", tc.version, headers)
		}
	}
	if extra["A2A-Version"] != "9.9" || extra["a2a-version"] != "8.8" {
		t.Fatalf("configured headers mutated: %v", extra)
	}
}
