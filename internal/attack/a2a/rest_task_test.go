package a2a

import "testing"

func TestRestTaskSendRequestTiming(t *testing.T) {
	for _, tc := range []struct {
		version string
		want    bool
	}{
		{"1.0", true},
		{"0.3.0", false},
	} {
		t.Run(tc.version, func(t *testing.T) {
			request := restTaskSendRequest("test", "ping", tc.version)
			configuration, hasConfiguration := request["configuration"].(map[string]interface{})
			if hasConfiguration != tc.want {
				t.Fatalf("configuration present = %t, want %t", hasConfiguration, tc.want)
			}
			if tc.want && configuration["returnImmediately"] != true {
				t.Fatalf("returnImmediately = %v, want true", configuration["returnImmediately"])
			}
		})
	}
}
