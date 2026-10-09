package a2a

import (
	"encoding/json"
	"testing"
)

func TestRestTaskSendRequestWireShape(t *testing.T) {
	for _, tc := range []struct {
		version string
		field   string
	}{
		{"1.0", "parts"},
		{"0.3.0", "content"},
	} {
		t.Run(tc.version, func(t *testing.T) {
			request := restTaskSendRequest("test", "ping", tc.version)
			message := request["message"].(map[string]interface{})
			if message["role"] != "ROLE_USER" {
				t.Errorf("role = %q, want ROLE_USER", message["role"])
			}
			parts, ok := message[tc.field].([]interface{})
			if !ok || len(parts) != 1 || parts[0].(map[string]string)["text"] != "ping" {
				t.Errorf("%s = %v, want one text part", tc.field, message[tc.field])
			}
			if _, ok := message["parts"]; ok && tc.field != "parts" {
				t.Error("legacy REST message used the v1 parts field")
			}
			if _, ok := message["content"]; ok && tc.field != "content" {
				t.Error("v1 REST message used the legacy content field")
			}
			configuration, hasConfiguration := request["configuration"].(map[string]interface{})
			if hasConfiguration != (tc.version == "1.0") {
				t.Fatalf("configuration present = %t", hasConfiguration)
			}
			if tc.version == "1.0" && configuration["returnImmediately"] != true {
				t.Fatalf("returnImmediately = %v, want true", configuration["returnImmediately"])
			}
		})
	}
}

func TestTaskMarkerLocation_LegacyRESTContent(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       string
	}{
		{"history", `{"id":"task-1","history":[{"content":[{"text":"marker"}]}]}`, "history"},
		{"status", `{"id":"task-1","status":{"message":{"content":[{"text":"marker"}]}}}`, "status message"},
		{"redacted", `{"id":"task-1","history":[{"content":[{"text":"hidden"}]}]}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			location, matched := taskMarkerLocation(json.RawMessage(tc.body), "task-1", "marker")
			if location != tc.want || !matched {
				t.Errorf("location = %q, matched = %t; want %q, true", location, matched, tc.want)
			}
		})
	}
}
