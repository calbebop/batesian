package a2a

import "testing"

func TestTaskReadMarkerLocation(t *testing.T) {
	const taskID = "owner-task"
	const marker = "batesian idor probe 123"
	tests := []struct {
		name     string
		body     string
		location string
		matched  bool
	}{
		{"history", `{"result":{"id":"owner-task","history":[{"parts":[{"text":"batesian idor probe 123"}]}]}}`, "history", true},
		{"nested artifact", `{"result":{"task":{"id":"owner-task","artifacts":[{"parts":[{"text":"batesian idor probe 123"}]}]}}}`, "artifact", true},
		{"status message", `{"result":{"id":"owner-task","status":{"message":{"parts":[{"text":"batesian idor probe 123"}]}}}}`, "status message", true},
		{"id echo", `{"result":{"id":"owner-task"}}`, "", true},
		{"generic status", `{"result":{"id":"owner-task","status":{"state":"working"}}}`, "", true},
		{"unrelated history", `{"result":{"id":"owner-task","history":[{"parts":[{"text":"other text"}]}]}}`, "", true},
		{"metadata echo", `{"result":{"id":"owner-task","metadata":{"debug":"batesian idor probe 123"}}}`, "", true},
		{"wrong task", `{"result":{"id":"other-task","history":[{"parts":[{"text":"batesian idor probe 123"}]}]}}`, "", false},
		{"context only", `{"result":{"contextId":"owner-context","history":[{"parts":[{"text":"batesian idor probe 123"}]}]}}`, "", false},
		{"null result", `{"result":null}`, "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			location, matched := taskReadMarkerLocation([]byte(tc.body), taskID, marker)
			if location != tc.location || matched != tc.matched {
				t.Fatalf("got location=%q matched=%t, want %q/%t", location, matched, tc.location, tc.matched)
			}
		})
	}
}
