package a2a

import (
	"testing"

	"github.com/calbebop/batesian/internal/attack"
)

func TestPushTaskReplyID(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"flat task", `{"jsonrpc":"2.0","id":"probe","result":{"id":"task-1","status":{"state":"submitted"}}}`, "task-1"},
		{"wrapped task", `{"jsonrpc":"2.0","id":"probe","result":{"task":{"id":"task-1","status":{"state":"TASK_STATE_SUBMITTED"}}}}`, "task-1"},
		{"wrong request", `{"jsonrpc":"2.0","id":"other","result":{"id":"task-1","status":{"state":"submitted"}}}`, ""},
		{"null result", `{"jsonrpc":"2.0","id":"probe","result":null}`, ""},
		{"generic result", `{"jsonrpc":"2.0","id":"probe","result":{"ok":true}}`, ""},
		{"id only", `{"jsonrpc":"2.0","id":"probe","result":{"id":"task-1"}}`, ""},
		{"empty state", `{"jsonrpc":"2.0","id":"probe","result":{"id":"task-1","status":{"state":""}}}`, ""},
		{"message discriminator", `{"jsonrpc":"2.0","id":"probe","result":{"kind":"message","id":"task-1","status":{"state":"submitted"}}}`, ""},
		{"message", `{"jsonrpc":"2.0","id":"probe","result":{"message":{"id":"task-1","status":{"state":"submitted"}}}}`, ""},
		{"ambiguous wrapper", `{"jsonrpc":"2.0","id":"probe","result":{"task":{"id":"task-1","status":{"state":"submitted"}},"message":{}}}`, ""},
		{"error", `{"jsonrpc":"2.0","id":"probe","error":{"code":-32601,"message":"Method not found"}}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := &attack.Response{StatusCode: 200, Body: []byte(tc.body)}
			if got := pushTaskReplyID(resp, "probe"); got != tc.want {
				t.Fatalf("task ID = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRESTPushTaskID(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"wrapped task", `{"task":{"id":"task-1","status":{"state":"TASK_STATE_SUBMITTED"}}}`, "task-1"},
		{"bare task", `{"id":"task-1","status":{"state":"submitted"}}`, "task-1"},
		{"id only", `{"task":{"id":"task-1"}}`, ""},
		{"message", `{"message":{"id":"task-1","status":{"state":"submitted"}}}`, ""},
		{"ambiguous wrapper", `{"task":{"id":"task-1","status":{"state":"submitted"}},"message":{}}`, ""},
		{"generic result", `{"id":"task-1","ok":true}`, ""},
		{"RPC error", `{"jsonrpc":"2.0","id":"probe","error":{"code":-32601,"message":"Method not found"}}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := &attack.Response{StatusCode: 200, Body: []byte(tc.body)}
			if got := restPushTaskID(resp); got != tc.want {
				t.Fatalf("task ID = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPushTaskSetupOutcome_MessagesAndMalformedReplies(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want int
	}{
		{"flat message", `{"jsonrpc":"2.0","id":"probe","result":{"kind":"message","messageId":"msg-1","role":"agent","parts":[{"text":"pong"}]}}`, setupFeatureAbsent},
		{"wrapped message", `{"jsonrpc":"2.0","id":"probe","result":{"message":{"messageId":"msg-1","role":"agent","parts":[{"text":"pong"}]}}}`, setupFeatureAbsent},
		{"missing parts", `{"jsonrpc":"2.0","id":"probe","result":{"kind":"message","messageId":"msg-1","role":"agent","parts":[]}}`, setupOtherRefusal},
		{"contradictory message", `{"jsonrpc":"2.0","id":"probe","result":{"kind":"message","id":"task-1","status":{"state":"submitted"},"messageId":"msg-1","role":"agent","parts":[{"text":"pong"}]}}`, setupOtherRefusal},
		{"id only", `{"jsonrpc":"2.0","id":"probe","result":{"id":"task-1"}}`, setupOtherRefusal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := &attack.Response{StatusCode: 200, Body: []byte(tc.body)}
			if got := pushTaskSetupOutcome("creating a task", "http://example.invalid", false, resp, "probe"); got.rank != tc.want {
				t.Fatalf("setup rank = %d, want %d: %s", got.rank, tc.want, got.reason)
			}
		})
	}
}
