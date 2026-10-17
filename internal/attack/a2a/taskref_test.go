package a2a

import (
	"reflect"
	"testing"
)

func TestParseRESTTaskListPage(t *testing.T) {
	tests := []struct {
		name  string
		body  string
		ids   []string
		next  string
		valid bool
	}{
		{"empty list", `{"tasks":[]}`, []string{}, "", true},
		{"task ID aliases", `{"tasks":[{"id":"t1"},{"taskId":"t2"}]}`, []string{"t1", "t2"}, "", true},
		{"bare list", `[{"id":"t1"}]`, []string{"t1"}, "", true},
		{"next page", `{"tasks":[],"nextPageToken":"next"}`, []string{}, "next", true},
		{"RPC error", `{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"Task not found"}}`, nil, "", false},
		{"missing list", `{"totalSize":42}`, nil, "", false},
		{"missing task ID", `{"tasks":[{}]}`, nil, "", false},
		{"null cursor", `{"tasks":[],"nextPageToken":null}`, []string{}, "", false},
		{"invalid JSON", `not json`, nil, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ids, next, valid := parseRESTTaskListPage([]byte(tt.body))
			if valid != tt.valid || next != tt.next || !reflect.DeepEqual(ids, tt.ids) {
				t.Fatalf("got ids=%v next=%q valid=%t, want ids=%v next=%q valid=%t",
					ids, next, valid, tt.ids, tt.next, tt.valid)
			}
		})
	}
}

func TestTaskResultContext(t *testing.T) {
	for _, tc := range []struct {
		name    string
		body    string
		wantID  string
		wantCtx string
	}{
		{"flat v0.3", `{"kind":"task","id":"task-1","contextId":"ctx-1","status":{"state":"submitted"}}`, "task-1", "ctx-1"},
		{"wrapped v1", `{"task":{"id":"task-1","contextId":"ctx-1","status":{"state":"TASK_STATE_SUBMITTED"}}}`, "task-1", "ctx-1"},
		{"id only", `{"id":"task-1","contextId":"ctx-1"}`, "", ""},
		{"missing state", `{"task":{"id":"task-1","status":{}}}`, "", ""},
		{"message", `{"message":{"id":"task-1","status":{"state":"submitted"}}}`, "", ""},
		{"wrong kind", `{"kind":"message","id":"task-1","status":{"state":"submitted"}}`, "", ""},
		{"ambiguous wrapper", `{"task":{"id":"task-1","status":{"state":"submitted"}},"message":{}}`, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id, contextID := taskResultContext([]byte(tc.body))
			if id != tc.wantID || contextID != tc.wantCtx {
				t.Fatalf("Task = (%q, %q), want (%q, %q)", id, contextID, tc.wantID, tc.wantCtx)
			}
		})
	}
}

func TestTaskIDExtractorsRequireTask(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result string
		want   string
	}{
		{"flat", `{"id":"task-1","status":{"state":"submitted"}}`, "task-1"},
		{"wrapped", `{"task":{"id":"task-1","status":{"state":"submitted"}}}`, "task-1"},
		{"id only", `{"id":"task-1"}`, ""},
		{"message", `{"message":{"messageId":"msg-1","role":"agent","parts":[{"text":"pong"}]}}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := restTaskID([]byte(tc.result)); got != tc.want {
				t.Fatalf("REST task ID = %q, want %q", got, tc.want)
			}
			envelope := `{"jsonrpc":"2.0","id":"probe","result":` + tc.result + `}`
			if got, _ := extractTaskContext([]byte(envelope)); got != tc.want {
				t.Fatalf("JSON-RPC task ID = %q, want %q", got, tc.want)
			}
		})
	}
}
