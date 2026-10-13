package attack

import "testing"

func TestRecordA2ATask(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		request  string
		response string
		wantID   string
	}{
		{"v1 task", "https://agent.example/rpc", `{"method":"SendMessage"}`,
			`{"jsonrpc":"2.0","id":1,"result":{"task":{"id":"task-v1"}}}`, "task-v1"},
		{"v0.3 task", "https://agent.example/rpc", `{"method":"message/send"}`,
			`{"jsonrpc":"2.0","id":1,"result":{"id":"task-v03"}}`, "task-v03"},
		{"REST task", "https://agent.example/v1/message:send", `{}`,
			`{"task":{"id":"task-rest"}}`, "task-rest"},
		{"message only", "https://agent.example/rpc", `{"method":"SendMessage"}`,
			`{"jsonrpc":"2.0","id":1,"result":{"messageId":"message-1"}}`, ""},
		{"RPC error", "https://agent.example/rpc", `{"method":"SendMessage"}`,
			`{"jsonrpc":"2.0","id":1,"error":{"code":-32601}}`, ""},
		{"read only", "https://agent.example/rpc", `{"method":"GetTask"}`,
			`{"jsonrpc":"2.0","id":1,"result":{"id":"task-existing"}}`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := &TargetState{}
			recordA2ATask(state, tt.endpoint, []byte(tt.request),
				&Response{StatusCode: 200, Body: []byte(tt.response)})
			objects := state.Snapshot()
			if tt.wantID == "" {
				if len(objects) != 0 {
					t.Fatalf("unexpected objects: %+v", objects)
				}
				return
			}
			if len(objects) != 1 || objects[0].ID != tt.wantID || objects[0].Cleanup != CleanupUnavailable {
				t.Fatalf("objects = %+v, want created task %q without deletion", objects, tt.wantID)
			}
		})
	}
}

func TestTargetStateSnapshotAndTaskDeduplication(t *testing.T) {
	state := &TargetState{}
	object := TargetObject{Kind: "a2a_task", ID: "task-1", Endpoint: "https://agent.example/rpc"}
	state.Record(object)
	state.Record(object)
	copy := state.Snapshot()
	if len(copy) != 1 {
		t.Fatalf("objects = %+v, want one task", copy)
	}
	copy[0].ID = "changed"
	if got := state.Snapshot()[0].ID; got != "task-1" {
		t.Errorf("snapshot changed stored object: %q", got)
	}
}

func TestRecordMCPTask(t *testing.T) {
	for _, response := range []string{
		`{"jsonrpc":"2.0","id":3,"result":{"resultType":"task","taskId":"task-1","status":"working"}}`,
		`{"jsonrpc":"2.0","id":3,"result":{"task":{"taskId":"task-1"}}}`,
	} {
		state := &TargetState{}
		recordMCPTask(state, "https://agent.example/mcp", []byte(`{"method":"tools/call"}`),
			&Response{StatusCode: 200, Body: []byte(response)})
		objects := state.Snapshot()
		if len(objects) != 1 || objects[0].Kind != "mcp_task" || objects[0].ID != "task-1" ||
			objects[0].Cleanup != CleanupUnavailable {
			t.Fatalf("MCP task state = %+v", objects)
		}
	}
}
