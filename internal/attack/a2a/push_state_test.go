package a2a

import (
	"testing"

	"github.com/calbebop/batesian/internal/attack"
)

func TestRecordPushConfigWithNumericRPCID(t *testing.T) {
	state := &attack.TargetState{}
	recordPushConfig(state, "https://agent.example/rpc", "task-1", "1.0", &attack.Response{
		StatusCode: 200,
		Body:       []byte(`{"jsonrpc":"2.0","id":1,"result":{"taskId":"task-1","id":"config-1"}}`),
	})
	objects := state.Snapshot()
	if len(objects) != 1 || objects[0].ID != "config-1" || objects[0].ParentID != "task-1" ||
		objects[0].Cleanup != attack.CleanupNotAttempted {
		t.Fatalf("push config state = %+v", objects)
	}
}

func TestRecordV03PushConfigDoesNotUseTaskIDAsConfigID(t *testing.T) {
	state := &attack.TargetState{}
	recordPushConfig(state, "https://agent.example/rpc", "task-1", "0.3.0", &attack.Response{
		StatusCode: 200,
		Body:       []byte(`{"jsonrpc":"2.0","id":1,"result":{"id":"task-1","pushNotificationConfig":{"url":"https://listener.example"}}}`),
	})
	objects := state.Snapshot()
	if len(objects) != 1 || objects[0].ID != "" || objects[0].ParentID != "task-1" {
		t.Fatalf("task ID was misreported as config ID: %+v", objects)
	}
}
