package a2a

import (
	"testing"

	"github.com/calbebop/batesian/internal/attack"
)

func TestRecordPushConfigWithNumericRPCID(t *testing.T) {
	resp := &attack.Response{
		StatusCode: 200,
		Body:       []byte(`{"jsonrpc":"2.0","id":1,"result":{"taskId":"task-1","id":"config-1"}}`),
	}
	if got := pushConfigID("task-1", "1.0", resp); got != "config-1" {
		t.Fatalf("config ID = %q", got)
	}
}

func TestRecordV03PushConfigDoesNotUseTaskIDAsConfigID(t *testing.T) {
	resp := &attack.Response{
		StatusCode: 200,
		Body:       []byte(`{"jsonrpc":"2.0","id":1,"result":{"id":"task-1","pushNotificationConfig":{"url":"https://listener.example"}}}`),
	}
	if got := pushConfigID("task-1", "0.3.0", resp); got != "" {
		t.Fatalf("task ID was misreported as config ID: %q", got)
	}
}

func TestPushConfigIDFromLegacyRESTName(t *testing.T) {
	resp := &attack.Response{StatusCode: 200, Body: []byte(`{"name":"tasks/task-1/pushNotificationConfigs/config-1"}`)}
	if got := pushConfigID("task-1", "0.3.0", resp); got != "config-1" {
		t.Fatalf("config ID = %q", got)
	}
}
