package a2a

import "testing"

func TestBodyShowsCanceled(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{"v0.3 lowercase", `{"result":{"id":"owner-task","status":{"state":"canceled"}}}`, true},
		{"v1 enum", `{"result":{"id":"owner-task","status":{"state":"TASK_STATE_CANCELED"}}}`, true},
		{"legacy enum", `{"result":{"id":"owner-task","status":{"state":"TASK_STATE_CANCELLED"}}}`, true},
		{"nested task", `{"result":{"task":{"id":"owner-task","status":{"state":"canceled"}}}}`, true},
		{"outer id nested state", `{"result":{"id":"owner-task","task":{"id":"owner-task","status":{"state":"canceled"}}}}`, true},
		{"nested state wins", `{"result":{"id":"owner-task","status":{"state":"canceled"},"task":{"id":"owner-task","status":{"state":"working"}}}}`, false},
		{"nested id wins", `{"result":{"id":"owner-task","status":{"state":"canceled"},"task":{"id":"other-task","status":{"state":"working"}}}}`, false},
		{"still working", `{"result":{"id":"owner-task","status":{"state":"working"}}}`, false},
		{"history echo", `{"result":{"id":"owner-task","status":{"state":"working"},"history":[{"text":"TASK_STATE_CANCELED"}]}}`, false},
		{"metadata echo", `{"result":{"id":"owner-task","status":{"state":"working"},"metadata":{"state":"canceled"}}}`, false},
		{"wrong task", `{"result":{"id":"other-task","status":{"state":"canceled"}}}`, false},
		{"message taskId", `{"result":{"taskId":"owner-task","status":{"state":"canceled"}}}`, false},
		{"error", `{"error":{"code":-32002,"message":"TASK_STATE_CANCELED"}}`, false},
		{"empty", ``, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bodyShowsCanceled([]byte(tt.body), "owner-task"); got != tt.want {
				t.Errorf("bodyShowsCanceled(%s) = %v, want %v", tt.body, got, tt.want)
			}
		})
	}
}
