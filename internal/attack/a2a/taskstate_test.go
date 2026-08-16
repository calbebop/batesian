package a2a

import "testing"

// A2A carries task states in two spellings. v0.3 used lowercase strings
// ("working"), v1.0 carries the proto enum ("TASK_STATE_WORKING"), and v1.0.1
// standardized the specification's own examples on the enum form. Detection
// helpers that recognize a task by its state must accept both, or a rule gated
// on them stays silent against a compliant server.

// bodyShowsCanceled already accepted both spellings when a2a-task-cancel-idor-001
// was written. This pins that, so a later simplification cannot quietly drop the
// enum form and leave the rule unable to confirm a cancellation.
func TestBodyShowsCanceled_AcceptsBothStateSpellings(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{"v0.3 lowercase", `{"result":{"status":{"state":"canceled"}}}`, true},
		{"v1.0 enum", `{"result":{"status":{"state":"TASK_STATE_CANCELED"}}}`, true},
		{"still working", `{"result":{"status":{"state":"working"}}}`, false},
		{"enum working", `{"result":{"status":{"state":"TASK_STATE_WORKING"}}}`, false},
		{
			// "cancelable" is a different word: a not-cancelable error must not
			// be read as proof the task was canceled.
			name: "TaskNotCancelableError is not a cancellation",
			body: `{"error":{"code":-32002,"message":"TaskNotCancelableError"}}`,
			want: false,
		},
		{"empty", ``, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bodyShowsCanceled([]byte(tt.body)); got != tt.want {
				t.Errorf("bodyShowsCanceled(%s) = %v, want %v", tt.body, got, tt.want)
			}
		})
	}
}
