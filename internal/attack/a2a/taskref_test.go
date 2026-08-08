package a2a

import "testing"

// The oracle these replaced was ContainsAny(`"history"`, `"contextId"`, taskID,
// contextID) — OR semantics over two KEY NAMES, so any accepted Task envelope
// matched and the check meant "the caller got a result".
func TestResultReferencesTask(t *testing.T) {
	const taskID, ctxID = "task-A", "ctx-A"

	cases := []struct {
		name string
		body string
		want bool
	}{
		{
			// The live false positive: a tenant-scoped server does not error on an
			// unknown taskId, it starts a new conversation and answers with a NEW
			// task. The old needle `"contextId"` matched this.
			name: "a different task is not A's task",
			body: `{"jsonrpc":"2.0","id":1,"result":{"id":"task-B-7","contextId":"ctx-B","status":{"state":"working"}}}`,
			want: false,
		},
		{
			name: "the same task id references it",
			body: `{"jsonrpc":"2.0","id":1,"result":{"id":"task-A","contextId":"ctx-A","status":{"state":"completed"}}}`,
			want: true,
		},
		{
			name: "A's context is enough even under another task id",
			body: `{"jsonrpc":"2.0","id":1,"result":{"id":"task-A-2","contextId":"ctx-A"}}`,
			want: true,
		},
		{
			name: "taskId spelling is accepted too",
			body: `{"jsonrpc":"2.0","id":1,"result":{"taskId":"task-A","contextId":"ctx-Z"}}`,
			want: true,
		},
		{
			// A Message result has no identifiers, so nothing can be established.
			name: "a message result establishes nothing",
			body: `{"jsonrpc":"2.0","id":1,"result":{"messageId":"m1","role":"agent","parts":[{"text":"hi"}]}}`,
			want: false,
		},
		{
			// Previously matched on the bare key name.
			name: "an envelope carrying only the key names does not match",
			body: `{"jsonrpc":"2.0","id":1,"result":{"contextId":"","history":[]}}`,
			want: false,
		},
		{
			// The false NEGATIVE this helper shipped with, and the one that cost
			// a2a-delegation-integrity-001 its whole oracle on the v1.0 wire. A v1.0
			// send-style reply is a SendMessageResponse, a protobuf oneof, so the Task
			// arrives NESTED under result.task. Measured against an a2a-sdk agent with
			// no ownership check: B's continuation landed on A's task, the agent
			// returned A's task in this shape, and the rule reported the binding held.
			name: "v1.0 nested task envelope references it",
			body: `{"jsonrpc":"2.0","id":1,"result":{"task":{"id":"task-A","contextId":"ctx-A",` +
				`"status":{"state":"TASK_STATE_SUBMITTED"}}}}`,
			want: true,
		},
		{
			// The nested shape must discriminate as sharply as the flat one, or fixing
			// the false negative would buy a false positive: a tenant-scoped server
			// answering with a NEW task nests it exactly the same way.
			name: "a different task nested is still not A's task",
			body: `{"jsonrpc":"2.0","id":1,"result":{"task":{"id":"task-B-7","contextId":"ctx-B"}}}`,
			want: false,
		},
		{
			name: "A's context nested is enough",
			body: `{"jsonrpc":"2.0","id":1,"result":{"task":{"id":"task-A-2","contextId":"ctx-A"}}}`,
			want: true,
		},
		{
			// The other oneof member. A Message carries no task identifiers, so nothing
			// can be established from it either way.
			name: "v1.0 nested message result establishes nothing",
			body: `{"jsonrpc":"2.0","id":1,"result":{"message":{"messageId":"m1","role":"ROLE_AGENT"}}}`,
			want: false,
		},
		{
			name: "an error envelope does not match",
			body: `{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"Task not found"}}`,
			want: false,
		},
		{
			name: "unparseable body does not match",
			body: `not json`,
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resultReferencesTask([]byte(tc.body), taskID, ctxID); got != tc.want {
				t.Errorf("resultReferencesTask(%s) = %v, want %v", tc.body, got, tc.want)
			}
		})
	}
}

// The oracle this replaced was ContainsAny(`"tasks"`, `"contextId"`, `"history"`) over
// the raw body: key names, present in a correctly scoped EMPTY response. That made
// a2a-task-idor-001 report "server-wide task disclosure" at critical/confirmed against
// a server that disclosed nothing, which is the highest-severity instance of the
// vacuous-needle class corrected in #163 and #169.
func TestCountListedTasks(t *testing.T) {
	cases := []struct {
		name string
		body string
		want int
	}{
		{
			// The live false positive: correctly scoped, nothing disclosed.
			name: "an empty list discloses nothing",
			body: `{"tasks":[],"totalSize":0}`,
			want: 0,
		},
		{
			name: "one task in the documented envelope",
			body: `{"tasks":[{"id":"t1","contextId":"c1"}],"totalSize":1}`,
			want: 1,
		},
		{
			name: "several tasks",
			body: `{"tasks":[{"id":"t1"},{"id":"t2"},{"id":"t3"}]}`,
			want: 3,
		},
		{
			// Some REST bindings answer with a bare array.
			name: "a bare array counts too",
			body: `[{"id":"t1"},{"id":"t2"}]`,
			want: 2,
		},
		{
			name: "an empty bare array discloses nothing",
			body: `[]`,
			want: 0,
		},
		{
			// A count without the tasks is not the tasks. It may hint at a scoping
			// problem, but nothing was disclosed that can be named.
			name: "a total with no tasks discloses nothing",
			body: `{"totalSize":42,"tasks":[]}`,
			want: 0,
		},
		{
			name: "placeholder objects disclose nothing",
			body: `{"tasks":[{},{"id":""},{"history":[]}]}`,
			want: 0,
		},
		{
			// No id, but a status was disclosed: something about a task came back.
			name: "an element with any real field counts",
			body: `{"tasks":[{"status":{"state":"working"}}]}`,
			want: 1,
		},
		{
			name: "a body that is not a list at all",
			body: `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}`,
			want: 0,
		},
		{
			name: "unparseable body",
			body: `not json`,
			want: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := countListedTasks([]byte(tc.body)); got != tc.want {
				t.Errorf("countListedTasks(%s) = %d, want %d", tc.body, got, tc.want)
			}
		})
	}
}
