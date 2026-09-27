package a2a

import "testing"

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
