package endpoint

import (
	"reflect"
	"testing"
)

// mcpPaths mirrors the MCP rule set's conventional paths, so the cases below
// read as the situations an operator actually hits.
var mcpPaths = []string{"/mcp", "/", "/api", "/rpc"}

func TestCandidates(t *testing.T) {
	tests := []struct {
		name  string
		base  string
		paths []string
		want  []string
	}{
		{
			// The historical behaviour, unchanged: nothing to preserve, so the
			// list is exactly the appended forms in the original order.
			name:  "bare origin appends only",
			base:  "http://127.0.0.1:3181",
			paths: mcpPaths,
			want: []string{
				"http://127.0.0.1:3181/mcp",
				"http://127.0.0.1:3181/",
				"http://127.0.0.1:3181/api",
				"http://127.0.0.1:3181/rpc",
			},
		},
		{
			// The bug this fixes. Appending alone reaches /mcp/mcp and friends
			// but never /mcp, so every rule reported no testable endpoint.
			name:  "path target is probed as given, first",
			base:  "http://127.0.0.1:3181/mcp",
			paths: mcpPaths,
			want: []string{
				"http://127.0.0.1:3181/mcp",
				"http://127.0.0.1:3181/mcp/mcp",
				"http://127.0.0.1:3181/mcp/",
				"http://127.0.0.1:3181/mcp/api",
				"http://127.0.0.1:3181/mcp/rpc",
			},
		},
		{
			// A trailing slash is the same target, and previously produced a
			// doubled separator (http://host/mcp//mcp) that servers 404.
			name:  "trailing slash on a path target",
			base:  "http://127.0.0.1:3181/mcp/",
			paths: mcpPaths,
			want: []string{
				"http://127.0.0.1:3181/mcp",
				"http://127.0.0.1:3181/mcp/mcp",
				"http://127.0.0.1:3181/mcp/",
				"http://127.0.0.1:3181/mcp/api",
				"http://127.0.0.1:3181/mcp/rpc",
			},
		},
		{
			name:  "trailing slash on an origin is not a path",
			base:  "https://mcp.example.com/",
			paths: mcpPaths,
			want: []string{
				"https://mcp.example.com/mcp",
				"https://mcp.example.com/",
				"https://mcp.example.com/api",
				"https://mcp.example.com/rpc",
			},
		},
		{
			name:  "nested path target",
			base:  "https://example.com/services/agent/mcp",
			paths: []string{"/mcp", "/"},
			want: []string{
				"https://example.com/services/agent/mcp",
				"https://example.com/services/agent/mcp/mcp",
				"https://example.com/services/agent/mcp/",
			},
		},
		{
			// A2A's list leads with "/", which for a path target collides with
			// nothing but must not reorder the rest.
			name:  "a2a paths on a path target",
			base:  "https://example.com/a2a",
			paths: []string{"/", "/a2a/jsonrpc", "/a2a", "/rpc"},
			want: []string{
				"https://example.com/a2a",
				"https://example.com/a2a/",
				"https://example.com/a2a/a2a/jsonrpc",
				"https://example.com/a2a/a2a",
				"https://example.com/a2a/rpc",
			},
		},
		{
			// An empty path entry would otherwise repeat the target.
			name:  "duplicates are collapsed, order preserved",
			base:  "https://example.com/mcp",
			paths: []string{"", "/mcp", ""},
			want: []string{
				"https://example.com/mcp",
				"https://example.com/mcp/mcp",
			},
		},
		{
			// Nothing here should panic or drop the caller's paths just because
			// the target will not parse.
			name:  "unparseable target still yields the appended forms",
			base:  "http://[::1",
			paths: []string{"/mcp"},
			want:  []string{"http://[::1/mcp"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Candidates(tt.base, tt.paths)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Candidates(%q, %v):\n got %q\nwant %q", tt.base, tt.paths, got, tt.want)
			}
		})
	}
}

// The caller's slice of paths is package-level state in both rule sets, so
// Candidates must not write through to it.
func TestCandidates_DoesNotMutateInput(t *testing.T) {
	paths := []string{"/mcp", "/", "/api", "/rpc"}
	before := append([]string(nil), paths...)

	Candidates("https://example.com/mcp", paths)

	if !reflect.DeepEqual(paths, before) {
		t.Errorf("Candidates mutated its paths argument: got %q, want %q", paths, before)
	}
}
