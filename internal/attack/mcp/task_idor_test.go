package mcp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

// taskIDORServer builds a mock MCP 2025-11-25 server with the tasks capability.
// Behaviour depends on mode:
//
//   - "vuln":          tasks are not scoped, so any session reads any task =>
//     both the tasks/get and tasks/result findings.
//   - "metadata-only": tasks/get leaks across sessions but tasks/result is
//     scoped => only the tasks/get finding.
//   - "secure":        tasks are bound to the creating session => silent.
//   - "no-auth":       task creation succeeds with no credentials, so the
//     discriminator suppresses the finding => silent.
//   - "no-tasks-cap":  the tasks capability is absent => skip.
//   - "unsafe-tool":   the only task-capable tool carries no safety annotations,
//     so the rule refuses to invoke it => skip.
//   - "not-mcp":       everything 404s => silent.
func taskIDORServer(mode string) *httptest.Server {
	var mu sync.Mutex
	sessions := 0
	// taskID -> owning session id
	owner := map[string]string{}
	tasks := 0

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mode == "not-mcp" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		method, _ := req["method"].(string)
		params, _ := req["params"].(map[string]interface{})
		id := req["id"]
		sid := r.Header.Get("Mcp-Session-Id")
		authed := strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ")
		w.Header().Set("Content-Type", "application/json")

		result := func(v interface{}) {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": id, "result": v})
		}
		rpcErr := func(code int, msg string) {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": id,
				"error": map[string]interface{}{"code": code, "message": msg}})
		}

		switch method {
		case "initialize":
			mu.Lock()
			sessions++
			newSID := fmt.Sprintf("sess-%d", sessions)
			mu.Unlock()
			caps := map[string]interface{}{"tools": map[string]interface{}{}}
			if mode != "no-tasks-cap" {
				caps["tasks"] = map[string]interface{}{
					"list":     map[string]interface{}{},
					"cancel":   map[string]interface{}{},
					"requests": map[string]interface{}{"tools": map[string]interface{}{"call": map[string]interface{}{}}},
				}
			}
			w.Header().Set("Mcp-Session-Id", newSID)
			result(map[string]interface{}{
				"protocolVersion": "2025-11-25",
				"serverInfo":      map[string]interface{}{"name": "task-srv", "version": "1.0"},
				"capabilities":    caps,
			})

		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)

		case "tools/list":
			tool := map[string]interface{}{
				"name":        "research",
				"description": "long running research",
				"execution":   map[string]interface{}{"taskSupport": "required"},
				"inputSchema": map[string]interface{}{
					"type":       "object",
					"properties": map[string]interface{}{"topic": map[string]interface{}{"type": "string"}},
				},
			}
			// The rule refuses to invoke a tool that does not declare itself safe.
			if mode != "unsafe-tool" {
				tool["annotations"] = map[string]interface{}{"readOnlyHint": false, "destructiveHint": false}
			}
			result(map[string]interface{}{"tools": []interface{}{tool}})

		case "tools/call":
			if _, isTask := params["task"]; !isTask {
				rpcErr(-32600, "task augmentation required")
				return
			}
			// Every mode except no-auth requires credentials to create a task.
			if mode != "no-auth" && !authed {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			mu.Lock()
			tasks++
			tid := fmt.Sprintf("task-%d", tasks)
			owner[tid] = sid
			mu.Unlock()
			result(map[string]interface{}{"task": map[string]interface{}{
				"taskId": tid, "status": "working", "createdAt": "2026-07-20T07:00:00Z",
				"lastUpdatedAt": "2026-07-20T07:00:00Z", "ttl": 60000, "pollInterval": 10,
			}})

		case "tasks/get":
			tid, _ := params["taskId"].(string)
			mu.Lock()
			own, exists := owner[tid]
			mu.Unlock()
			if !exists || (mode == "secure" && own != sid) {
				rpcErr(-32602, "Task not found")
				return
			}
			// Terminal immediately so the rule can proceed to tasks/result without
			// burning its polling budget.
			result(map[string]interface{}{
				"taskId": tid, "status": "completed", "statusMessage": "done",
				"createdAt": "2026-07-20T07:00:00Z", "lastUpdatedAt": "2026-07-20T07:00:05Z", "ttl": 60000,
			})

		case "tasks/result":
			tid, _ := params["taskId"].(string)
			mu.Lock()
			own, exists := owner[tid]
			mu.Unlock()
			if !exists || mode == "metadata-only" || (mode == "secure" && own != sid) {
				rpcErr(-32602, "Task not found")
				return
			}
			result(map[string]interface{}{
				"content": []interface{}{map[string]interface{}{"type": "text", "text": "CONFIDENTIAL research output"}},
				"isError": false,
			})

		default:
			rpcErr(-32601, "Method not found")
		}
	}))
}

func runTaskIDOR(t *testing.T, srv *httptest.Server) []attack.Finding {
	t.Helper()
	exec := mcpattack.NewTaskIDORExecutor(attack.RuleContext{ID: "mcp-task-idor-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{
		TimeoutSeconds: 5,
		Principals: []attack.Principal{
			{Name: "tenant-a", Token: "tok-a"},
			{Name: "tenant-b", Token: "tok-b"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return findings
}

// TestTaskIDOR_CrossContext: B reads A's task and its result => both findings.
func TestTaskIDOR_CrossContext(t *testing.T) {
	srv := taskIDORServer("vuln")
	defer srv.Close()

	findings := runTaskIDOR(t, srv)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (tasks/get + tasks/result), got %d: %+v", len(findings), findings)
	}
	var high, critical bool
	for _, f := range findings {
		if f.Confidence != attack.ConfirmedExploit {
			t.Errorf("expected ConfirmedExploit, got %v", f.Confidence)
		}
		switch f.Severity {
		case "high":
			high = true
		case "critical":
			critical = true
			if !strings.Contains(f.Evidence, "CONFIDENTIAL research output") {
				t.Errorf("result finding should cite the disclosed output, got evidence %q", f.Evidence)
			}
		}
	}
	if !high || !critical {
		t.Errorf("expected both high and critical findings, got high=%v critical=%v", high, critical)
	}
}

// TestTaskIDOR_MetadataOnly: tasks/get leaks but tasks/result is scoped.
func TestTaskIDOR_MetadataOnly(t *testing.T) {
	srv := taskIDORServer("metadata-only")
	defer srv.Close()

	findings := runTaskIDOR(t, srv)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding (metadata only), got %d: %+v", len(findings), findings)
	}
	if findings[0].Severity != "high" {
		t.Errorf("expected the high tasks/get finding, got %q", findings[0].Severity)
	}
}

// TestTaskIDOR_Secure: tasks bound to the creating session => silent.
func TestTaskIDOR_Secure(t *testing.T) {
	srv := taskIDORServer("secure")
	defer srv.Close()

	if findings := runTaskIDOR(t, srv); len(findings) != 0 {
		t.Errorf("expected 0 findings for session-scoped tasks, got %d: %+v", len(findings), findings)
	}
}

// TestTaskIDOR_NoAuthSuppressed: anonymous task creation succeeds, so this is a
// missing-authentication failure rather than an IDOR and must be suppressed.
func TestTaskIDOR_NoAuthSuppressed(t *testing.T) {
	srv := taskIDORServer("no-auth")
	defer srv.Close()

	if findings := runTaskIDOR(t, srv); len(findings) != 0 {
		t.Errorf("expected 0 findings when the server enforces no auth at all, got %d: %+v", len(findings), findings)
	}
}

// TestTaskIDOR_NoTasksCapability: server does not advertise tasks => skip.
func TestTaskIDOR_NoTasksCapability(t *testing.T) {
	srv := taskIDORServer("no-tasks-cap")
	defer srv.Close()

	if findings := runTaskIDOR(t, srv); len(findings) != 0 {
		t.Errorf("expected 0 findings without the tasks capability, got %d: %+v", len(findings), findings)
	}
}

// TestTaskIDOR_UnsafeToolSkipped: the only task-capable tool carries no safety
// annotations, so the rule must refuse to invoke it.
func TestTaskIDOR_UnsafeToolSkipped(t *testing.T) {
	srv := taskIDORServer("unsafe-tool")
	defer srv.Close()

	if findings := runTaskIDOR(t, srv); len(findings) != 0 {
		t.Errorf("expected 0 findings when no safely-annotated task tool exists, got %d: %+v", len(findings), findings)
	}
}

// TestTaskIDOR_NotMCP: initialize fails => silent.
func TestTaskIDOR_NotMCP(t *testing.T) {
	srv := taskIDORServer("not-mcp")
	defer srv.Close()

	if findings := runTaskIDOR(t, srv); len(findings) != 0 {
		t.Errorf("expected 0 findings for a non-MCP server, got %d: %+v", len(findings), findings)
	}
}
