package mcp_test

import (
	"context"
	"encoding/json"
	"errors"
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
//   - "no-auth":       nothing requires credentials, on creation or on reads, so
//     the discriminator suppresses the finding => silent.
//   - "create-open":   task creation needs no credentials but reads do, and reads
//     are not scoped. Authentication really is enforced on the surface this rule
//     tests, so the boundary B crosses is real => both findings.
//   - "anon-create-envelope": anonymous creation is refused with a JSON-RPC
//     error envelope at HTTP 200, the spec'd refusal shape, while reads are
//     unscoped. The refusal is a verdict, so the rule proceeds; it used to read
//     as no verdict and suppress the rule.
//   - "no-tasks-cap":  the tasks capability is absent => skip.
//   - "unsafe-tool":   the only task-capable tool carries no safety annotations,
//     so the rule refuses to invoke it => skip.
//   - "not-mcp":       everything 404s => silent.
//   - "anon-init-hidden": initialize without a bearer 404s (the endpoint is
//     hidden from anonymous callers) while credentialed initialize works.
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
			if mode == "anon-init-hidden" && !authed {
				// The auth middleware hides the endpoint from anonymous callers
				// rather than answering 401: an unanswered control, not an
				// observed refusal (classifyInitFailure treats 404 as a routing
				// miss, correctly).
				w.WriteHeader(http.StatusNotFound)
				return
			}
			mu.Lock()
			sessions++
			newSID := fmt.Sprintf("sess-%d", sessions)
			mu.Unlock()
			caps := map[string]interface{}{"tools": map[string]interface{}{}}
			if mode != "no-tasks-cap" {
				tasksCap := map[string]interface{}{
					"cancel":   map[string]interface{}{},
					"requests": map[string]interface{}{"tools": map[string]interface{}{"call": map[string]interface{}{}}},
				}
				if mode != "no-list-cap" {
					tasksCap["list"] = map[string]interface{}{}
				}
				caps["tasks"] = tasksCap
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
			// Only no-auth and create-open let an anonymous caller create a task.
			if mode != "no-auth" && mode != "create-open" && !authed {
				if mode == "anon-create-envelope" {
					// The spec'd refusal shape: a JSON-RPC error envelope at
					// HTTP 200. That is a real answer, not a missing verdict.
					rpcErr(-32001, "Unauthorized")
					return
				}
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
			// create-open gates the read surface even though creation is open.
			if mode == "create-open" && !authed {
				rpcErr(-32001, "Unauthorized")
				return
			}
			tid, _ := params["taskId"].(string)
			mu.Lock()
			own, exists := owner[tid]
			mu.Unlock()
			if !exists || ((mode == "secure" || mode == "list-only") && own != sid) {
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
			if mode == "create-open" && !authed {
				rpcErr(-32001, "Unauthorized")
				return
			}
			tid, _ := params["taskId"].(string)
			mu.Lock()
			own, exists := owner[tid]
			mu.Unlock()
			if !exists || mode == "metadata-only" || mode == "list-only" || (mode == "secure" && own != sid) {
				rpcErr(-32602, "Task not found")
				return
			}
			result(map[string]interface{}{
				"content": []interface{}{map[string]interface{}{"type": "text", "text": "CONFIDENTIAL research output"}},
				"isError": false,
			})

		case "tasks/list":
			if mode == "create-open" && !authed {
				rpcErr(-32001, "Unauthorized")
				return
			}
			mu.Lock()
			var listed []interface{}
			for tid, own := range owner {
				// A correctly-scoped server returns only the caller's own tasks.
				if (mode == "secure" || mode == "metadata-only") && own != sid {
					continue
				}
				listed = append(listed, map[string]interface{}{"taskId": tid, "status": "completed"})
			}
			mu.Unlock()
			result(map[string]interface{}{"tasks": listed})

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

// TestTaskIDOR_HiddenAnonInitializeIsNotTested: the anonymous initialize
// control was never answered - this server hides the endpoint from anonymous
// callers (404) instead of refusing it (401), and classifyInitFailure is right
// that a routing miss is not a refused handshake. The rule used to keep the
// default evidence line "anonymous initialize: refused" and proceed anyway,
// stamping a refusal it never observed into any finding it emitted; a server
// that hides from anonymous callers may still scope tasks per authorization
// context either way, so the rule reports not tested.
func TestTaskIDOR_HiddenAnonInitializeIsNotTested(t *testing.T) {
	srv := taskIDORServer("anon-init-hidden")
	defer srv.Close()

	exec := mcpattack.NewTaskIDORExecutor(attack.RuleContext{ID: "mcp-task-idor-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{
		TimeoutSeconds: 5,
		Principals: []attack.Principal{
			{Name: "tenant-a", Token: "tok-a"},
			{Name: "tenant-b", Token: "tok-b"},
		},
	})
	if len(findings) != 0 {
		t.Fatalf("expected no findings when the anonymous control went unanswered, got %d: %+v", len(findings), findings)
	}
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected ErrInconclusive, got %v", err)
	}
	if !strings.Contains(err.Error(), "returned no verdict") {
		t.Errorf("reason should name the unanswered control: %v", err)
	}
}

// TestTaskIDOR_AnonCreationRefusedAt200StillTestsScoping: the anonymous control
// had task creation refused with a JSON-RPC error envelope at HTTP 200, which
// is the spec'd refusal shape and a real answer. createTask used to read it as
// no verdict, so the discriminator suppressed the whole rule with "the
// anonymous control returned no verdict" on exactly the servers that refuse
// politely; getTask in the same file already read the identical shape as a
// refusal. The refusal is also what the findings' evidence records.
func TestTaskIDOR_AnonCreationRefusedAt200StillTestsScoping(t *testing.T) {
	srv := taskIDORServer("anon-create-envelope")
	defer srv.Close()

	findings := runTaskIDOR(t, srv)
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings (tasks/get + tasks/result + tasks/list), got %d: %+v", len(findings), findings)
	}
	for _, f := range findings {
		if !strings.Contains(f.Evidence, "anonymous task creation: refused") {
			t.Errorf("evidence should record the observed anonymous refusal: %s", f.Evidence)
		}
	}
}

// TestTaskIDOR_CrossContext: B reads A's task and its result => both findings.
func TestTaskIDOR_CrossContext(t *testing.T) {
	srv := taskIDORServer("vuln")
	defer srv.Close()

	findings := runTaskIDOR(t, srv)
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings (tasks/get + tasks/result + tasks/list), got %d: %+v", len(findings), findings)
	}
	// Identify each failure by the method it names: severity alone is ambiguous
	// now that both the result leak and the enumeration are critical.
	var sawGet, sawResult, sawList bool
	for _, f := range findings {
		if f.Confidence != attack.ConfirmedExploit {
			t.Errorf("expected ConfirmedExploit, got %v", f.Confidence)
		}
		switch {
		case strings.Contains(f.Title, "tasks/get"):
			sawGet = true
			if f.Severity != "high" {
				t.Errorf("tasks/get finding should be high, got %q", f.Severity)
			}
		case strings.Contains(f.Title, "tasks/result"):
			sawResult = true
			if f.Severity != "critical" {
				t.Errorf("tasks/result finding should be critical, got %q", f.Severity)
			}
			if !strings.Contains(f.Evidence, "CONFIDENTIAL research output") {
				t.Errorf("result finding should cite the disclosed output, got evidence %q", f.Evidence)
			}
		case strings.Contains(f.Title, "tasks/list"):
			sawList = true
			if f.Severity != "critical" {
				t.Errorf("tasks/list finding should be critical, got %q", f.Severity)
			}
		default:
			t.Errorf("unexpected finding title %q", f.Title)
		}
	}
	if !sawGet || !sawResult || !sawList {
		t.Errorf("expected all three failures, got get=%v result=%v list=%v", sawGet, sawResult, sawList)
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

// TestTaskIDOR_ListOnly: tasks/get and tasks/result are correctly scoped, but
// tasks/list still enumerates another session's tasks. The enumeration check
// must therefore run independently of the by-id checks.
func TestTaskIDOR_ListOnly(t *testing.T) {
	srv := taskIDORServer("list-only")
	defer srv.Close()

	findings := runTaskIDOR(t, srv)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding (enumeration only), got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != "critical" {
		t.Errorf("expected the critical enumeration finding, got %q", f.Severity)
	}
	if !strings.Contains(f.Title, "tasks/list") {
		t.Errorf("expected the tasks/list enumeration finding, got title %q", f.Title)
	}
}

// TestTaskIDOR_NoListCapability: the server does not advertise tasks.list, so
// only the by-id failure is reported and no enumeration is attempted.
func TestTaskIDOR_NoListCapability(t *testing.T) {
	srv := taskIDORServer("no-list-cap")
	defer srv.Close()

	findings := runTaskIDOR(t, srv)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (tasks/get + tasks/result, no enumeration), got %d: %+v", len(findings), findings)
	}
	for _, f := range findings {
		if strings.Contains(f.Title, "tasks/list") {
			t.Errorf("must not report enumeration when tasks.list is not advertised: %q", f.Title)
		}
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

// TestTaskIDOR_CreateOpenButReadsGated: task creation needs no credentials, but
// tasks/get, tasks/result and tasks/list all refuse an anonymous caller and none
// of them are scoped to the creator.
//
// Open creation alone used to suppress the whole rule, which lost this server. The
// suppression exists to avoid reporting an IDOR against a server that authenticates
// nothing, and this server does authenticate the surface the rule tests: anonymous
// reads are refused, authenticated reads are not, and any authenticated principal
// can read every other principal's task. That is the boundary the spec requires
// receivers to enforce, so it is reportable.
func TestTaskIDOR_CreateOpenButReadsGated(t *testing.T) {
	srv := taskIDORServer("create-open")
	defer srv.Close()

	findings := runTaskIDOR(t, srv)
	if len(findings) == 0 {
		t.Fatal("expected findings: reads are gated and unscoped, so an authorization boundary was crossed")
	}

	// The evidence must describe the boundary that was actually measured. Here that
	// is the refused anonymous read, not a refused creation, which did not happen.
	for _, f := range findings {
		if strings.Contains(f.Evidence, "anonymous task creation: refused") {
			t.Errorf("evidence claims anonymous creation was refused, but this server accepts it: %s", f.Evidence)
		}
		if !strings.Contains(f.Evidence, "anonymous tasks/get: refused") {
			t.Errorf("evidence should cite the anonymous read that was refused, got: %s", f.Evidence)
		}
		if !strings.Contains(f.Evidence, "task reads only (anonymous task creation was accepted)") {
			t.Errorf("evidence should record that only reads are authenticated, got: %s", f.Evidence)
		}
	}
}

// The default posture refuses anonymous task creation, so the discriminator stops
// there and never issues an anonymous read. The evidence must cite the refused
// creation rather than a read it did not attempt.
func TestTaskIDOR_EvidenceCitesTheProbeThatRan(t *testing.T) {
	srv := taskIDORServer("vuln")
	defer srv.Close()

	findings := runTaskIDOR(t, srv)
	if len(findings) == 0 {
		t.Fatal("expected findings against the unscoped server")
	}
	for _, f := range findings {
		if !strings.Contains(f.Evidence, "anonymous task creation: refused") {
			t.Errorf("evidence should cite the refused creation, got: %s", f.Evidence)
		}
		if strings.Contains(f.Evidence, "anonymous tasks/get: refused") {
			t.Errorf("no anonymous read was attempted, so the evidence must not cite one: %s", f.Evidence)
		}
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

	assertInconclusive(t, mcpattack.NewTaskIDORExecutor(attack.RuleContext{ID: "mcp-task-idor-001"}), srv.URL, testOpts())
}

// A server carrying tasks under the 2026-07-28 io.modelcontextprotocol/tasks
// extension has a task surface this rule cannot assess: the extension removed
// tasks/result and tasks/list and dropped the context-binding requirement the rule
// tests, so its oracle does not apply. That is different from a server with no
// tasks at all, and reporting it clean would assert task scoping is sound on a
// surface never touched.
func TestTaskIDOR_TasksExtensionIsNotTested(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		method, _ := req["method"].(string)
		id := req["id"]
		w.Header().Set("Content-Type", "application/json")
		if method == "initialize" {
			w.Header().Set("Mcp-Session-Id", "ext-1")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{
					"protocolVersion": "2025-06-18",
					"serverInfo":      map[string]interface{}{"name": "ext", "version": "1"},
					// The extension shape: no core "tasks" capability at all.
					"capabilities": map[string]interface{}{
						"tools": map[string]interface{}{},
						"extensions": map[string]interface{}{
							"io.modelcontextprotocol/tasks": map[string]interface{}{},
						},
					},
				}})
			return
		}
		if method == "notifications/initialized" {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": id,
			"error": map[string]interface{}{"code": -32601, "message": "Method not found"}})
	}))
	defer srv.Close()

	exec := mcpattack.NewTaskIDORExecutor(attack.RuleContext{ID: "mcp-task-idor-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("the extension wire is untested, not clean; got err=%v", err)
	}
	if !strings.Contains(err.Error(), "io.modelcontextprotocol/tasks") {
		t.Errorf("the reason should name the extension, got: %v", err)
	}
}

// A server with no tasks anywhere is genuinely not applicable, and must stay
// clean. This is the control that keeps the check above from becoming a blanket
// "any server without core tasks is untested".
func TestTaskIDOR_NoTasksAnywhereStaysClean(t *testing.T) {
	srv := taskIDORServer("no-tasks-cap")
	defer srv.Close()

	exec := mcpattack.NewTaskIDORExecutor(attack.RuleContext{ID: "mcp-task-idor-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, testOpts())
	if err != nil {
		t.Fatalf("a server with no tasks capability is not applicable, which is clean: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}
