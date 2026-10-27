package mcp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcp "github.com/calbebop/batesian/internal/attack/mcp"
)

type taskAccessFixture struct {
	mu              sync.Mutex
	calls           int
	updates         int
	cancels         int
	shared          bool
	inputNeeded     bool
	secondActive    bool
	badRead         bool
	dedup           bool
	ackUnknown      bool
	fakeUnknownRead bool
}

func (f *taskAccessFixture) handler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     json.RawMessage        `json:"id"`
		Method string                 `json:"method"`
		Params map[string]interface{} `json:"params"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	respond := func(result interface{}, code int, message string) {
		w.Header().Set("Content-Type", "application/json")
		body := map[string]interface{}{"jsonrpc": "2.0", "id": req.ID}
		if code != 0 {
			body["error"] = map[string]interface{}{"code": code, "message": message}
		} else {
			body["result"] = result
		}
		_ = json.NewEncoder(w).Encode(body)
	}
	if req.Method == "initialize" {
		respond(nil, -32601, "Method not found")
		return
	}
	meta, _ := req.Params["_meta"].(map[string]interface{})
	caps, _ := meta["io.modelcontextprotocol/clientCapabilities"].(map[string]interface{})
	extensions, _ := caps["extensions"].(map[string]interface{})
	if r.Header.Get("MCP-Protocol-Version") != "2026-07-28" ||
		r.Header.Get("Mcp-Method") != req.Method ||
		meta["io.modelcontextprotocol/protocolVersion"] != "2026-07-28" ||
		extensions["io.modelcontextprotocol/tasks"] == nil {
		respond(nil, -32020, "HeaderMismatch")
		return
	}
	principal := r.Header.Get("Authorization")
	if principal == "Bearer tok-a" && r.Header.Get("X-Tenant-Id") != "A" ||
		principal == "Bearer tok-b" && r.Header.Get("X-Tenant-Id") != "B" {
		respond(nil, -32602, "wrong tenant route")
		return
	}
	switch req.Method {
	case "server/discover":
		respond(map[string]interface{}{
			"resultType": "complete", "supportedVersions": []string{"2026-07-28"},
			"capabilities": map[string]interface{}{
				"tools":      map[string]interface{}{},
				"extensions": map[string]interface{}{"io.modelcontextprotocol/tasks": map[string]interface{}{}},
			},
		}, 0, "")
	case "tools/list":
		if principal != "Bearer tok-a" {
			respond(nil, -32602, "not authorized")
			return
		}
		respond(map[string]interface{}{"resultType": "complete", "tools": []interface{}{
			map[string]interface{}{
				"name": "wait_a_moment", "annotations": map[string]interface{}{"readOnlyHint": true},
				"inputSchema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
			},
		}}, 0, "")
	case "tools/call":
		if principal != "Bearer tok-a" || r.Header.Get("Mcp-Name") != "wait_a_moment" {
			respond(nil, -32602, "not authorized")
			return
		}
		f.mu.Lock()
		f.calls++
		call := f.calls
		f.mu.Unlock()
		if f.dedup {
			call = 1
		}
		status := "working"
		if call == 1 && f.inputNeeded {
			status = "input_required"
		}
		respond(map[string]interface{}{"resultType": "task", "taskId": "task-" + string(rune('0'+call)), "status": status}, 0, "")
	case "tasks/get", "tasks/update", "tasks/cancel":
		taskID, _ := req.Params["taskId"].(string)
		if r.Header.Get("Mcp-Name") != taskID {
			respond(nil, -32020, "HeaderMismatch")
			return
		}
		if taskID != "task-1" && taskID != "task-2" {
			if f.fakeUnknownRead && req.Method == "tasks/get" {
				respond(map[string]interface{}{"resultType": "complete", "taskId": taskID, "status": "working"}, 0, "")
			} else if f.ackUnknown && req.Method != "tasks/get" {
				respond(map[string]interface{}{"resultType": "complete"}, 0, "")
			} else {
				respond(nil, -32602, "task not found")
			}
			return
		}
		if principal == "Bearer tok-b" && !f.shared {
			respond(nil, -32602, "task not found")
			return
		}
		if principal != "Bearer tok-a" && principal != "Bearer tok-b" {
			respond(nil, -32602, "task not found")
			return
		}
		switch req.Method {
		case "tasks/get":
			status := "working"
			if taskID == "task-1" && f.inputNeeded {
				status = "input_required"
			}
			if taskID == "task-2" && !f.secondActive {
				status = "completed"
			}
			result := map[string]interface{}{"resultType": "complete", "taskId": taskID, "status": status}
			if status == "completed" {
				result["result"] = map[string]interface{}{"content": []interface{}{}}
			}
			if status == "input_required" {
				result["inputRequests"] = map[string]interface{}{"probe-input": map[string]interface{}{
					"method": "elicitation/create", "params": map[string]interface{}{"mode": "form"},
				}}
			}
			if f.badRead && principal == "Bearer tok-b" {
				result["taskId"] = "another-task"
			}
			respond(result, 0, "")
		case "tasks/update":
			responses, _ := req.Params["inputResponses"].(map[string]interface{})
			decline, _ := responses["probe-input"].(map[string]interface{})
			if taskID != "task-1" || !f.inputNeeded || decline["action"] != "decline" || len(decline) != 1 {
				respond(nil, -32602, "invalid update")
				return
			}
			f.mu.Lock()
			f.updates++
			f.mu.Unlock()
			respond(map[string]interface{}{"resultType": "complete"}, 0, "")
		case "tasks/cancel":
			if taskID != "task-2" && principal != "Bearer tok-a" {
				respond(nil, -32602, "wrong task")
				return
			}
			if principal == "Bearer tok-b" {
				f.mu.Lock()
				f.cancels++
				f.mu.Unlock()
			}
			respond(map[string]interface{}{"resultType": "complete"}, 0, "")
		}
	default:
		respond(nil, -32601, "Method not found")
	}
}

func taskAccessOptions() attack.Options {
	return attack.Options{TimeoutSeconds: 5, MCPInvokeTools: []string{"wait_a_moment"}, Principals: []attack.Principal{
		{Name: "tenant-a", Token: "tok-a", Tenant: "A", Headers: map[string]string{"X-Tenant-Id": "A"}},
		{Name: "tenant-b", Token: "tok-b", Tenant: "B", Headers: map[string]string{"X-Tenant-Id": "B"}},
	}}
}

func runTaskAccess(t *testing.T, fixture *taskAccessFixture, opts attack.Options) ([]attack.Finding, error) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(fixture.handler))
	defer srv.Close()
	return mcp.NewTaskAccessExecutor(attack.RuleContext{ID: "mcp-task-access-001", Name: "Task access"}).
		Execute(context.Background(), srv.URL, opts)
}

func TestTaskAccessSharedAndProtected(t *testing.T) {
	for _, shared := range []bool{false, true} {
		fixture := &taskAccessFixture{shared: shared, inputNeeded: true, secondActive: true}
		findings, err := runTaskAccess(t, fixture, taskAccessOptions())
		if err != nil {
			t.Fatalf("shared=%v: %v", shared, err)
		}
		want := 0
		if shared {
			want = 3
		}
		if len(findings) != want {
			t.Fatalf("shared=%v: got %d findings, want %d: %+v", shared, len(findings), want, findings)
		}
		for _, finding := range findings {
			if finding.Confidence != attack.RiskIndicator || finding.Access == nil ||
				finding.Access.Caller != "tenant-b" || finding.Access.Owner != "tenant-a" ||
				finding.Access.CallerTenant != "B" || finding.Access.OwnerTenant != "A" ||
				strings.Contains(finding.Evidence, "task-1") || strings.Contains(finding.Evidence, "task-2") {
				t.Fatalf("unsafe or misattributed finding: %+v", finding)
			}
		}
		if fixture.calls != 2 {
			t.Fatalf("shared=%v: tool calls = %d, want 2", shared, fixture.calls)
		}
		if fixture.updates != want/3 || fixture.cancels != want/3 {
			t.Fatalf("shared=%v: updates=%d cancels=%d", shared, fixture.updates, fixture.cancels)
		}
	}
}

func TestTaskAccessSkipsUnsafeActions(t *testing.T) {
	fixture := &taskAccessFixture{shared: true, inputNeeded: false, secondActive: false}
	findings, err := runTaskAccess(t, fixture, taskAccessOptions())
	if err == nil || !strings.Contains(err.Error(), "tasks/update was not tested") || !strings.Contains(err.Error(), "cancellation task") {
		t.Fatalf("expected inactive cancellation task to be not tested: findings=%+v err=%v", findings, err)
	}
	if len(findings) != 1 || fixture.updates != 0 || fixture.cancels != 0 {
		t.Fatalf("unsafe action was attempted: findings=%+v fixture=%+v", findings, fixture)
	}
}

func TestTaskAccessRequiresToolApproval(t *testing.T) {
	fixture := &taskAccessFixture{shared: true, inputNeeded: true, secondActive: true}
	opts := taskAccessOptions()
	opts.MCPInvokeTools = nil
	findings, err := runTaskAccess(t, fixture, opts)
	if len(findings) != 0 || err == nil || !strings.Contains(err.Error(), "--mcp-invoke-tool") || fixture.calls != 0 {
		t.Fatalf("tool invoked without exact approval: findings=%+v err=%v calls=%d", findings, err, fixture.calls)
	}
}

func TestTaskAccessRejectsUnrelatedRead(t *testing.T) {
	fixture := &taskAccessFixture{shared: true, inputNeeded: true, secondActive: true, badRead: true}
	findings, err := runTaskAccess(t, fixture, taskAccessOptions())
	if err == nil || !strings.Contains(err.Error(), "tasks/get") || len(findings) != 2 {
		t.Fatalf("unrelated read must not become access: findings=%+v err=%v", findings, err)
	}
}

func TestTaskAccessDoesNotCancelReusedTask(t *testing.T) {
	fixture := &taskAccessFixture{shared: true, inputNeeded: true, secondActive: true, dedup: true}
	findings, err := runTaskAccess(t, fixture, taskAccessOptions())
	if err == nil || !strings.Contains(err.Error(), "reused the first task handle") || fixture.cancels != 0 || len(findings) != 2 {
		t.Fatalf("reused handle was cancelled as a second task: findings=%+v err=%v cancels=%d", findings, err, fixture.cancels)
	}
}

func TestTaskAccessPolicyPromotesOnlyMatchingRelationship(t *testing.T) {
	fixture := &taskAccessFixture{shared: true, inputNeeded: true, secondActive: true}
	findings, err := runTaskAccess(t, fixture, taskAccessOptions())
	if err != nil || len(findings) != 3 {
		t.Fatalf("findings=%+v err=%v", findings, err)
	}
	denials := []attack.ExpectedDenial{{Operation: attack.MCPTasksGet, Caller: "tenant-b", CallerTenant: "B", Owner: "tenant-a", OwnerTenant: "A"}}
	for i := range findings {
		promoted := attack.ApplyExpectedDenial(&findings[i], denials)
		if promoted != (findings[i].Access.Operation == attack.MCPTasksGet) {
			t.Errorf("unexpected policy match for %s", findings[i].Access.Operation)
		}
	}
}

func TestTaskAccessGenericAcknowledgementsAreNotFindings(t *testing.T) {
	fixture := &taskAccessFixture{shared: true, inputNeeded: true, secondActive: true, ackUnknown: true}
	findings, err := runTaskAccess(t, fixture, taskAccessOptions())
	if err == nil || !strings.Contains(err.Error(), "nonexistent task") || len(findings) != 1 ||
		fixture.updates != 0 || fixture.cancels != 0 {
		t.Fatalf("generic acknowledgements counted as task access: findings=%+v err=%v fixture=%+v", findings, err, fixture)
	}
}

func TestTaskAccessFabricatedUnknownReadIsNotFinding(t *testing.T) {
	fixture := &taskAccessFixture{shared: true, inputNeeded: true, secondActive: true, fakeUnknownRead: true}
	findings, err := runTaskAccess(t, fixture, taskAccessOptions())
	if err == nil || !strings.Contains(err.Error(), "tasks/get did not reject a nonexistent task") || len(findings) != 2 {
		t.Fatalf("fabricated task read counted as owner access: findings=%+v err=%v", findings, err)
	}
}
