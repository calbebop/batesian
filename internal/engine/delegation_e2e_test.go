package engine_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/engine"
	"github.com/calbebop/batesian/internal/rules"
)

// twoTenantDelegationServer is an A2A server wired so that, end-to-end:
//   - the multi-tenant rule (producer) creates a task for each tenant and
//     publishes their task-ids to the blackboard, but finds nothing (GetTask is
//     owner-bound, so cross-tenant reads are rejected);
//   - the delegation rule (consumer) reuses tenant A's published task-id and
//     continues it as tenant B, which the server wrongly allows.
//
// Creation and continuation are auth-gated (so the open-server discriminators in
// both rules pass); GetTask is owner-bound; continuation ignores ownership.
func twoTenantDelegationServer() *httptest.Server {
	var mu sync.Mutex
	owner := map[string]string{}

	tenantOf := func(r *http.Request) string {
		switch r.Header.Get("Authorization") {
		case "Bearer tok-a":
			return "A"
		case "Bearer tok-b":
			return "B"
		default:
			return ""
		}
	}
	write := func(w http.ResponseWriter, v interface{}) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	result := func(w http.ResponseWriter, id interface{}, taskID, ctxID string) {
		write(w, map[string]interface{}{
			"jsonrpc": "2.0", "id": id,
			"result": map[string]interface{}{"id": taskID, "contextId": ctxID, "status": "working",
				"history": []interface{}{map[string]interface{}{"role": "user", "parts": []interface{}{map[string]string{"text": "x"}}}}},
		})
	}
	rpcErr := func(w http.ResponseWriter, id interface{}, code int, msg string) {
		write(w, map[string]interface{}{"jsonrpc": "2.0", "id": id, "error": map[string]interface{}{"code": code, "message": msg}})
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req map[string]interface{}
		_ = json.Unmarshal(body, &req)
		method, _ := req["method"].(string)
		id := req["id"]
		params, _ := req["params"].(map[string]interface{})
		tenant := tenantOf(r)

		switch method {
		case "SendMessage", "message/send":
			msg, _ := params["message"].(map[string]interface{})
			contID, _ := msg["taskId"].(string)
			if contID == "" { // creation (auth-gated)
				if tenant == "" {
					rpcErr(w, id, -32600, "authentication required")
					return
				}
				mu.Lock()
				taskID := "task-" + tenant
				owner[taskID] = tenant
				mu.Unlock()
				result(w, id, taskID, "ctx-"+tenant)
				return
			}
			// continuation: auth enforced, but ownership IS NOT checked (the bug)
			if tenant == "" {
				rpcErr(w, id, -32600, "authentication required")
				return
			}
			mu.Lock()
			own := owner[contID]
			mu.Unlock()
			result(w, id, contID, "ctx-"+own)
		case "GetTask", "tasks/get":
			// Owner-bound read => the multi-tenant rule stays silent here.
			if tenant == "" {
				rpcErr(w, id, -32600, "authentication required")
				return
			}
			taskID, _ := params["id"].(string)
			mu.Lock()
			own := owner[taskID]
			mu.Unlock()
			if tenant != own {
				rpcErr(w, id, -32001, "task not found")
				return
			}
			result(w, id, taskID, "ctx-"+own)
		default:
			rpcErr(w, id, -32601, "Method not found")
		}
	}))
}

// TestE2E_DelegationConsumesMultiTenantTaskID runs the real multi-tenant
// (producer) and delegation (consumer) rules through the engine and asserts the
// engine ordered producer-before-consumer and that the consumer reused the
// task-id the producer published to the shared blackboard.
func TestE2E_DelegationConsumesMultiTenantTaskID(t *testing.T) {
	srv := twoTenantDelegationServer()
	defer srv.Close()

	opts := attack.Options{
		TimeoutSeconds: 5,
		Principals: []attack.Principal{
			{Name: "tenant-a", Token: "tok-a", Tenant: "A"},
			{Name: "tenant-b", Token: "tok-b", Tenant: "B"},
		},
	}
	eng := engine.New(opts)

	// Supplied consumer-first to prove the engine orders by dependency.
	rs := []*rules.Rule{
		ruleFor("a2a-delegation-integrity-001", "a2a-delegation-integrity"),
		ruleFor("a2a-multitenant-isolation-001", "a2a-multitenant-isolation"),
	}
	results := eng.Run(context.Background(), srv.URL, rs)

	idxProducer, idxConsumer := -1, -1
	var delegation *engine.RunResult
	for i := range results {
		switch results[i].Rule.ID {
		case "a2a-multitenant-isolation-001":
			idxProducer = i
		case "a2a-delegation-integrity-001":
			idxConsumer = i
			delegation = &results[i]
		}
	}
	if idxProducer == -1 || idxConsumer == -1 || idxProducer > idxConsumer {
		t.Fatalf("expected producer before consumer, got producer=%d consumer=%d", idxProducer, idxConsumer)
	}
	if delegation == nil || len(delegation.Findings) != 1 {
		t.Fatalf("expected exactly 1 delegation finding, got %+v", delegation)
	}
	f := delegation.Findings[0]
	if len(f.Chain) != 2 || f.Chain[1].Principal != "tenant-b" {
		t.Fatalf("expected 2-hop chain with tenant-b continuing, got %+v", f.Chain)
	}
	// The task must have come from the producer's blackboard artifact, not a
	// local creation - the chain hop-1 action records the provenance.
	if !contains(f.Chain[0].Action, "consumed from blackboard") {
		t.Errorf("expected the consumer to reuse the producer's task-id, got hop-1 %q", f.Chain[0].Action)
	}
	if !contains(f.Chain[0].Action, "task-A") {
		t.Errorf("expected the consumed task to be tenant A's, got hop-1 %q", f.Chain[0].Action)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
