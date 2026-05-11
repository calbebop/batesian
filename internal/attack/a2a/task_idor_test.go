package a2a_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/attack/a2a"
)

// TestTaskIDORExecutor_IDORConfirmed verifies that when GetTask succeeds for a
// task created by SendMessage (simulating a different unauthenticated caller),
// at least one finding is produced.
func TestTaskIDORExecutor_IDORConfirmed(t *testing.T) {
	const taskID = "task-idor-abc123"
	const ctxID = "ctx-idor-xyz789"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reject list endpoints to avoid extra critical findings.
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		body, _ := io.ReadAll(r.Body)
		var req map[string]interface{}
		_ = json.Unmarshal(body, &req)
		method, _ := req["method"].(string)
		id := req["id"]

		switch method {
		case "SendMessage", "message/send":
			// Return a task result so extractTaskContext can pull out the task ID.
			writeJSON(w, map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      id,
				"result": map[string]interface{}{
					"id":        taskID,
					"contextId": ctxID,
					"status":    "working",
				},
			})
		case "GetTask", "tasks/get":
			// Return the full task with history — simulates IDOR: any caller can read it.
			writeJSON(w, map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      id,
				"result": map[string]interface{}{
					"id":        taskID,
					"contextId": ctxID,
					"history": []interface{}{
						map[string]interface{}{
							"role":  "user",
							"parts": []interface{}{map[string]string{"text": "probe"}},
						},
					},
				},
			})
		default:
			writeJSON(w, map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      id,
				"error": map[string]interface{}{
					"code":    -32601,
					"message": "Method not found",
				},
			})
		}
	}))
	defer ts.Close()

	ex := a2a.NewTaskIDORExecutor(testRuleCtx())
	findings, err := ex.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one IDOR finding, got zero")
	}
	rc := testRuleCtx()
	for _, f := range findings {
		if f.RuleID != rc.ID {
			t.Errorf("finding has rule ID %q; want %q", f.RuleID, rc.ID)
		}
		if f.Severity == "" {
			t.Error("finding has empty severity")
		}
		if f.Title == "" {
			t.Error("finding has empty title")
		}
		if f.Confidence != attack.ConfirmedExploit {
			t.Errorf("finding %q: want ConfirmedExploit, got %q", f.Title, f.Confidence)
		}
	}
}

// TestTaskIDORExecutor_TaskNotFound verifies that when GetTask returns a
// JSON-RPC error (task not found / access denied), zero findings are produced.
func TestTaskIDORExecutor_TaskNotFound(t *testing.T) {
	const taskID = "task-idor-notfound"
	const ctxID = "ctx-idor-notfound"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		body, _ := io.ReadAll(r.Body)
		var req map[string]interface{}
		_ = json.Unmarshal(body, &req)
		method, _ := req["method"].(string)
		id := req["id"]

		switch method {
		case "SendMessage", "message/send":
			writeJSON(w, map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      id,
				"result": map[string]interface{}{
					"id":        taskID,
					"contextId": ctxID,
					"status":    "working",
				},
			})
		case "GetTask", "tasks/get":
			// Reject: task ownership enforced.
			writeJSON(w, map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      id,
				"error": map[string]interface{}{
					"code":    -32603,
					"message": "Task not found or access denied",
				},
			})
		default:
			writeJSON(w, map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      id,
				"error": map[string]interface{}{
					"code":    -32601,
					"message": "Method not found",
				},
			})
		}
	}))
	defer ts.Close()

	ex := a2a.NewTaskIDORExecutor(testRuleCtx())
	findings, err := ex.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings when GetTask is rejected, got %d: %+v", len(findings), findings)
	}
}
