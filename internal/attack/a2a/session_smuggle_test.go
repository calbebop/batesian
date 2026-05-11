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

// TestSessionSmuggleExecutor_RoleInjectionAccepted verifies that when the
// server accepts a SendMessage with role=2 (AGENT) and returns a valid task
// result, at least one finding is produced.
func TestSessionSmuggleExecutor_RoleInjectionAccepted(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req map[string]interface{}
		_ = json.Unmarshal(body, &req)
		id := req["id"]

		// Accept all requests: return a task-like result so looksLikeTask passes.
		writeJSON(w, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      id,
			"result": map[string]interface{}{
				"id":        "task-smuggle-001",
				"contextId": "ctx-smuggle-001",
				"status":    "working",
			},
		})
	}))
	defer ts.Close()

	ex := a2a.NewSessionSmuggleExecutor(testRuleCtx())
	findings, err := ex.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for role injection acceptance, got zero")
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
			t.Errorf("finding %q: want ConfirmedExploit confidence, got %q", f.Title, f.Confidence)
		}
	}
}

// TestSessionSmuggleExecutor_RoleInjectionRejected verifies that when the
// server rejects agent-role messages with a JSON-RPC -32602 error, zero
// findings are produced.
func TestSessionSmuggleExecutor_RoleInjectionRejected(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req map[string]interface{}
		_ = json.Unmarshal(body, &req)
		id := req["id"]

		// Reject all messages — return a JSON-RPC error.
		writeJSON(w, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      id,
			"error": map[string]interface{}{
				"code":    -32602,
				"message": "Invalid params: role must be USER",
			},
		})
	}))
	defer ts.Close()

	ex := a2a.NewSessionSmuggleExecutor(testRuleCtx())
	findings, err := ex.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings for rejected role injection, got %d: %+v", len(findings), findings)
	}
}
