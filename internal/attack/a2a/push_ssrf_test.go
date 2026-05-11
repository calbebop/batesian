package a2a_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/calbebop/batesian/internal/attack/a2a"
)

// TestPushSSRFExecutor_MethodNotFound verifies that a server rejecting all A2A
// methods with JSON-RPC -32601 produces zero findings.
func TestPushSSRFExecutor_MethodNotFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			writeJSON(w, jsonRPCError(-32601, "Method not found"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	ex := a2a.NewPushSSRFExecutor(testRuleCtx())
	findings, err := ex.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings, got %d: %+v", len(findings), findings)
	}
}

// TestPushSSRFExecutor_TaskAccepted verifies that when the server accepts both
// SendMessage and CreateTaskPushNotificationConfig but no OOB callback is
// configured (using an external OOB URL), no high-severity SSRF finding is
// produced. The executor reports an info-level finding at most.
func TestPushSSRFExecutor_TaskAccepted(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		var req map[string]interface{}
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		method, _ := req["method"].(string)
		id := req["id"]

		switch method {
		case "SendMessage":
			writeJSON(w, map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      id,
				"result": map[string]interface{}{
					"id":        "task-push-001",
					"contextId": "ctx-push-001",
				},
			})
		case "CreateTaskPushNotificationConfig":
			writeJSON(w, map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      id,
				"result":  map[string]interface{}{"ok": true},
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

	// Provide an external OOB URL so the executor doesn't spin up its own listener
	// and block for 10 seconds waiting for a callback.
	opts := testOpts()
	opts.OOBListenerURL = "http://oob.example.invalid/callback"

	ex := a2a.NewPushSSRFExecutor(testRuleCtx())
	findings, err := ex.Execute(context.Background(), ts.URL, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// No high-severity SSRF confirmed finding should be produced without a
	// confirmed OOB callback. At most an info-level "task accepted" indicator.
	for _, f := range findings {
		if f.Severity == "high" || f.Severity == "critical" {
			t.Errorf("expected no high/critical SSRF finding, got: %+v", f)
		}
	}
}
