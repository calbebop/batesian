package a2a_test

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
	a2aattack "github.com/calbebop/batesian/internal/attack/a2a"
)

// contextOrphanRC returns a minimal RuleContext for context orphan tests.
func contextOrphanRC() attack.RuleContext {
	return attack.RuleContext{
		ID:          "a2a-context-orphan-001",
		Name:        "A2A Context Orphan",
		Severity:    "high",
		Remediation: "Bind contextId to the creating session.",
	}
}

// vulnerableContextServer simulates an A2A server that:
// - Creates a task with contextId when SendMessage is called
// - Accepts any contextId supplied by the client in configuration.contextId
// - Returns the supplied contextId back in the result
func vulnerableContextServer(t *testing.T) *httptest.Server {
	t.Helper()

	var mu sync.Mutex
	taskStore := map[string]string{} // taskId -> contextId
	msgStore := map[string]string{}  // contextId -> first message text

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}

		var req map[string]interface{}
		json.NewDecoder(r.Body).Decode(&req)
		method, _ := req["method"].(string)
		id := req["id"]
		w.Header().Set("Content-Type", "application/json")

		switch method {
		case "SendMessage":
			params, _ := req["params"].(map[string]interface{})
			msg, _ := params["message"].(map[string]interface{})

			// Extract contextId from configuration (v1.0) or top-level (v0.3)
			var contextID string
			if cfg, ok := params["configuration"].(map[string]interface{}); ok {
				contextID, _ = cfg["contextId"].(string)
			}
			if contextID == "" {
				contextID, _ = params["contextId"].(string)
			}

			// Assign new contextId if none provided
			parts, _ := msg["parts"].([]interface{})
			var msgText string
			if len(parts) > 0 {
				if part, ok := parts[0].(map[string]interface{}); ok {
					msgText, _ = part["text"].(string)
				}
			}

			mu.Lock()
			if contextID == "" {
				contextID = "ctx-" + msgText[:min(len(msgText), 16)]
				contextID = strings.ReplaceAll(contextID, " ", "-")
			}
			taskID := fmt.Sprintf("task-%x", len(taskStore))
			taskStore[taskID] = contextID
			if _, exists := msgStore[contextID]; !exists {
				msgStore[contextID] = msgText
			}
			mu.Unlock()

			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      id,
				"result": map[string]interface{}{
					"id":        taskID,
					"contextId": contextID,
					"status":    map[string]interface{}{"state": "completed"},
				},
			})

		case "GetTask":
			params, _ := req["params"].(map[string]interface{})
			taskID, _ := params["id"].(string)

			mu.Lock()
			cid, ok := taskStore[taskID]
			firstMsg := msgStore[cid]
			mu.Unlock()

			if !ok {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      id,
					"error":   map[string]interface{}{"code": -32001, "message": "Task not found"},
				})
				return
			}

			// Return the history for this context (including first message from ANY task in this context)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      id,
				"result": map[string]interface{}{
					"id":        taskID,
					"contextId": cid,
					"history": []interface{}{
						map[string]interface{}{
							"role":  "user",
							"parts": []interface{}{map[string]string{"text": firstMsg}},
						},
					},
				},
			})

		default:
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      id,
				"error":   map[string]interface{}{"code": -32601, "message": "Method not found"},
			})
		}
	}))
	return ts
}

// secureContextServer rejects SendMessage requests that supply an existing contextId
// from a different session (simulates proper context ownership validation).
func secureContextServer(t *testing.T) *httptest.Server {
	t.Helper()

	var mu sync.Mutex
	createdContexts := map[string]string{} // contextId -> creator session marker

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		json.NewDecoder(r.Body).Decode(&req)
		method, _ := req["method"].(string)
		id := req["id"]
		w.Header().Set("Content-Type", "application/json")

		switch method {
		case "SendMessage":
			params, _ := req["params"].(map[string]interface{})
			var contextID string
			if cfg, ok := params["configuration"].(map[string]interface{}); ok {
				contextID, _ = cfg["contextId"].(string)
			}

			mu.Lock()
			if contextID != "" {
				if _, exists := createdContexts[contextID]; exists {
					// Context exists but this is a different session — reject
					mu.Unlock()
					json.NewEncoder(w).Encode(map[string]interface{}{
						"jsonrpc": "2.0",
						"id":      id,
						"error":   map[string]interface{}{"code": -32001, "message": "Context not found"},
					})
					return
				}
			}

			newCID := "ctx-new"
			if contextID == "" {
				contextID = newCID
			}
			createdContexts[contextID] = "session-1"
			taskID := fmt.Sprintf("task-%x", len(createdContexts))
			mu.Unlock()

			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      id,
				"result": map[string]interface{}{
					"id":        taskID,
					"contextId": contextID,
					"status":    map[string]interface{}{"state": "completed"},
				},
			})

		default:
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      id,
				"error":   map[string]interface{}{"code": -32601, "message": "Method not found"},
			})
		}
	}))
	return ts
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestContextOrphan_VulnerableServer(t *testing.T) {
	ts := vulnerableContextServer(t)
	defer ts.Close()

	exec := a2aattack.NewContextOrphanExecutor(contextOrphanRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings on vulnerable context server, got none")
	}
	// Should have high or critical findings
	hasHighOrCritical := false
	for _, f := range findings {
		if f.Severity == "high" || f.Severity == "critical" {
			hasHighOrCritical = true
		}
	}
	if !hasHighOrCritical {
		t.Errorf("expected high/critical finding for context injection, got: %v", findings)
	}
	for _, f := range findings {
		if f.Confidence != attack.ConfirmedExploit {
			t.Errorf("finding %q: want ConfirmedExploit, got %q", f.Title, f.Confidence)
		}
	}
}

func TestContextOrphan_SecureServer(t *testing.T) {
	ts := secureContextServer(t)
	defer ts.Close()

	exec := a2aattack.NewContextOrphanExecutor(contextOrphanRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings on secure server, got %d: %v", len(findings), findings)
	}
}

func TestContextOrphan_NotA2AServer(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	defer ts.Close()

	exec := a2aattack.NewContextOrphanExecutor(contextOrphanRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings on non-A2A server, got %d", len(findings))
	}
}
