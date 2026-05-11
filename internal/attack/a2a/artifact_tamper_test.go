package a2a_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	a2aattack "github.com/calbebop/batesian/internal/attack/a2a"
)

type taskStore struct {
	mu    sync.Mutex
	tasks map[string]string
}

func newTaskStore() *taskStore {
	return &taskStore{tasks: make(map[string]string)}
}
func (ts *taskStore) set(id, text string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.tasks[id] = text
}
func (ts *taskStore) get(id string) (string, bool) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	v, ok := ts.tasks[id]
	return v, ok
}

func vulnerableA2AServer(t *testing.T) *httptest.Server {
	t.Helper()
	store := newTaskStore()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		method, _ := req["method"].(string)
		w.Header().Set("Content-Type", "application/json")
		switch method {
		case "tasks/send":
			params, _ := req["params"].(map[string]interface{})
			taskID, _ := params["id"].(string)
			msg, _ := params["message"].(map[string]interface{})
			parts, _ := msg["parts"].([]interface{})
			var text string
			if len(parts) > 0 {
				if p, ok := parts[0].(map[string]interface{}); ok {
					text, _ = p["text"].(string)
				}
			}
			store.set(taskID, text) // vulnerable: always overwrite
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]interface{}{
					"id": taskID, "state": "completed",
					"message": map[string]interface{}{
						"role":  "agent",
						"parts": []interface{}{map[string]interface{}{"type": "text", "text": text}},
					},
				},
			})
		case "tasks/get":
			params, _ := req["params"].(map[string]interface{})
			taskID, _ := params["id"].(string)
			text, ok := store.get(taskID)
			if !ok {
				json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": req["id"],
					"error": map[string]interface{}{"code": -32001, "message": "not found"}})
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]interface{}{
					"id": taskID, "state": "completed",
					"message": map[string]interface{}{
						"role":  "user",
						"parts": []interface{}{map[string]interface{}{"type": "text", "text": text}},
					},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestArtifactTamper_OverwriteAllowed(t *testing.T) {
	srv := vulnerableA2AServer(t)
	defer srv.Close()

	exec := a2aattack.NewArtifactTamperExecutor(attack.RuleContext{ID: "a2a-artifact-tamper-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings for server that allows task overwrite")
	}
	hasConfirmed := false
	for _, f := range findings {
		if f.Confidence == attack.ConfirmedExploit {
			hasConfirmed = true
		}
	}
	if !hasConfirmed {
		t.Error("expected at least one ConfirmedExploit finding")
	}
}

func TestArtifactTamper_ImmutableTasks(t *testing.T) {
	store := newTaskStore()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		method, _ := req["method"].(string)
		w.Header().Set("Content-Type", "application/json")
		switch method {
		case "tasks/send":
			params, _ := req["params"].(map[string]interface{})
			taskID, _ := params["id"].(string)
			msg, _ := params["message"].(map[string]interface{})
			parts, _ := msg["parts"].([]interface{})
			var text string
			if len(parts) > 0 {
				if p, ok := parts[0].(map[string]interface{}); ok {
					text, _ = p["text"].(string)
				}
			}
			if _, exists := store.get(taskID); exists {
				json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": req["id"],
					"error": map[string]interface{}{"code": -32600, "message": "task ID already exists"}})
				return
			}
			store.set(taskID, text)
			json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]interface{}{"id": taskID, "state": "completed"}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	exec := a2aattack.NewArtifactTamperExecutor(attack.RuleContext{ID: "a2a-artifact-tamper-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Confidence == attack.ConfirmedExploit && strings.Contains(f.Title, "TAMPERED") {
			t.Errorf("tampered content should not appear for immutable server: %s", f.Title)
		}
	}
}
