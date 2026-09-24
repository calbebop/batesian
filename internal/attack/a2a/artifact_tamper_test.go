package a2a_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
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

func storedArtifact(text string) []interface{} {
	return []interface{}{map[string]interface{}{
		"artifactId": "stored-output",
		"parts":      []interface{}{map[string]interface{}{"text": text}},
	}}
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
					"artifacts": storedArtifact(text),
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
					"artifacts": storedArtifact(text),
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

// appendingA2AServer accepts re-submission but APPENDS the new text to the
// stored task rather than replacing it (both original and tampered survive).
func appendingA2AServer(t *testing.T) *httptest.Server {
	t.Helper()
	store := newTaskStore()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		method, _ := req["method"].(string)
		w.Header().Set("Content-Type", "application/json")
		params, _ := req["params"].(map[string]interface{})
		taskID, _ := params["id"].(string)
		switch method {
		case "tasks/send":
			msg, _ := params["message"].(map[string]interface{})
			parts, _ := msg["parts"].([]interface{})
			var text string
			if len(parts) > 0 {
				if p, ok := parts[0].(map[string]interface{}); ok {
					text, _ = p["text"].(string)
				}
			}
			if prev, ok := store.get(taskID); ok {
				text = prev + " | " + text // append, don't replace
			}
			store.set(taskID, text)
			json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]interface{}{"id": taskID, "state": "completed"}})
		case "tasks/get":
			text, ok := store.get(taskID)
			if !ok {
				json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": req["id"],
					"error": map[string]interface{}{"code": -32001, "message": "not found"}})
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]interface{}{"id": taskID, "state": "completed",
					"artifacts": storedArtifact(text),
					"message": map[string]interface{}{"role": "user",
						"parts": []interface{}{map[string]interface{}{"type": "text", "text": text}}}}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// idempotentPreserveServer accepts the re-submission at the transport layer
// (HTTP 200, no JSON-RPC error) but PRESERVES the original content - a benign
// idempotent/no-op server that must NOT be flagged as tampering.
func idempotentPreserveServer(t *testing.T) *httptest.Server {
	t.Helper()
	store := newTaskStore()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		method, _ := req["method"].(string)
		w.Header().Set("Content-Type", "application/json")
		params, _ := req["params"].(map[string]interface{})
		taskID, _ := params["id"].(string)
		switch method {
		case "tasks/send":
			msg, _ := params["message"].(map[string]interface{})
			parts, _ := msg["parts"].([]interface{})
			var text string
			if len(parts) > 0 {
				if p, ok := parts[0].(map[string]interface{}); ok {
					text, _ = p["text"].(string)
				}
			}
			if _, ok := store.get(taskID); !ok {
				store.set(taskID, text) // only the first write sticks
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]interface{}{"id": taskID, "state": "completed"}})
		case "tasks/get":
			text, ok := store.get(taskID)
			if !ok {
				json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": req["id"],
					"error": map[string]interface{}{"code": -32001, "message": "not found"}})
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]interface{}{"id": taskID, "state": "completed",
					"artifacts": storedArtifact(text),
					"message": map[string]interface{}{"role": "user",
						"parts": []interface{}{map[string]interface{}{"type": "text", "text": text}}}}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// An appended continuation preserves the artifact's original content.
func TestArtifactTamper_AppendIsNotAFinding(t *testing.T) {
	srv := appendingA2AServer(t)
	defer srv.Close()

	exec := a2aattack.NewArtifactTamperExecutor(attack.RuleContext{ID: "a2a-artifact-tamper-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("an append is a tested, clean result, not an error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("appending a continuation is conformant and must not be reported, got %d finding(s): %q",
			len(findings), findings[0].Title)
	}
}

// TestArtifactTamper_AcceptedButPreserved: server returns 200 to the
// re-submission but keeps the original content. Must NOT be flagged.
func TestArtifactTamper_AcceptedButPreserved(t *testing.T) {
	srv := idempotentPreserveServer(t)
	defer srv.Close()

	exec := a2aattack.NewArtifactTamperExecutor(attack.RuleContext{ID: "a2a-artifact-tamper-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings when original content is preserved, got %d: %v", len(findings), findings)
	}
}

func TestArtifactTamper_TruncatedHistoryDoesNotProveOverwrite(t *testing.T) {
	for _, tc := range []struct {
		name         string
		secondState  string
		inconclusive bool
	}{
		{"completed continuation", "completed", false},
		{"pending continuation", "working", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var original, latest string
			var sends int
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				req := readBody(r)
				method, _ := req["method"].(string)
				params, _ := req["params"].(map[string]interface{})
				id := req["id"]
				switch method {
				case "SendMessage":
					message, _ := params["message"].(map[string]interface{})
					parts, _ := message["parts"].([]interface{})
					part, _ := parts[0].(map[string]interface{})
					latest, _ = part["text"].(string)
					if original == "" {
						original = latest
					}
					sends++
					state := "completed"
					if sends == 2 {
						state = tc.secondState
					}
					writeJSON(w, map[string]interface{}{"jsonrpc": "2.0", "id": id,
						"result": map[string]interface{}{"task": map[string]interface{}{
							"id": "task-1", "status": map[string]string{"state": state},
						}}})
				case "GetTask":
					if original == "" {
						rpcErr(w, id, -32001, "Task not found")
						return
					}
					writeJSON(w, map[string]interface{}{"jsonrpc": "2.0", "id": id,
						"result": map[string]interface{}{
							"id": "task-1", "status": map[string]string{"state": "completed"},
							"artifacts": storedArtifact(original),
							"history": []interface{}{map[string]interface{}{
								"role": "user", "parts": []interface{}{map[string]string{"text": latest}},
							}},
						}})
				default:
					rpcErr(w, id, -32601, "Method not found")
				}
			}))
			defer srv.Close()

			exec := a2aattack.NewArtifactTamperExecutor(attack.RuleContext{ID: "a2a-artifact-tamper-001"})
			findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
			if len(findings) != 0 || (tc.inconclusive && !errors.Is(err, attack.ErrInconclusive)) || (!tc.inconclusive && err != nil) {
				t.Fatalf("unexpected verdict: findings=%+v err=%v", findings, err)
			}
			if sends != 2 {
				t.Fatalf("expected a create and continuation, got %d sends", sends)
			}
		})
	}
}

func TestArtifactTamper_HistoryWithoutStoredArtifactIsInconclusive(t *testing.T) {
	var latest string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := readBody(r)
		method, _ := req["method"].(string)
		id := req["id"]
		switch method {
		case "SendMessage":
			params, _ := req["params"].(map[string]interface{})
			message, _ := params["message"].(map[string]interface{})
			parts, _ := message["parts"].([]interface{})
			part, _ := parts[0].(map[string]interface{})
			latest, _ = part["text"].(string)
			writeJSON(w, map[string]interface{}{"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{"task": map[string]interface{}{"id": "task-1"}}})
		case "GetTask":
			if latest == "" {
				rpcErr(w, id, -32001, "Task not found")
				return
			}
			writeJSON(w, map[string]interface{}{"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{
					"id": "task-1", "status": map[string]string{"state": "completed"},
					"history": []interface{}{map[string]interface{}{
						"role": "user", "parts": []interface{}{map[string]string{"text": latest}},
					}},
				}})
		default:
			rpcErr(w, id, -32601, "Method not found")
		}
	}))
	defer srv.Close()

	exec := a2aattack.NewArtifactTamperExecutor(attack.RuleContext{ID: "a2a-artifact-tamper-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("history alone cannot prove stored replacement, got findings=%+v err=%v", findings, err)
	}
}

func TestArtifactTamper_UnjudgedContinuationIsInconclusive(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reply func(http.ResponseWriter, interface{})
	}{
		{"service unavailable", func(w http.ResponseWriter, _ interface{}) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}},
		{"invalid params", func(w http.ResponseWriter, id interface{}) {
			rpcErr(w, id, -32602, "Invalid params")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var original string
			var sends int
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				req := readBody(r)
				method, _ := req["method"].(string)
				id := req["id"]
				switch method {
				case "SendMessage":
					sends++
					if sends == 2 {
						tc.reply(w, id)
						return
					}
					params, _ := req["params"].(map[string]interface{})
					message, _ := params["message"].(map[string]interface{})
					parts, _ := message["parts"].([]interface{})
					part, _ := parts[0].(map[string]interface{})
					original, _ = part["text"].(string)
					writeJSON(w, map[string]interface{}{"jsonrpc": "2.0", "id": id,
						"result": map[string]interface{}{"task": map[string]interface{}{"id": "task-1"}}})
				case "GetTask":
					if original == "" {
						rpcErr(w, id, -32001, "Task not found")
						return
					}
					writeJSON(w, map[string]interface{}{"jsonrpc": "2.0", "id": id,
						"result": map[string]interface{}{
							"id": "task-1", "status": map[string]string{"state": "completed"},
							"artifacts": storedArtifact(original),
						}})
				default:
					rpcErr(w, id, -32601, "Method not found")
				}
			}))
			defer srv.Close()

			exec := a2aattack.NewArtifactTamperExecutor(attack.RuleContext{ID: "a2a-artifact-tamper-001"})
			findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
			if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
				t.Fatalf("unjudged continuation must be inconclusive, got findings=%+v err=%v", findings, err)
			}
		})
	}
}

func TestArtifactTamper_ChecksEveryOriginalArtifact(t *testing.T) {
	var original, latest string
	var sends int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := readBody(r)
		method, _ := req["method"].(string)
		id := req["id"]
		switch method {
		case "SendMessage":
			params, _ := req["params"].(map[string]interface{})
			message, _ := params["message"].(map[string]interface{})
			parts, _ := message["parts"].([]interface{})
			part, _ := parts[0].(map[string]interface{})
			latest, _ = part["text"].(string)
			if original == "" {
				original = latest
			}
			sends++
			writeJSON(w, map[string]interface{}{"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{"task": map[string]interface{}{"id": "task-1"}}})
		case "GetTask":
			if original == "" {
				rpcErr(w, id, -32001, "Task not found")
				return
			}
			secondText := original
			if sends > 1 {
				secondText = latest
			}
			writeJSON(w, map[string]interface{}{"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{
					"id": "task-1", "status": map[string]string{"state": "completed"},
					"artifacts": []interface{}{
						map[string]interface{}{"artifactId": "preserved", "parts": []interface{}{map[string]string{"text": original}}},
						map[string]interface{}{"artifactId": "replaced", "parts": []interface{}{map[string]string{"text": secondText}}},
					},
				}})
		default:
			rpcErr(w, id, -32601, "Method not found")
		}
	}))
	defer srv.Close()

	exec := a2aattack.NewArtifactTamperExecutor(attack.RuleContext{ID: "a2a-artifact-tamper-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil || len(findings) != 1 {
		t.Fatalf("expected one finding for the replaced artifact, got findings=%+v err=%v", findings, err)
	}
	if !strings.Contains(findings[0].Evidence, "artifact:replaced") {
		t.Fatalf("finding must identify the changed artifact: %s", findings[0].Evidence)
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
		case "tasks/get":
			params, _ := req["params"].(map[string]interface{})
			taskID, _ := params["id"].(string)
			text, ok := store.get(taskID)
			if !ok {
				rpcErr(w, req["id"], -32001, "Task not found")
				return
			}
			writeJSON(w, map[string]interface{}{"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]interface{}{"id": taskID, "state": "completed", "artifacts": storedArtifact(text)}})
		default:
			// Realistic JSON-RPC: unknown methods return -32601, not HTTP 404.
			json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": req["id"],
				"error": map[string]interface{}{"code": -32601, "message": "method not found"}})
		}
	}))
	defer srv.Close()

	exec := a2aattack.NewArtifactTamperExecutor(attack.RuleContext{ID: "a2a-artifact-tamper-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The old assertion checked strings.Contains(f.Title, "TAMPERED"), but the
	// rule's confirmed title spells "tampered" in lowercase, so the guard could
	// never fire and the test passed with any confirmed finding. An immutable
	// server must not produce one at all, which is the claim worth pinning.
	for _, f := range findings {
		if f.Confidence == attack.ConfirmedExploit {
			t.Errorf("an immutable server must not produce a confirmed finding: %s", f.Title)
		}
	}
}

// modernOnlyOverwritingServer replaces an identified artifact on the v1 wire.
func modernOnlyOverwritingServer(t *testing.T) *httptest.Server {
	t.Helper()
	stored := map[string]string{}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/agent-card.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"name":"Modern Agent","description":"d","version":"1.0.0",`+
				`"protocolVersion":"1.0","capabilities":{},"skills":[],`+
				`"supportedInterfaces":[{"url":"`+"http://"+r.Host+`/","protocolBinding":"JSONRPC","protocolVersion":"1.0"}]}`)
			return
		}
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		method, _ := req["method"].(string)
		params, _ := req["params"].(map[string]interface{})
		w.Header().Set("Content-Type", "application/json")

		notFound := func() {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": req["id"],
				"error": map[string]interface{}{"code": -32601, "message": "method not found"}})
		}

		switch method {
		case "SendMessage":
			msg, _ := params["message"].(map[string]interface{})
			parts, _ := msg["parts"].([]interface{})
			text := ""
			if len(parts) > 0 {
				if pm, ok := parts[0].(map[string]interface{}); ok {
					text, _ = pm["text"].(string)
				}
			}
			id, _ := msg["taskId"].(string)
			if id == "" {
				id = "task-modern-1"
			}
			// VULNERABLE: the stored content is replaced, not appended.
			stored[id] = text
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]interface{}{"task": map[string]interface{}{"id": id, "contextId": "ctx-1"}}})
		case "GetTask":
			id, _ := params["id"].(string)
			text, ok := stored[id]
			if !ok {
				notFound()
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]interface{}{"id": id, "status": map[string]string{"state": "completed"},
					"artifacts": storedArtifact(text), "history": []interface{}{
						map[string]interface{}{"role": "user",
							"parts": []interface{}{map[string]interface{}{"text": text}}}}}})
		default:
			// Every other name, including the v0.2 tasks/send the rule used to send.
			notFound()
		}
	}))
}

// A v1.0-only agent that overwrites task content must be caught. Before the method
// names were corrected this reported clean.
func TestArtifactTamper_V1OnlyAgentOverwriteIsCaught(t *testing.T) {
	srv := modernOnlyOverwritingServer(t)
	defer srv.Close()

	exec := a2aattack.NewArtifactTamperExecutor(attack.RuleContext{ID: "a2a-artifact-tamper-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected the overwrite to be caught on the v1.0 wire, got %d finding(s)", len(findings))
	}
	if findings[0].Confidence != attack.ConfirmedExploit || findings[0].Severity != "critical" {
		t.Errorf("expected critical/ConfirmedExploit, got %q/%q", findings[0].Severity, findings[0].Confidence)
	}
	if !strings.Contains(findings[0].Evidence, "v1.0 SendMessage") {
		t.Errorf("evidence should name the wire that worked, got: %s", findings[0].Evidence)
	}
}

// An agent that serves a card but implements no task-creation method the rule
// knows has not exercised immutability, so the result must be not-tested rather
// than a clean pass.
func TestArtifactTamper_NoTaskCreatedIsNotTested(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/agent-card.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"name":"Card Only","description":"d","version":"1.0.0",`+
				`"capabilities":{},"skills":[],`+
				`"supportedInterfaces":[{"url":"`+"http://"+r.Host+`/","protocolBinding":"JSONRPC","protocolVersion":"1.0"}]}`)
			return
		}
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		// Answers MCP-shaped JSON-RPC but implements no send method.
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": req["id"],
			"error": map[string]interface{}{"code": -32601, "message": "method not found"}})
	}))
	defer srv.Close()

	exec := a2aattack.NewArtifactTamperExecutor(attack.RuleContext{ID: "a2a-artifact-tamper-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Errorf("no task could be created, so immutability was never tested; want ErrInconclusive, got %v", err)
	}
}

// legacyOnlyOverwritingServer implements ONLY the v0.2 tasks/send name and answers
// every other method with -32601 at HTTP 200, which is how both official SDKs
// answer a name their revision does not define.
//
// This is what makes the fallback gate matter. The first attempt is v1.0
// SendMessage; a gate keyed on !IsSuccess() sees HTTP 200 and stops, so the walk
// never reaches the wire this server actually speaks. Gating on !IsAccepted()
// treats the error envelope as a non-answer and advances.
func legacyOnlyOverwritingServer(t *testing.T) *httptest.Server {
	t.Helper()
	stored := map[string]string{}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/agent-card.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"name":"Legacy Agent","description":"d","version":"0.2.0",`+
				`"capabilities":{},"skills":[],"url":"`+"http://"+r.Host+`/"}`)
			return
		}
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		method, _ := req["method"].(string)
		params, _ := req["params"].(map[string]interface{})
		w.Header().Set("Content-Type", "application/json")

		switch method {
		case "tasks/send":
			id, _ := params["id"].(string)
			msg, _ := params["message"].(map[string]interface{})
			parts, _ := msg["parts"].([]interface{})
			text := ""
			if len(parts) > 0 {
				if pm, ok := parts[0].(map[string]interface{}); ok {
					text, _ = pm["text"].(string)
				}
			}
			// VULNERABLE: overwrite with no immutability check.
			stored[id] = text
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]interface{}{"id": id, "state": "completed"}})
		case "tasks/get":
			id, _ := params["id"].(string)
			text, ok := stored[id]
			if !ok {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": req["id"],
					"error": map[string]interface{}{"code": -32001, "message": "not found"}})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]interface{}{"id": id, "state": "completed", "artifacts": storedArtifact(text), "message": map[string]interface{}{
					"role": "user", "parts": []interface{}{map[string]interface{}{"type": "text", "text": text}}}}})
		default:
			// HTTP 200 with a JSON-RPC error, exactly as the real SDKs answer a name
			// their revision does not define.
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": req["id"],
				"error": map[string]interface{}{"code": -32601, "message": "method not found"}})
		}
	}))
}

// A -32601 at HTTP 200 on an earlier wire must not end the walk. This is the exact
// shape that made the rule silent: gating the fallback on HTTP status meant the
// first attempt "succeeded" and the wire the server actually speaks was never tried.
func TestArtifactTamper_JSONRPCErrorAdvancesToTheNextWire(t *testing.T) {
	srv := legacyOnlyOverwritingServer(t)
	defer srv.Close()

	exec := a2aattack.NewArtifactTamperExecutor(attack.RuleContext{ID: "a2a-artifact-tamper-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("the walk must advance past a 200-carried -32601 to the wire the server speaks, got %d finding(s)", len(findings))
	}
	if !strings.Contains(findings[0].Evidence, "v0.2 tasks/send") {
		t.Errorf("evidence should name the wire that worked, got: %s", findings[0].Evidence)
	}
}
