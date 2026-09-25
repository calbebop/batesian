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
	"github.com/calbebop/batesian/internal/attack/a2a"
)

const idorOwnerToken = "owner-secret-token"

// idorOpts returns scan options carrying an owner credential. The IDOR rule can
// only establish an "owner" when a token is supplied, so the validation servers
// distinguish the authenticated creator from an unauthenticated reader by the
// presence of this bearer token.
func idorOpts() attack.Options {
	return attack.Options{TimeoutSeconds: 5, Token: idorOwnerToken}
}

func decodeRPC(r *http.Request) (method string, id interface{}) {
	req := readBody(r)
	method, _ = req["method"].(string)
	return method, req["id"]
}

func rpcMessageText(req map[string]interface{}) string {
	params, _ := req["params"].(map[string]interface{})
	message, _ := params["message"].(map[string]interface{})
	parts, _ := message["parts"].([]interface{})
	if len(parts) == 0 {
		return ""
	}
	part, _ := parts[0].(map[string]interface{})
	text, _ := part["text"].(string)
	return text
}

// readBody decodes a JSON-RPC request body into a map. Shared across a2a tests.
func readBody(r *http.Request) map[string]interface{} {
	body, _ := io.ReadAll(r.Body)
	var req map[string]interface{}
	_ = json.Unmarshal(body, &req)
	return req
}

func hasOwnerAuth(r *http.Request) bool {
	return r.Header.Get("Authorization") == "Bearer "+idorOwnerToken
}

// taskResult writes a SendMessage success envelope carrying a task id/contextId.
func taskResult(w http.ResponseWriter, id interface{}, taskID, ctxID string) {
	writeJSON(w, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"result":  map[string]interface{}{"id": taskID, "contextId": ctxID, "status": "working"},
	})
}

// taskWithHistory writes a GetTask success envelope including conversation history.
func taskWithHistory(w http.ResponseWriter, id interface{}, taskID, ctxID string, text ...string) {
	messageText := "probe"
	if len(text) > 0 {
		messageText = text[0]
	}
	writeJSON(w, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"result": map[string]interface{}{
			"id":        taskID,
			"contextId": ctxID,
			"history": []interface{}{
				map[string]interface{}{"role": "user", "parts": []interface{}{map[string]string{"text": messageText}}},
			},
		},
	})
}

func rpcErr(w http.ResponseWriter, id interface{}, code int, msg string) {
	writeJSON(w, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   map[string]interface{}{"code": code, "message": msg},
	})
}

// TestTaskIDOR_Vulnerable: the server authenticates task creation but returns
// task history to an unauthenticated tasks/get. The rule MUST fire (confirmed).
func TestTaskIDOR_Vulnerable(t *testing.T) {
	const taskID, ctxID = "task-vuln-abc", "ctx-vuln-xyz"
	var mu sync.Mutex
	ownerText := ""
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" { // no tasks/list endpoint
			http.NotFound(w, r)
			return
		}
		req := readBody(r)
		method, _ := req["method"].(string)
		id := req["id"]
		switch method {
		case "SendMessage", "message/send":
			if !hasOwnerAuth(r) {
				rpcErr(w, id, -32600, "authentication required") // creation is auth-gated
				return
			}
			mu.Lock()
			ownerText = rpcMessageText(req)
			mu.Unlock()
			taskResult(w, id, taskID, ctxID)
		case "GetTask", "tasks/get":
			mu.Lock()
			text := ownerText
			mu.Unlock()
			taskWithHistory(w, id, taskID, ctxID, text)
		default:
			rpcErr(w, id, -32601, "Method not found")
		}
	}))
	defer ts.Close()

	findings, err := a2a.NewTaskIDORExecutor(testRuleCtx()).Execute(context.Background(), ts.URL, idorOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly one IDOR finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Confidence != attack.ConfirmedExploit {
		t.Errorf("want ConfirmedExploit, got %q", f.Confidence)
	}
	if f.Severity != "high" {
		t.Errorf("want high severity, got %q", f.Severity)
	}
}

// TestTaskIDOR_Vulnerable_V03Only verifies the rule still fires against a server
// that speaks only the v0.3 slash-method binding: it rejects the v1.0 PascalCase
// methods (SendMessage, GetTask) with a JSON-RPC error over HTTP 200 and accepts
// only message/send and tasks/get. This exercises the v1.0->v0.3 fallback on both
// the create and the read path. Without the fallback the create guard short-
// circuits on the 200+error and the rule never fires (false negative).
func TestTaskIDOR_Vulnerable_V03Only(t *testing.T) {
	const taskID, ctxID = "task-v03-abc", "ctx-v03-xyz"
	var mu sync.Mutex
	ownerText := ""
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		req := readBody(r)
		method, _ := req["method"].(string)
		id := req["id"]
		switch method {
		case "message/send":
			if !hasOwnerAuth(r) {
				rpcErr(w, id, -32600, "authentication required") // creation is auth-gated
				return
			}
			mu.Lock()
			ownerText = rpcMessageText(req)
			mu.Unlock()
			taskResult(w, id, taskID, ctxID)
		case "tasks/get":
			mu.Lock()
			text := ownerText
			mu.Unlock()
			taskWithHistory(w, id, taskID, ctxID, text)
		default:
			// v1.0 PascalCase methods are unknown to this v0.3-only server:
			// HTTP 200 carrying a JSON-RPC method-not-found error.
			rpcErr(w, id, -32601, "Method not found")
		}
	}))
	defer ts.Close()

	findings, err := a2a.NewTaskIDORExecutor(testRuleCtx()).Execute(context.Background(), ts.URL, idorOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly one IDOR finding against v0.3-only server, got %d: %+v", len(findings), findings)
	}
	if findings[0].Confidence != attack.ConfirmedExploit {
		t.Errorf("want ConfirmedExploit, got %q", findings[0].Confidence)
	}
	if findings[0].Severity != "high" {
		t.Errorf("want high severity, got %q", findings[0].Severity)
	}
}

func TestTaskIDOR_HybridReadChecksLegacyAfterStub(t *testing.T) {
	var mu sync.Mutex
	ownerText := ""
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		req := readBody(r)
		method, _ := req["method"].(string)
		id := req["id"]
		switch method {
		case "SendMessage", "message/send":
			if !hasOwnerAuth(r) {
				rpcErr(w, id, -32600, "authentication required")
				return
			}
			mu.Lock()
			ownerText = rpcMessageText(req)
			mu.Unlock()
			taskResult(w, id, "task-hybrid", "ctx-hybrid")
		case "GetTask":
			writeJSON(w, map[string]interface{}{"jsonrpc": "2.0", "id": id,
				"result": map[string]string{"id": "task-hybrid"}})
		case "tasks/get":
			mu.Lock()
			text := ownerText
			mu.Unlock()
			taskWithHistory(w, id, "task-hybrid", "ctx-hybrid", text)
		default:
			rpcErr(w, id, -32601, "Method not found")
		}
	}))
	defer ts.Close()

	findings, err := a2a.NewTaskIDORExecutor(testRuleCtx()).Execute(context.Background(), ts.URL, idorOpts())
	if err != nil || len(findings) != 1 {
		t.Fatalf("legacy read must expose the owner marker after a v1 stub; findings=%+v err=%v", findings, err)
	}
	if !strings.Contains(findings[0].Evidence, "anonymous tasks/get") {
		t.Fatalf("finding must identify the leaking method: %s", findings[0].Evidence)
	}
}

// TestTaskIDOR_Patched: creation is auth-gated AND tasks/get enforces ownership
// (rejects unauthenticated reads). The rule MUST stay silent.
func TestTaskIDOR_Patched(t *testing.T) {
	const taskID, ctxID = "task-ok-abc", "ctx-ok-xyz"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		method, id := decodeRPC(r)
		if !hasOwnerAuth(r) {
			rpcErr(w, id, -32600, "authentication required") // every method is auth-gated
			return
		}
		switch method {
		case "SendMessage", "message/send":
			taskResult(w, id, taskID, ctxID)
		case "GetTask", "tasks/get":
			taskWithHistory(w, id, taskID, ctxID)
		default:
			rpcErr(w, id, -32601, "Method not found")
		}
	}))
	defer ts.Close()

	findings, err := a2a.NewTaskIDORExecutor(testRuleCtx()).Execute(context.Background(), ts.URL, idorOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings against patched server, got %d: %+v", len(findings), findings)
	}
}

// TestTaskIDOR_OpenServerIsNotIDOR: the server enforces NO authentication at all
// (anonymous creation succeeds). Reading a task back without credentials is then
// expected behaviour, not broken object-level authorization. The rule MUST stay
// silent - this is the false-positive class the auth-enforcement discriminator
// exists to suppress.
func TestTaskIDOR_OpenServerIsNotIDOR(t *testing.T) {
	const taskID, ctxID = "task-open-abc", "ctx-open-xyz"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		method, id := decodeRPC(r)
		switch method {
		case "SendMessage", "message/send":
			taskResult(w, id, taskID, ctxID) // no auth check - anyone can create
		case "GetTask", "tasks/get":
			taskWithHistory(w, id, taskID, ctxID)
		default:
			rpcErr(w, id, -32601, "Method not found")
		}
	}))
	defer ts.Close()

	findings, err := a2a.NewTaskIDORExecutor(testRuleCtx()).Execute(context.Background(), ts.URL, idorOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings against a fully-open server (not IDOR), got %d: %+v", len(findings), findings)
	}
}

// TestTaskIDOR_NoContextIdNullRead_NoFalsePositive guards the empty-substring
// false positive. The server auth-gates creation but returns a task WITHOUT a
// contextId (so the executor's contextID is ""), and answers the unauthenticated
// read with a null result (HTTP 200, no JSON-RPC error) rather than denying it.
// The unauth read returned none of the owner's data, so the rule MUST stay
// silent. Before the ContainsAny empty-needle fix, the "" contextID matched any
// body and this fired a false IDOR finding.
func TestTaskIDOR_NoContextIdNullRead_NoFalsePositive(t *testing.T) {
	const taskID = "task-nocontext-1"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		method, id := decodeRPC(r)
		switch method {
		case "SendMessage", "message/send":
			if !hasOwnerAuth(r) {
				rpcErr(w, id, -32600, "authentication required") // creation is auth-gated
				return
			}
			// Created task carries an id but no contextId.
			writeJSON(w, map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{"id": taskID, "status": "working"},
			})
		case "GetTask", "tasks/get":
			// Secure: a task the caller cannot see comes back as a null result,
			// not an error, and discloses none of the owner's data.
			writeJSON(w, map[string]interface{}{"jsonrpc": "2.0", "id": id, "result": nil})
		default:
			rpcErr(w, id, -32601, "Method not found")
		}
	}))
	defer ts.Close()

	findings, err := a2a.NewTaskIDORExecutor(testRuleCtx()).Execute(context.Background(), ts.URL, idorOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings (null read discloses nothing), got %d: %+v", len(findings), findings)
	}
}

// A populated list alone does not establish who owns its tasks.
func TestTaskIDOR_ListWithoutOwnerTaskIsInconclusive(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/tasks" {
			writeJSON(w, map[string]interface{}{
				"tasks": []interface{}{
					map[string]interface{}{"id": "t1", "contextId": "c1"},
					map[string]interface{}{"id": "t2", "contextId": "c2"},
				},
			})
			return
		}
		// Not a JSON-RPC task endpoint: the create step finds no owner task and
		// falls through to the list probe.
		http.NotFound(w, r)
	}))
	defer ts.Close()

	findings, err := a2a.NewTaskIDORExecutor(testRuleCtx()).Execute(context.Background(), ts.URL, idorOpts())
	if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("unattributed list cannot prove disclosure; got findings=%+v err=%v", findings, err)
	}
}

func TestTaskIDOR_TaskListRequiresOwnerEvidence(t *testing.T) {
	tests := []struct {
		name         string
		anonCreate   bool
		anonV1Error  bool
		listedIDs    []string
		wantFinding  bool
		inconclusive bool
	}{
		{name: "anonymous task only", anonCreate: true, listedIDs: []string{"task-anon"}},
		{name: "authenticated owner exposed", listedIDs: []string{"task-owner", "task-other"}, wantFinding: true},
		{name: "empty list", listedIDs: nil},
		{name: "other task has unknown owner", listedIDs: []string{"task-other"}, inconclusive: true},
		{name: "anonymous task plus unknown task", anonCreate: true, listedIDs: []string{"task-anon", "task-other"}, inconclusive: true},
		{name: "open creation cannot prove ownership", anonCreate: true, listedIDs: []string{"task-owner"}, inconclusive: true},
		{name: "other wire rejection cannot prove ownership", anonV1Error: true, listedIDs: []string{"task-owner"}, inconclusive: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					if r.URL.Path != "/v1/tasks" {
						http.NotFound(w, r)
						return
					}
					tasks := make([]map[string]string, 0, len(tc.listedIDs))
					for _, id := range tc.listedIDs {
						tasks = append(tasks, map[string]string{"id": id})
					}
					writeJSON(w, map[string]interface{}{"tasks": tasks})
					return
				}
				method, id := decodeRPC(r)
				switch method {
				case "SendMessage", "message/send":
					if hasOwnerAuth(r) {
						taskResult(w, id, "task-owner", "ctx-owner")
					} else if tc.anonV1Error && method == "SendMessage" {
						w.WriteHeader(http.StatusServiceUnavailable)
					} else if tc.anonCreate {
						taskResult(w, id, "task-anon", "ctx-anon")
					} else {
						rpcErr(w, id, -32600, "authentication required")
					}
				case "GetTask", "tasks/get":
					rpcErr(w, id, -32001, "Task not found")
				default:
					rpcErr(w, id, -32601, "Method not found")
				}
			}))
			defer ts.Close()

			findings, err := a2a.NewTaskIDORExecutor(testRuleCtx()).Execute(context.Background(), ts.URL, idorOpts())
			wantCount := 0
			if tc.wantFinding {
				wantCount = 1
			}
			if len(findings) != wantCount {
				t.Fatalf("findings=%+v err=%v; want finding=%t", findings, err, tc.wantFinding)
			}
			if errors.Is(err, attack.ErrInconclusive) != tc.inconclusive {
				t.Fatalf("err=%v; want inconclusive=%t", err, tc.inconclusive)
			}
			if !tc.inconclusive && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantFinding {
				if findings[0].Severity != "high" || findings[0].Confidence != attack.ConfirmedExploit {
					t.Fatalf("want high/confirmed, got %s/%s", findings[0].Severity, findings[0].Confidence)
				}
				if !strings.Contains(findings[0].Evidence, "task-owner") {
					t.Fatalf("finding must identify the disclosed owner task: %s", findings[0].Evidence)
				}
			}
		})
	}
}

func TestTaskIDOR_CreateProbesUseDistinctMessageIDs(t *testing.T) {
	var mu sync.Mutex
	ownerMessageID := ""
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			if r.URL.Path == "/v1/tasks" {
				writeJSON(w, map[string]interface{}{"tasks": []interface{}{map[string]string{"id": "task-owner"}}})
			} else {
				http.NotFound(w, r)
			}
			return
		}
		req := readBody(r)
		method, _ := req["method"].(string)
		id := req["id"]
		switch method {
		case "SendMessage", "message/send":
			params, _ := req["params"].(map[string]interface{})
			message, _ := params["message"].(map[string]interface{})
			messageID, _ := message["messageId"].(string)
			mu.Lock()
			if hasOwnerAuth(r) {
				ownerMessageID = messageID
			}
			duplicate := !hasOwnerAuth(r) && messageID == ownerMessageID
			mu.Unlock()
			if hasOwnerAuth(r) || duplicate {
				taskResult(w, id, "task-owner", "ctx-owner")
			} else {
				rpcErr(w, id, -32600, "authentication required")
			}
		case "GetTask", "tasks/get":
			rpcErr(w, id, -32001, "Task not found")
		default:
			rpcErr(w, id, -32601, "Method not found")
		}
	}))
	defer ts.Close()

	findings, err := a2a.NewTaskIDORExecutor(testRuleCtx()).Execute(context.Background(), ts.URL, idorOpts())
	if err != nil || len(findings) != 1 || !strings.Contains(findings[0].Evidence, "task-owner") {
		t.Fatalf("distinct create probes should reveal the owner task in the list; findings=%+v err=%v", findings, err)
	}
}

// taskListServer serves an A2A card and answers the REST task-list paths with body.
// Everything else is a JSON-RPC method-not-found, so the rule reaches the list probe.
func taskListServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/.well-known/") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"name":"List Agent","description":"d","version":"1.0.0",`+
				`"protocolVersion":"1.0","capabilities":{},"skills":[],`+
				`"supportedInterfaces":[{"url":"http://`+r.Host+`/","protocolBinding":"JSONRPC","protocolVersion":"1.0"}]}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/tasks" || r.URL.Path == "/v1/tasks" {
			_, _ = io.WriteString(w, body)
			return
		}
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}`)
	}))
}

// A server that scopes its task list correctly and returns nothing to an anonymous
// caller has disclosed nothing. This reported "server-wide task disclosure" at
// critical/confirmed, because the oracle matched the KEY NAME "tasks" in an empty
// envelope.
func TestTaskIDOR_EmptyTaskListIsNotDisclosure(t *testing.T) {
	srv := taskListServer(t, `{"tasks":[],"totalSize":0}`)
	defer srv.Close()

	exec := a2a.NewTaskIDORExecutor(attack.RuleContext{ID: "a2a-task-idor-001", Severity: "high"})
	findings, _ := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	for _, f := range findings {
		if strings.Contains(f.Title, "tasks/list") {
			t.Fatalf("an empty list is the secure answer, not a critical disclosure: %s\n%s",
				f.Title, f.Evidence)
		}
	}
}

// A list without a known owner task cannot prove cross-principal disclosure.
func TestTaskIDOR_PopulatedTaskListWithoutOwnerIsInconclusive(t *testing.T) {
	srv := taskListServer(t, `{"tasks":[{"id":"t1","contextId":"c1"},{"id":"t2","contextId":"c2"}],"totalSize":2}`)
	defer srv.Close()

	exec := a2a.NewTaskIDORExecutor(attack.RuleContext{ID: "a2a-task-idor-001", Severity: "high"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("unattributed list cannot prove disclosure; got findings=%+v err=%v", findings, err)
	}
}
