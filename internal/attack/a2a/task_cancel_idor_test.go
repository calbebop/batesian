package a2a_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	a2aattack "github.com/calbebop/batesian/internal/attack/a2a"
)

// cancelServer builds a mock A2A server whose cancel behavior depends on mode:
//   - "vuln":           unauth cancel is rejected (401) but ANY authenticated
//     token may cancel any task (cross-principal IDOR).
//   - "secure":         cancel is bound to the task's owner; unauth -> 401, a
//     non-owner token -> 403.
//   - "no-auth":        cancel is accepted with no credentials at all.
//   - "not-cancelable": cancel always returns TaskNotCancelable (-32002).
//   - "not-a2a":        every request 404s.
//
// GetTask/tasks/get returns the stored task state so the rule's owner read-back
// can confirm a cancellation persisted.
func cancelServer(mode string) *httptest.Server {
	type task struct {
		state string
		owner string
	}
	var mu sync.Mutex
	store := map[string]*task{}
	counter := 0

	bearer := func(r *http.Request) string {
		return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mode == "not-a2a" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var req map[string]interface{}
		_ = json.Unmarshal(body, &req)
		method, _ := req["method"].(string)
		id := req["id"]
		params, _ := req["params"].(map[string]interface{})
		tok := bearer(r)
		w.Header().Set("Content-Type", "application/json")

		result := func(res map[string]interface{}) {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": id, "result": res})
		}
		rpcErr := func(code int, msg string) {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": id,
				"error": map[string]interface{}{"code": code, "message": msg}})
		}
		taskID, _ := params["id"].(string)

		switch method {
		case "SendMessage", "message/send":
			mu.Lock()
			counter++
			tid := fmt.Sprintf("task-%d", counter)
			store[tid] = &task{state: "submitted", owner: tok}
			mu.Unlock()
			result(map[string]interface{}{"id": tid, "contextId": "ctx-" + tid,
				"status": map[string]interface{}{"state": "submitted"}})

		case "CancelTask", "tasks/cancel":
			if mode == "not-cancelable" {
				rpcErr(-32002, "Task is not in a cancelable state")
				return
			}
			if mode != "no-auth" && tok == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			mu.Lock()
			t := store[taskID]
			if mode == "secure" && (t == nil || t.owner != tok) {
				mu.Unlock()
				w.WriteHeader(http.StatusForbidden)
				return
			}
			if t != nil {
				t.state = "canceled"
			}
			mu.Unlock()
			result(map[string]interface{}{"id": taskID, "status": map[string]interface{}{"state": "canceled"}})

		case "GetTask", "tasks/get":
			mu.Lock()
			t := store[taskID]
			mu.Unlock()
			if t == nil {
				rpcErr(-32001, "Task not found")
				return
			}
			result(map[string]interface{}{"id": taskID, "contextId": "ctx-" + taskID,
				"status": map[string]interface{}{"state": t.state}})

		default:
			rpcErr(-32601, "method not found")
		}
	}))
}

func runTaskCancel(t *testing.T, srv *httptest.Server) ([]attack.Finding, error) {
	t.Helper()
	exec := a2aattack.NewTaskCancelIDORExecutor(attack.RuleContext{
		ID:   "a2a-task-cancel-idor-001",
		Name: "A2A Cross-Principal Task Cancellation",
	})
	return exec.Execute(context.Background(), srv.URL, attack.Options{
		TimeoutSeconds: 5,
		Principals: []attack.Principal{
			{Name: "tenant-a", Token: "tok-a", Tenant: "A"},
			{Name: "tenant-b", Token: "tok-b", Tenant: "B"},
		},
	})
}

// TestTaskCancelIDOR_CrossPrincipal: unauth cancel rejected, but a different
// authenticated principal cancels the owner's task => confirmed IDOR.
func TestTaskCancelIDOR_CrossPrincipal(t *testing.T) {
	srv := cancelServer("vuln")
	defer srv.Close()

	findings, err := runTaskCancel(t, srv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Confidence != attack.ConfirmedExploit || f.Severity != "high" {
		t.Errorf("expected high/confirmed, got %q/%v", f.Severity, f.Confidence)
	}
	if !strings.Contains(f.Title, "non-owning") {
		t.Errorf("expected the cross-principal IDOR finding, got title %q", f.Title)
	}
}

// TestTaskCancelIDOR_Unauthenticated: cancel accepted with no credentials =>
// the unauthenticated-cancellation finding.
func TestTaskCancelIDOR_Unauthenticated(t *testing.T) {
	srv := cancelServer("no-auth")
	defer srv.Close()

	findings, err := runTaskCancel(t, srv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Title, "without authentication") {
		t.Errorf("expected the unauthenticated-cancel finding, got title %q", findings[0].Title)
	}
}

// TestTaskCancelIDOR_Secure: cancel bound to the owner => no finding.
func TestTaskCancelIDOR_Secure(t *testing.T) {
	srv := cancelServer("secure")
	defer srv.Close()

	if findings, err := runTaskCancel(t, srv); err != nil || len(findings) != 0 {
		t.Errorf("expected 0 findings / nil err for owner-bound cancel, got %d findings, err=%v", len(findings), err)
	}
}

// TestTaskCancelIDOR_NotCancelable: task cannot be canceled => no finding.
func TestTaskCancelIDOR_NotCancelable(t *testing.T) {
	srv := cancelServer("not-cancelable")
	defer srv.Close()

	if findings, err := runTaskCancel(t, srv); err != nil || len(findings) != 0 {
		t.Errorf("expected 0 findings / nil err when the task is not cancelable, got %d findings, err=%v", len(findings), err)
	}
}

// TestTaskCancelIDOR_NotA2A: no reachable endpoint => inconclusive.
func TestTaskCancelIDOR_NotA2A(t *testing.T) {
	srv := cancelServer("not-a2a")
	defer srv.Close()

	_, err := runTaskCancel(t, srv)
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected ErrInconclusive for a non-A2A endpoint, got err=%v", err)
	}
}
