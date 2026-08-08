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
	"github.com/calbebop/batesian/internal/attack/a2a"
)

// continuationTaskID extracts message.taskId from a JSON-RPC SendMessage body.
// A non-empty value marks the request as a delegated continuation rather than a
// fresh task creation.
func continuationTaskID(req map[string]interface{}) string {
	params, _ := req["params"].(map[string]interface{})
	msg, _ := params["message"].(map[string]interface{})
	id, _ := msg["taskId"].(string)
	return id
}

// delegationServer builds an A2A server that supports task creation and delegated
// continuation. mode selects the posture for continuation:
//   - "vulnerable": any authenticated principal may continue any task (ignores owner)
//   - "secure":     only the owning tenant may continue its task
//   - "open":       no authentication at all (unauth continuation succeeds)
func delegationServer(mode string) *httptest.Server {
	var mu sync.Mutex
	owner := map[string]string{}
	counter := 0

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		req := readBody(r)
		method, _ := req["method"].(string)
		id := req["id"]
		tenant := tenantOf(r)
		contID := continuationTaskID(req)

		switch method {
		case "SendMessage", "message/send":
			if contID == "" { // task creation
				if mode != "open" && tenant == "" {
					rpcErr(w, id, -32600, "authentication required")
					return
				}
				tn := tenant
				if tn == "" {
					tn = "anon"
				}
				mu.Lock()
				counter++
				taskID := "task-" + tn + "-1"
				owner[taskID] = tn
				mu.Unlock()
				taskResult(w, id, taskID, "ctx-"+tn)
				return
			}
			// delegated continuation
			mu.Lock()
			own := owner[contID]
			mu.Unlock()
			switch mode {
			case "open":
				taskResult(w, id, contID, "ctx-"+own)
			case "secure":
				if tenant == "" {
					rpcErr(w, id, -32600, "authentication required")
					return
				}
				if tenant != own {
					rpcErr(w, id, -32001, "task not found") // owner-bound continuation
					return
				}
				taskResult(w, id, contID, "ctx-"+own)
			default: // vulnerable
				if tenant == "" {
					rpcErr(w, id, -32600, "authentication required") // auth enforced...
					return
				}
				taskResult(w, id, contID, "ctx-"+own) // ...but owner IS NOT checked
			}
		default:
			rpcErr(w, id, -32601, "Method not found")
		}
	}))
}

// TestDelegation_Vulnerable: the wrong principal can continue another principal's
// task. The rule MUST fire (confirmed, high) with a 2-hop chain.
func TestDelegation_Vulnerable(t *testing.T) {
	ts := delegationServer("vulnerable")
	defer ts.Close()

	findings, err := a2a.NewDelegationIntegrityExecutor(testRuleCtx()).
		Execute(context.Background(), ts.URL, mtOpts(tenantPrincipals()...))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 delegation finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Confidence != attack.ConfirmedExploit || f.Severity != "high" {
		t.Errorf("want high/ConfirmedExploit, got %q/%q", f.Severity, f.Confidence)
	}
	if len(f.Chain) != 2 || f.Chain[1].Principal != "tenant-b" {
		t.Errorf("expected 2-hop chain with tenant-b continuing, got %+v", f.Chain)
	}
}

// TestDelegation_Secure: continuation is owner-bound. The rule MUST stay silent.
func TestDelegation_Secure(t *testing.T) {
	ts := delegationServer("secure")
	defer ts.Close()

	findings, err := a2a.NewDelegationIntegrityExecutor(testRuleCtx()).
		Execute(context.Background(), ts.URL, mtOpts(tenantPrincipals()...))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings against owner-bound continuation, got %d: %+v", len(findings), findings)
	}
}

// TestDelegation_OpenServerIsNotADelegationBreak: no auth at all, so the unauth
// continuation succeeds. That is task-idor territory, not a delegation-binding
// break. The rule MUST stay silent (discriminator suppresses).
func TestDelegation_OpenServerIsNotADelegationBreak(t *testing.T) {
	ts := delegationServer("open")
	defer ts.Close()

	findings, err := a2a.NewDelegationIntegrityExecutor(testRuleCtx()).
		Execute(context.Background(), ts.URL, mtOpts(tenantPrincipals()...))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings against a fully-open server, got %d: %+v", len(findings), findings)
	}
}

// TestDelegation_RequiresTwoPrincipals: fewer than two principals => clean skip.
func TestDelegation_RequiresTwoPrincipals(t *testing.T) {
	ts := delegationServer("vulnerable")
	defer ts.Close()

	findings, err := a2a.NewDelegationIntegrityExecutor(testRuleCtx()).
		Execute(context.Background(), ts.URL, mtOpts(tenantPrincipals()[:1]...))
	// A rule that sends no packets has not tested anything. This used to assert
	// err == nil, which under the project's convention means "tested, and the target
	// is secure" - about a deliberately vulnerable fixture, with zero requests sent.
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("one principal cannot exercise a cross-principal rule; want ErrInconclusive, got %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings, got %d", len(findings))
	}
}

// TestDelegation_ConsumesBlackboardTaskID proves cross-rule chaining: the server
// REFUSES task creation, so the only delegator task available is one pre-seeded
// on the blackboard (as an upstream rule would publish it). The rule must consume
// that artifact and fire, marking the task as blackboard-sourced in its chain.
func TestDelegation_ConsumesBlackboardTaskID(t *testing.T) {
	const preTask = "task-tenant-a-upstream"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		req := readBody(r)
		method, _ := req["method"].(string)
		id := req["id"]
		tenant := tenantOf(r)
		contID := continuationTaskID(req)

		if method != "SendMessage" && method != "message/send" {
			rpcErr(w, id, -32601, "Method not found")
			return
		}
		if contID == "" {
			rpcErr(w, id, -32600, "task creation disabled") // force reliance on the artifact
			return
		}
		if tenant == "" {
			rpcErr(w, id, -32600, "authentication required") // unauth continuation rejected
			return
		}
		taskResult(w, id, contID, "ctx-upstream") // wrong-principal continuation accepted
	}))
	defer ts.Close()

	bb := attack.NewBlackboard()
	bb.Publish(attack.Artifact{
		Kind:      attack.ArtifactTaskID,
		Value:     preTask,
		Principal: "tenant-a",
		Producer:  "a2a-multitenant-isolation-001",
		Meta:      map[string]string{"contextId": "ctx-upstream"},
	})

	findings, err := a2a.NewDelegationIntegrityExecutor(testRuleCtx()).
		ExecuteChained(context.Background(), ts.URL, mtOpts(tenantPrincipals()...), bb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding consuming the blackboard task-id, got %d: %+v", len(findings), findings)
	}
	if c := findings[0].Chain; len(c) != 2 || !strings.Contains(c[0].Action, preTask) || !strings.Contains(c[0].Action, "consumed from blackboard") {
		t.Errorf("expected hop 1 to cite the consumed blackboard task, got %+v", c)
	}
}

// A server with tenant-scoped task stores. Principal B's continuation names A's
// taskId, which B's store does not contain, so the server treats the message as a
// NEW conversation and answers with a new task. It has correctly refused to expose
// A's task, and there is no chain-of-custody break to report.
//
// This used to fire high/ConfirmedExploit: the acceptance oracle accepted the bare
// key name "contextId", which the new task's envelope contains.
func TestDelegationIntegrity_NewTaskForUnknownIDIsNotAContinuation(t *testing.T) {
	var created int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, ".well-known") {
			writeJSON(w, map[string]interface{}{"name": "scoped", "version": "1.0"})
			return
		}
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Method string `json:"method"`
			Params struct {
				Message struct {
					TaskID string `json:"taskId"`
				} `json:"message"`
			} `json:"params"`
		}
		_ = json.Unmarshal(body, &req)

		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// Every send yields a task in the CALLER's own tenant namespace. A taskId
		// the caller does not own is simply not continued.
		created++
		writeJSON(w, map[string]interface{}{"jsonrpc": "2.0", "id": 1, "result": map[string]interface{}{
			"id":        fmt.Sprintf("task-%s-%d", token, created),
			"contextId": "ctx-" + token,
			"status":    map[string]interface{}{"state": "working"},
		}})
	}))
	defer srv.Close()

	exec := a2a.NewDelegationIntegrityExecutor(testRuleCtx())
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{
		TimeoutSeconds: 5,
		Principals: []attack.Principal{
			{Name: "a", Token: "tok-a"},
			{Name: "b", Token: "tok-b"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("FALSE POSITIVE: B got its own new task, not A's; got %d finding(s): %s",
			len(findings), findings[0].Title)
	}
}
