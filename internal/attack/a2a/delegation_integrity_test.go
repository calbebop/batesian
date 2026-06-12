package a2a_test

import (
	"context"
	"net/http"
	"net/http/httptest"
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected clean skip with one principal, got %d findings", len(findings))
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
	if c := findings[0].Chain; len(c) != 2 || !containsSub(c[0].Action, preTask) || !containsSub(c[0].Action, "consumed from blackboard") {
		t.Errorf("expected hop 1 to cite the consumed blackboard task, got %+v", c)
	}
}

func containsSub(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
