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

func continuationTaskID(req map[string]interface{}) string {
	params, _ := req["params"].(map[string]interface{})
	msg, _ := params["message"].(map[string]interface{})
	id, _ := msg["taskId"].(string)
	return id
}

func continuationMessage(req map[string]interface{}) map[string]interface{} {
	params, _ := req["params"].(map[string]interface{})
	msg, _ := params["message"].(map[string]interface{})
	return msg
}

// delegationServer stores continuations so owner readback can verify them.
func delegationServer(mode string) *httptest.Server {
	var mu sync.Mutex
	owner := map[string]string{}
	history := map[string][]map[string]interface{}{}
	lastMessageID := ""
	counter := 0
	readCount := 0

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
		if mode == "legacy-only" && !strings.Contains(method, "/") {
			rpcErr(w, id, -32601, "Method not found")
			return
		}

		switch method {
		case "GetTask", "tasks/get":
			params, _ := req["params"].(map[string]interface{})
			taskID, _ := params["id"].(string)
			mu.Lock()
			own, exists := owner[taskID]
			stored := append([]map[string]interface{}{}, history[taskID]...)
			echoed := lastMessageID
			if mode == "delayed-history" {
				readCount++
				if readCount <= 2 && len(stored) > 1 {
					stored = stored[:1]
				}
			}
			mu.Unlock()
			if !exists || (mode == "secure" && tenant != own) || mode == "get-unavailable" {
				rpcErr(w, id, -32001, "task not found")
				return
			}
			task := map[string]interface{}{
				"id": taskID, "contextId": "ctx-" + own, "status": map[string]interface{}{"state": "input-required"},
				"history": stored, "metadata": map[string]string{"lastMessageId": echoed},
			}
			if mode == "omitted-history" && len(stored) == 0 {
				delete(task, "history")
			}
			writeJSON(w, map[string]interface{}{"jsonrpc": "2.0", "id": id, "result": task})
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
				taskID := fmt.Sprintf("task-%s-%d", tn, counter)
				owner[taskID] = tn
				history[taskID] = []map[string]interface{}{continuationMessage(req)}
				if mode == "empty-history" || mode == "omitted-history" {
					history[taskID] = []map[string]interface{}{}
				}
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
				mu.Lock()
				history[contID] = append(history[contID], continuationMessage(req))
				mu.Unlock()
				taskResult(w, id, contID, "ctx-"+own)
			case "anon-no-op", "empty-history", "omitted-history":
				if tenant != "" {
					mu.Lock()
					history[contID] = append(history[contID], continuationMessage(req))
					mu.Unlock()
				}
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
				mu.Lock()
				history[contID] = append(history[contID], continuationMessage(req))
				mu.Unlock()
				taskResult(w, id, contID, "ctx-"+own)
			case "no-op", "get-unavailable", "echo-metadata":
				if tenant == "" {
					rpcErr(w, id, -32600, "authentication required")
					return
				}
				if mode == "echo-metadata" {
					mu.Lock()
					lastMessageID, _ = continuationMessage(req)["messageId"].(string)
					mu.Unlock()
				}
				taskResult(w, id, contID, "ctx-"+own)
			case "echo-agent-history":
				if tenant == "" {
					rpcErr(w, id, -32600, "authentication required")
					return
				}
				echo := continuationMessage(req)
				echo["role"] = "agent"
				mu.Lock()
				history[contID] = append(history[contID], echo)
				mu.Unlock()
				taskResult(w, id, contID, "ctx-"+own)
			case "echo-id-only-history":
				if tenant == "" {
					rpcErr(w, id, -32600, "authentication required")
					return
				}
				msg := continuationMessage(req)
				mu.Lock()
				history[contID] = append(history[contID], map[string]interface{}{
					"role": msg["role"], "taskId": contID, "messageId": msg["messageId"],
				})
				mu.Unlock()
				taskResult(w, id, contID, "ctx-"+own)
			case "error-after-write", "anon-error-after-write":
				if tenant == "" && mode != "anon-error-after-write" {
					rpcErr(w, id, -32600, "authentication required")
					return
				}
				mu.Lock()
				history[contID] = append(history[contID], continuationMessage(req))
				mu.Unlock()
				rpcErr(w, id, -32000, "processing failed after enqueue")
			case "same-context":
				if tenant == "" {
					rpcErr(w, id, -32600, "authentication required")
					return
				}
				taskResult(w, id, "task-new-for-"+tenant, "ctx-"+own)
			default: // vulnerable
				if tenant == "" {
					rpcErr(w, id, -32600, "authentication required") // auth enforced...
					return
				}
				mu.Lock()
				history[contID] = append(history[contID], continuationMessage(req))
				mu.Unlock()
				taskResult(w, id, contID, "ctx-"+own)
			}
		default:
			rpcErr(w, id, -32601, "Method not found")
		}
	}))
}

// A stored cross-principal continuation yields a confirmed two-hop finding.
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

func TestDelegation_AcknowledgedWithoutMutation(t *testing.T) {
	ts := delegationServer("no-op")
	defer ts.Close()

	findings, err := a2a.NewDelegationIntegrityExecutor(testRuleCtx()).
		Execute(context.Background(), ts.URL, mtOpts(tenantPrincipals()...))
	if !errors.Is(err, attack.ErrInconclusive) || len(findings) != 0 {
		t.Fatalf("unchanged task must not confirm a continuation: findings=%+v err=%v", findings, err)
	}
}

func TestDelegation_DelayedHistory(t *testing.T) {
	ts := delegationServer("delayed-history")
	defer ts.Close()

	findings, err := a2a.NewDelegationIntegrityExecutor(testRuleCtx()).
		Execute(context.Background(), ts.URL, mtOpts(tenantPrincipals()...))
	if err != nil || len(findings) != 1 {
		t.Fatalf("delayed owner history must confirm the stored continuation: findings=%+v err=%v", findings, err)
	}
}

func TestDelegation_UnreadableOwnerHistory(t *testing.T) {
	ts := delegationServer("get-unavailable")
	defer ts.Close()

	findings, err := a2a.NewDelegationIntegrityExecutor(testRuleCtx()).
		Execute(context.Background(), ts.URL, mtOpts(tenantPrincipals()...))
	if !errors.Is(err, attack.ErrInconclusive) || len(findings) != 0 {
		t.Fatalf("unreadable owner history must not confirm a continuation: findings=%+v err=%v", findings, err)
	}
}

func TestDelegation_MarkerEchoOutsideHistory(t *testing.T) {
	ts := delegationServer("echo-metadata")
	defer ts.Close()

	findings, err := a2a.NewDelegationIntegrityExecutor(testRuleCtx()).
		Execute(context.Background(), ts.URL, mtOpts(tenantPrincipals()...))
	if !errors.Is(err, attack.ErrInconclusive) || len(findings) != 0 {
		t.Fatalf("metadata echo is not task-history evidence: findings=%+v err=%v", findings, err)
	}
}

func TestDelegation_AgentEchoInHistory(t *testing.T) {
	ts := delegationServer("echo-agent-history")
	defer ts.Close()

	findings, err := a2a.NewDelegationIntegrityExecutor(testRuleCtx()).
		Execute(context.Background(), ts.URL, mtOpts(tenantPrincipals()...))
	if !errors.Is(err, attack.ErrInconclusive) || len(findings) != 0 {
		t.Fatalf("agent echo is not a stored user continuation: findings=%+v err=%v", findings, err)
	}
}

func TestDelegation_IDOnlyEchoInHistory(t *testing.T) {
	ts := delegationServer("echo-id-only-history")
	defer ts.Close()

	findings, err := a2a.NewDelegationIntegrityExecutor(testRuleCtx()).
		Execute(context.Background(), ts.URL, mtOpts(tenantPrincipals()...))
	if !errors.Is(err, attack.ErrInconclusive) || len(findings) != 0 {
		t.Fatalf("message ID alone is not stored-content evidence: findings=%+v err=%v", findings, err)
	}
}

func TestDelegation_ErrorAfterWrite(t *testing.T) {
	ts := delegationServer("error-after-write")
	defer ts.Close()

	findings, err := a2a.NewDelegationIntegrityExecutor(testRuleCtx()).
		Execute(context.Background(), ts.URL, mtOpts(tenantPrincipals()...))
	if err != nil || len(findings) != 1 {
		t.Fatalf("stored continuation must be reported despite response error: findings=%+v err=%v", findings, err)
	}
}

func TestDelegation_AnonymousErrorAfterWrite(t *testing.T) {
	ts := delegationServer("anon-error-after-write")
	defer ts.Close()

	findings, err := a2a.NewDelegationIntegrityExecutor(testRuleCtx()).
		Execute(context.Background(), ts.URL, mtOpts(tenantPrincipals()...))
	if err != nil || len(findings) != 0 {
		t.Fatalf("stored anonymous continuation must suppress delegation finding: findings=%+v err=%v", findings, err)
	}
}

func TestDelegation_LegacyOnly(t *testing.T) {
	ts := delegationServer("legacy-only")
	defer ts.Close()

	findings, err := a2a.NewDelegationIntegrityExecutor(testRuleCtx()).
		Execute(context.Background(), ts.URL, mtOpts(tenantPrincipals()...))
	if err != nil || len(findings) != 1 {
		t.Fatalf("expected verified v0.3 continuation: findings=%+v err=%v", findings, err)
	}
}

func TestDelegation_NewTaskInSameContext(t *testing.T) {
	ts := delegationServer("same-context")
	defer ts.Close()

	findings, err := a2a.NewDelegationIntegrityExecutor(testRuleCtx()).
		Execute(context.Background(), ts.URL, mtOpts(tenantPrincipals()...))
	if !errors.Is(err, attack.ErrInconclusive) || len(findings) != 0 {
		t.Fatalf("new task in A's context is not an A-task continuation: findings=%+v err=%v", findings, err)
	}
}

// Owner-bound continuations produce no finding.
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

// A stored anonymous continuation belongs to the unauthenticated-access rules.
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

func TestDelegation_AcknowledgedAnonymousNoOp(t *testing.T) {
	ts := delegationServer("anon-no-op")
	defer ts.Close()

	findings, err := a2a.NewDelegationIntegrityExecutor(testRuleCtx()).
		Execute(context.Background(), ts.URL, mtOpts(tenantPrincipals()...))
	if err != nil || len(findings) != 1 {
		t.Fatalf("anonymous no-op must not hide a stored B continuation: findings=%+v err=%v", findings, err)
	}
}

func TestDelegation_EmptyHistoryBeforeCrossPrincipalSend(t *testing.T) {
	ts := delegationServer("empty-history")
	defer ts.Close()

	findings, err := a2a.NewDelegationIntegrityExecutor(testRuleCtx()).
		Execute(context.Background(), ts.URL, mtOpts(tenantPrincipals()...))
	if err != nil || len(findings) != 1 {
		t.Fatalf("empty owner history must not hide a stored B continuation: findings=%+v err=%v", findings, err)
	}
}

func TestDelegation_OmittedHistoryBeforeCrossPrincipalSend(t *testing.T) {
	ts := delegationServer("omitted-history")
	defer ts.Close()

	findings, err := a2a.NewDelegationIntegrityExecutor(testRuleCtx()).
		Execute(context.Background(), ts.URL, mtOpts(tenantPrincipals()...))
	if err != nil || len(findings) != 1 {
		t.Fatalf("omitted history must not hide a stored B continuation: findings=%+v err=%v", findings, err)
	}
}

// Cross-principal checks need two identities.
func TestDelegation_RequiresTwoPrincipals(t *testing.T) {
	ts := delegationServer("vulnerable")
	defer ts.Close()

	findings, err := a2a.NewDelegationIntegrityExecutor(testRuleCtx()).
		Execute(context.Background(), ts.URL, mtOpts(tenantPrincipals()[:1]...))
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("one principal cannot exercise a cross-principal rule; want ErrInconclusive, got %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings, got %d", len(findings))
	}
}

// A blackboard task remains usable when task creation is disabled.
func TestDelegation_ConsumesBlackboardTaskID(t *testing.T) {
	const preTask = "task-tenant-a-upstream"
	var mu sync.Mutex
	var history []map[string]interface{}
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

		if method == "GetTask" || method == "tasks/get" {
			params, _ := req["params"].(map[string]interface{})
			if params["id"] != preTask || tenant != "A" {
				rpcErr(w, id, -32001, "task not found")
				return
			}
			mu.Lock()
			stored := append([]map[string]interface{}(nil), history...)
			mu.Unlock()
			writeJSON(w, map[string]interface{}{"jsonrpc": "2.0", "id": id, "result": map[string]interface{}{
				"id": preTask, "contextId": "ctx-upstream", "history": stored,
			}})
			return
		}
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
		mu.Lock()
		history = append(history, continuationMessage(req))
		mu.Unlock()
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

// A new task for B does not prove a continuation of A's task.
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
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("unverified new-task response must be inconclusive, got %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("FALSE POSITIVE: B got its own new task, not A's; got %d finding(s): %s",
			len(findings), findings[0].Title)
	}
}
