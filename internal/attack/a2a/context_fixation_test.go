package a2a_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/attack/a2a"
)

type ctxMsg struct {
	tenant string
	text   string
	taskID string
}

// contextServer builds an A2A server that groups messages by contextId. mode:
//   - "vulnerable":   honors a client-supplied contextId AND returns the whole
//     context's history on GetTask (merges principals)
//   - "isolated":     honors the client contextId but GetTask returns only the
//     requested task's own messages (no cross-principal merge)
//   - "server-minted": ignores the client contextId and mints its own
//   - "open":         no authentication at all
//   - "read-fails":   like vulnerable, but GetTask answers HTTP 500, so whether
//     the context merged cannot be observed
func contextServer(mode string) *httptest.Server {
	var mu sync.Mutex
	ctxMsgs := map[string][]ctxMsg{} // contextId -> messages
	taskCtx := map[string]string{}   // taskId -> contextId
	counter := 0

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		req := readBody(r)
		method, _ := req["method"].(string)
		id := req["id"]
		params, _ := req["params"].(map[string]interface{})
		msg, _ := params["message"].(map[string]interface{})
		tenant := tenantOf(r)

		switch method {
		case "SendMessage", "message/send":
			if mode != "open" && tenant == "" {
				rpcErr(w, id, -32600, "authentication required")
				return
			}
			cin, _ := msg["contextId"].(string)
			ctxID := cin
			if mode == "server-minted" || ctxID == "" {
				ctxID = "srv-ctx" // server mints / ignores the client value
			}
			text := ""
			if parts, ok := msg["parts"].([]interface{}); ok && len(parts) > 0 {
				if p, ok := parts[0].(map[string]interface{}); ok {
					text, _ = p["text"].(string)
				}
			}
			tn := tenant
			if tn == "" {
				tn = "anon"
			}
			mu.Lock()
			counter++
			taskID := mkTaskID(tn, counter)
			ctxMsgs[ctxID] = append(ctxMsgs[ctxID], ctxMsg{tenant: tn, text: text, taskID: taskID})
			taskCtx[taskID] = ctxID
			mu.Unlock()
			taskResult(w, id, taskID, ctxID)
		case "GetTask", "tasks/get":
			if mode == "read-fails" {
				// The read-back breaks at the gateway: sends work, but nothing
				// about the merge can be observed.
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if mode != "open" && tenant == "" {
				rpcErr(w, id, -32600, "authentication required")
				return
			}
			taskID, _ := params["id"].(string)
			mu.Lock()
			ctxID := taskCtx[taskID]
			var hist []ctxMsg
			for _, m := range ctxMsgs[ctxID] {
				if mode == "isolated" && m.taskID != taskID {
					continue // task-scoped: no cross-principal merge
				}
				hist = append(hist, m)
			}
			mu.Unlock()
			writeHistory(w, id, taskID, ctxID, hist)
		default:
			rpcErr(w, id, -32601, "Method not found")
		}
	}))
}

func mkTaskID(tenant string, n int) string {
	return "task-" + tenant + "-" + itoa(n)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// writeHistory emits a GetTask success envelope whose history carries the given
// messages (each message's text is included so markers are detectable).
func writeHistory(w http.ResponseWriter, id interface{}, taskID, ctxID string, msgs []ctxMsg) {
	history := make([]interface{}, 0, len(msgs))
	for _, m := range msgs {
		history = append(history, map[string]interface{}{
			"role":  "user",
			"parts": []interface{}{map[string]string{"text": m.text}},
		})
	}
	writeJSON(w, map[string]interface{}{
		"jsonrpc": "2.0", "id": id,
		"result": map[string]interface{}{"id": taskID, "contextId": ctxID, "history": history},
	})
}

// TestContextFixation_Vulnerable: the server honors the client contextId and
// merges both principals' messages, so A reads B's marker. MUST fire (confirmed).
func TestContextFixation_Vulnerable(t *testing.T) {
	ts := contextServer("vulnerable")
	defer ts.Close()

	findings, err := a2a.NewContextFixationExecutor(testRuleCtx()).
		Execute(context.Background(), ts.URL, mtOpts(tenantPrincipals()...))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 context-fixation finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Confidence != attack.ConfirmedExploit || f.Severity != "high" {
		t.Errorf("want high/ConfirmedExploit, got %q/%q", f.Severity, f.Confidence)
	}
	if len(f.Chain) != 3 || f.Chain[2].Principal != "tenant-a" {
		t.Errorf("expected a 3-hop chain ending with the attacker reading, got %+v", f.Chain)
	}
}

// TestContextFixation_Isolated: the server honors the client contextId but keeps
// each task's history task-scoped (no cross-principal merge). MUST stay silent.
func TestContextFixation_Isolated(t *testing.T) {
	ts := contextServer("isolated")
	defer ts.Close()

	findings, err := a2a.NewContextFixationExecutor(testRuleCtx()).
		Execute(context.Background(), ts.URL, mtOpts(tenantPrincipals()...))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings when contexts are isolated per principal, got %d: %+v", len(findings), findings)
	}
}

// TestContextFixation_ServerMinted: the server mints its own contextId, ignoring
// the client-supplied one. MUST stay silent (fixation precondition absent).
func TestContextFixation_ServerMinted(t *testing.T) {
	ts := contextServer("server-minted")
	defer ts.Close()

	findings, err := a2a.NewContextFixationExecutor(testRuleCtx()).
		Execute(context.Background(), ts.URL, mtOpts(tenantPrincipals()...))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings when the server mints its own contextId, got %d: %+v", len(findings), findings)
	}
}

// TestContextFixation_UnreadableReadBackIsNotTested: the discriminator passed,
// both principals posted under the fixed context, and then the attacker's
// read-back failed. A "marker not found" in a history that was never fetched is
// not evidence of isolation; this used to return clean, while
// a2a-artifact-tamper-001 reports the identical unreadable read-back as not
// tested.
func TestContextFixation_UnreadableReadBackIsNotTested(t *testing.T) {
	ts := contextServer("read-fails")
	defer ts.Close()

	findings, err := a2a.NewContextFixationExecutor(testRuleCtx()).
		Execute(context.Background(), ts.URL, mtOpts(tenantPrincipals()...))
	if len(findings) != 0 {
		t.Fatalf("expected zero findings, got %d: %+v", len(findings), findings)
	}
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected ErrInconclusive for an unreadable read-back, got %v", err)
	}
}

// TestContextFixation_OpenServerIsNotFixation: no auth at all, so the unauth
// message under the fixed context succeeds. MUST stay silent (discriminator).
func TestContextFixation_OpenServerIsNotFixation(t *testing.T) {
	ts := contextServer("open")
	defer ts.Close()

	findings, err := a2a.NewContextFixationExecutor(testRuleCtx()).
		Execute(context.Background(), ts.URL, mtOpts(tenantPrincipals()...))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings against a fully-open server, got %d: %+v", len(findings), findings)
	}
}

// TestContextFixation_RequiresTwoPrincipals: fewer than two principals => skip.
func TestContextFixation_RequiresTwoPrincipals(t *testing.T) {
	ts := contextServer("vulnerable")
	defer ts.Close()

	findings, err := a2a.NewContextFixationExecutor(testRuleCtx()).
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
