package a2a_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/attack/a2a"
)

// roleOf extracts params.message.role from a decoded SendMessage request body.
func roleOf(req map[string]interface{}) interface{} {
	params, _ := req["params"].(map[string]interface{})
	msg, _ := params["message"].(map[string]interface{})
	return msg["role"]
}

func textOf(req map[string]interface{}) string {
	params, _ := req["params"].(map[string]interface{})
	msg, _ := params["message"].(map[string]interface{})
	parts, _ := msg["parts"].([]interface{})
	if len(parts) == 0 {
		return ""
	}
	p, _ := parts[0].(map[string]interface{})
	t, _ := p["text"].(string)
	return t
}

func isAgentRoleVal(v interface{}) bool {
	switch r := v.(type) {
	case float64:
		return r == 2
	case string:
		return r == "agent" || r == "ROLE_AGENT"
	}
	return false
}

// TestSessionSmuggle_VulnerableHonored: the server accepts an agent-role message
// and stores it verbatim in history. The rule MUST fire as a confirmed exploit.
func TestSessionSmuggle_VulnerableHonored(t *testing.T) {
	var stored map[string]interface{} // last accepted message, echoed into history
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		body := readBody(r)
		method, _ := body["method"].(string)
		id := body["id"]
		switch method {
		case "SendMessage", "message/send":
			params, _ := body["params"].(map[string]interface{})
			stored, _ = params["message"].(map[string]interface{}) // honored as-is
			taskResult(w, id, "task-smuggle-1", "ctx-smuggle-1")
		case "GetTask", "tasks/get":
			writeJSON(w, map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{
					"id": "task-smuggle-1", "contextId": "ctx-smuggle-1",
					"history": []interface{}{stored},
				},
			})
		default:
			rpcErr(w, id, -32601, "Method not found")
		}
	}))
	defer ts.Close()

	findings, err := a2a.NewSessionSmuggleExecutor(testRuleCtx()).Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Confidence != attack.ConfirmedExploit {
		t.Errorf("want ConfirmedExploit, got %q", findings[0].Confidence)
	}
}

// TestSessionSmuggle_V03OnlyFallback: a server that implements only the legacy
// v0.3 message/send method, answering the v1.0 SendMessage with -32601. Before
// the fallback-trigger fix the rule never tried message/send here (the v1.0
// -32601 response did not trigger the fallback) and silently reported clean;
// after the fix the rule falls back to message/send, the agent-role message is
// honored, and the confirmed finding fires.
func TestSessionSmuggle_V03OnlyFallback(t *testing.T) {
	var stored map[string]interface{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		body := readBody(r)
		method, _ := body["method"].(string)
		id := body["id"]
		switch method {
		case "SendMessage":
			rpcErr(w, id, -32601, "Method not found") // v1.0 method not implemented
		case "message/send":
			params, _ := body["params"].(map[string]interface{})
			stored, _ = params["message"].(map[string]interface{})
			taskResult(w, id, "task-smuggle-v03", "ctx-smuggle-v03")
		case "GetTask", "tasks/get":
			writeJSON(w, map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{
					"id": "task-smuggle-v03", "contextId": "ctx-smuggle-v03",
					"history": []interface{}{stored},
				},
			})
		default:
			rpcErr(w, id, -32601, "Method not found")
		}
	}))
	defer ts.Close()

	findings, err := a2a.NewSessionSmuggleExecutor(testRuleCtx()).Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding via the v0.3 fallback, got %d: %+v", len(findings), findings)
	}
	if findings[0].Confidence != attack.ConfirmedExploit {
		t.Errorf("want ConfirmedExploit, got %q", findings[0].Confidence)
	}
}

// TestSessionSmuggle_PatchedRejects: the server rejects any non-user role with
// JSON-RPC -32602. The rule MUST stay silent.
func TestSessionSmuggle_PatchedRejects(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		body := readBody(r)
		id := body["id"]
		if isAgentRoleVal(roleOf(body)) {
			rpcErr(w, id, -32602, "Invalid params: role must be USER")
			return
		}
		taskResult(w, id, "task-ok-1", "ctx-ok-1")
	}))
	defer ts.Close()

	findings, err := a2a.NewSessionSmuggleExecutor(testRuleCtx()).Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings against patched server, got %d: %+v", len(findings), findings)
	}
}

// TestSessionSmuggle_AcceptedButNormalized: the server accepts the request but
// normalizes the role to user before storing. The injection is neutralized, so
// the rule MUST NOT fire (this is the over-claim guard).
func TestSessionSmuggle_AcceptedButNormalized(t *testing.T) {
	var markerText string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		body := readBody(r)
		method, _ := body["method"].(string)
		id := body["id"]
		switch method {
		case "SendMessage", "message/send":
			markerText = textOf(body)
			taskResult(w, id, "task-norm-1", "ctx-norm-1") // accepted (no error)
		case "GetTask", "tasks/get":
			writeJSON(w, map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{
					"id": "task-norm-1", "contextId": "ctx-norm-1",
					"history": []interface{}{
						// marker preserved but role coerced to user (1)
						map[string]interface{}{"role": 1, "parts": []interface{}{map[string]string{"text": markerText}}},
					},
				},
			})
		default:
			rpcErr(w, id, -32601, "Method not found")
		}
	}))
	defer ts.Close()

	findings, err := a2a.NewSessionSmuggleExecutor(testRuleCtx()).Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings when role is normalized to user, got %d: %+v", len(findings), findings)
	}
}

// The server accepts the agent-role message but exposes no retrievable history
// (GetTask errors). This used to be a high/RiskIndicator finding, and it was a
// finding produced BECAUSE nothing was determined.
//
// Acceptance on its own is not the failure. The specification defines the roles by
// direction and carries no MUST or SHOULD requiring a server to validate or reject a
// client-supplied role, and both official SDKs accept one, so the old finding rested
// on a requirement that does not exist. What this rule reports is the STORED turn,
// and without the history that cannot be established either way: not tested.
func TestSessionSmuggle_AcceptedUnverifiableIsNotTested(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		body := readBody(r)
		method, _ := body["method"].(string)
		id := body["id"]
		switch method {
		case "SendMessage", "message/send":
			taskResult(w, id, "task-unv-1", "ctx-unv-1")
		default: // GetTask / tasks/get not supported
			rpcErr(w, id, -32601, "Method not found")
		}
	}))
	defer ts.Close()

	findings, err := a2a.NewSessionSmuggleExecutor(testRuleCtx()).Execute(context.Background(), ts.URL, testOpts())
	if len(findings) != 0 {
		t.Fatalf("acceptance alone is not a finding, got %d: %+v", len(findings), findings)
	}
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected ErrInconclusive, got %v", err)
	}
	// The reason has to say which half was missing, or an operator cannot act on it.
	if !strings.Contains(err.Error(), "history could not be read back") {
		t.Errorf("reason should name the unreadable history; got: %v", err)
	}
}

// A2A permits answering a send with a Message rather than a Task. There is then no
// history at all, so the same not-tested applies, and the reason has to say so
// rather than blaming an unreadable history that was never involved.
func TestSessionSmuggle_AcceptedWithNoTaskIsNotTested(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		body := readBody(r)
		id := body["id"]
		w.Header().Set("Content-Type", "application/json")
		// A Message result: legal, and it carries no task identifiers.
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": id,
			"result": map[string]interface{}{
				"messageId": "srv-1", "role": "ROLE_AGENT",
				"parts": []interface{}{map[string]string{"text": "TASK_STATE_SUBMITTED"}},
			},
		})
	}))
	defer ts.Close()

	findings, err := a2a.NewSessionSmuggleExecutor(testRuleCtx()).Execute(context.Background(), ts.URL, testOpts())
	if len(findings) != 0 {
		t.Fatalf("no task means no stored turn to report, got %d: %+v", len(findings), findings)
	}
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected ErrInconclusive, got %v", err)
	}
	if !strings.Contains(err.Error(), "no task id") {
		t.Errorf("reason should name the missing task; got: %v", err)
	}
}

// A Message reply carrying none of the task-identifier markers at all. The
// accepted-side looksLikeTask gate used to read this shape as "not a task" and
// funnel it through the refusal observations, which errIfAuthRefused turned
// into a clean result - while the rule's own contract (and the test above)
// says a reply with no task reports not tested. The gate could also suppress
// real findings from task bodies whose state spelled none of its needles.
func TestSessionSmuggle_MessageReplyWithNoTaskMarkersIsNotTested(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		body := readBody(r)
		id := body["id"]
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": id,
			"result": map[string]interface{}{
				"messageId": "srv-1", "role": "ROLE_AGENT",
				"parts": []interface{}{map[string]string{"text": "done"}},
			},
		})
	}))
	defer ts.Close()

	findings, err := a2a.NewSessionSmuggleExecutor(testRuleCtx()).Execute(context.Background(), ts.URL, testOpts())
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d: %+v", len(findings), findings)
	}
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected ErrInconclusive, got %v", err)
	}
	if !strings.Contains(err.Error(), "no task id") {
		t.Errorf("reason should name the missing task; got: %v", err)
	}
}

// History readable and the marker absent: the server persisted nothing, which is a
// real result and a clean one. The old switch had no branch for it, so it fell
// through to the indicator and reported a high-severity finding about a server that
// stores no history at all. Found by the fixture sweep, on two fixtures written for
// entirely different rules.
func TestSessionSmuggle_ReadableHistoryWithoutTheMarkerIsClean(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		body := readBody(r)
		id := body["id"]
		w.Header().Set("Content-Type", "application/json")
		// A minimal task, echoed back by tasks/get, carrying no history whatsoever.
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": id,
			"result": map[string]interface{}{"id": "task-1", "contextId": "ctx-1", "status": "working"},
		})
	}))
	defer ts.Close()

	findings, err := a2a.NewSessionSmuggleExecutor(testRuleCtx()).Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("the history was readable, so this is a tested result: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("nothing was persisted, so there is nothing to report; got %d: %+v", len(findings), findings)
	}
}
