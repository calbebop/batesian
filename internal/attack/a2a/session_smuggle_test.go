package a2a_test

import (
	"context"
	"net/http"
	"net/http/httptest"
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

// TestSessionSmuggle_AcceptedUnverifiable: the server accepts the agent-role
// message but exposes no retrievable history (GetTask errors). The rule MUST
// report a RiskIndicator (accepted without rejection, exploitability unconfirmed).
func TestSessionSmuggle_AcceptedUnverifiable(t *testing.T) {
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one indicator finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Confidence != attack.RiskIndicator {
		t.Errorf("want RiskIndicator, got %q", findings[0].Confidence)
	}
}
