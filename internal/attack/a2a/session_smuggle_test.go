package a2a_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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

func TestSessionSmuggle_PollsDelayedHistory(t *testing.T) {
	var reads atomic.Int32
	var stored map[string]interface{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := readBody(r)
		method, _ := body["method"].(string)
		id := body["id"]
		switch method {
		case "SendMessage", "message/send":
			params, _ := body["params"].(map[string]interface{})
			stored, _ = params["message"].(map[string]interface{})
			taskResult(w, id, "task-delayed", "ctx-delayed")
		case "GetTask", "tasks/get":
			params, _ := body["params"].(map[string]interface{})
			taskID, _ := params["id"].(string)
			history := []interface{}{}
			if taskID == "task-delayed" && reads.Add(1) > 1 {
				history = []interface{}{stored}
			}
			writeJSON(w, map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{
					"id": taskID, "status": map[string]string{"state": "working"}, "history": history,
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
		t.Fatalf("expected one finding after history polling, got %d: %+v", len(findings), findings)
	}
	if got := reads.Load(); got != 2 {
		t.Fatalf("expected two task reads, got %d", got)
	}
}

func TestSessionSmuggle_StopsWhenHistoryBecomesUnreadable(t *testing.T) {
	var reads atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := readBody(r)
		method, _ := body["method"].(string)
		id := body["id"]
		switch method {
		case "SendMessage", "message/send":
			taskResult(w, id, "task-unreadable", "ctx-unreadable")
		case "GetTask", "tasks/get":
			params, _ := body["params"].(map[string]interface{})
			if params["id"] != "task-unreadable" {
				rpcErr(w, id, -32001, "Task not found")
				return
			}
			if reads.Add(1) == 1 {
				writeJSON(w, map[string]interface{}{
					"jsonrpc": "2.0", "id": id,
					"result": map[string]interface{}{"id": "task-unreadable", "history": []interface{}{}},
				})
				return
			}
			rpcErr(w, id, -32001, "Task not found")
		default:
			rpcErr(w, id, -32601, "Method not found")
		}
	}))
	defer ts.Close()

	findings, err := a2a.NewSessionSmuggleExecutor(testRuleCtx()).Execute(context.Background(), ts.URL, testOpts())
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d: %+v", len(findings), findings)
	}
	if !errors.Is(err, attack.ErrInconclusive) || !strings.Contains(err.Error(), "could not be read back") {
		t.Fatalf("expected an unreadable-history result, got %v", err)
	}
	if got := reads.Load(); got != 3 {
		t.Fatalf("expected polling to stop after the failed read, got %d requests", got)
	}
}

func TestSessionSmuggle_BoundsBlockedHistoryRead(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := readBody(r)
		method, _ := body["method"].(string)
		id := body["id"]
		switch method {
		case "SendMessage", "message/send":
			taskResult(w, id, "task-blocked", "ctx-blocked")
		case "GetTask", "tasks/get":
			params, _ := body["params"].(map[string]interface{})
			if params["id"] != "task-blocked" {
				rpcErr(w, id, -32001, "Task not found")
				return
			}
			<-r.Context().Done()
		default:
			rpcErr(w, id, -32601, "Method not found")
		}
	}))
	defer ts.Close()

	started := time.Now()
	findings, err := a2a.NewSessionSmuggleExecutor(testRuleCtx()).Execute(context.Background(), ts.URL, testOpts())
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d: %+v", len(findings), findings)
	}
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected ErrInconclusive, got %v", err)
	}
	if elapsed := time.Since(started); elapsed >= 4*time.Second {
		t.Fatalf("history polling exceeded its budget: %s", elapsed)
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

func TestSessionSmuggle_EmptyHistoryIsNotTested(t *testing.T) {
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
				"id": "task-1", "contextId": "ctx-1", "status": "working",
				"history": []interface{}{},
			},
		})
	}))
	defer ts.Close()

	findings, err := a2a.NewSessionSmuggleExecutor(testRuleCtx()).Execute(context.Background(), ts.URL, testOpts())
	if len(findings) != 0 {
		t.Fatalf("empty history must not produce a finding, got %d: %+v", len(findings), findings)
	}
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected ErrInconclusive, got %v", err)
	}
	if !strings.Contains(err.Error(), "did not include the injected marker") {
		t.Fatalf("reason should name the absent marker; got: %v", err)
	}
}

func TestSessionSmuggle_UnusableHistoryIsNotTested(t *testing.T) {
	tests := []struct {
		name    string
		include bool
		history interface{}
		retry   bool
	}{
		{name: "missing", retry: true},
		{name: "null", include: true, history: nil, retry: true},
		{name: "wrong type", include: true, history: map[string]interface{}{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var reads atomic.Int32
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body := readBody(r)
				id := body["id"]
				method, _ := body["method"].(string)
				switch method {
				case "SendMessage", "message/send":
					taskResult(w, id, "task-no-history", "ctx-no-history")
				case "GetTask", "tasks/get":
					params, _ := body["params"].(map[string]interface{})
					if params["id"] == "task-no-history" {
						reads.Add(1)
					}
					result := map[string]interface{}{
						"id": "task-no-history", "contextId": "ctx-no-history", "status": "working",
					}
					if tt.include {
						result["history"] = tt.history
					}
					writeJSON(w, map[string]interface{}{"jsonrpc": "2.0", "id": id, "result": result})
				default:
					rpcErr(w, id, -32601, "Method not found")
				}
			}))
			defer ts.Close()

			findings, err := a2a.NewSessionSmuggleExecutor(testRuleCtx()).Execute(context.Background(), ts.URL, testOpts())
			if len(findings) != 0 {
				t.Fatalf("unusable history must not produce a finding, got %d: %+v", len(findings), findings)
			}
			if !errors.Is(err, attack.ErrInconclusive) {
				t.Fatalf("expected ErrInconclusive, got %v", err)
			}
			if got := reads.Load(); (tt.retry && got < 2) || (!tt.retry && got != 1) {
				t.Fatalf("unexpected task read count: %d", got)
			}
			wantReason := "no usable history"
			if tt.name == "wrong type" {
				wantReason = "malformed history"
			}
			if !strings.Contains(err.Error(), wantReason) {
				t.Fatalf("reason should name %s; got: %v", wantReason, err)
			}
		})
	}
}

func TestSessionSmuggle_MarkerWithUnknownRoleIsNotTested(t *testing.T) {
	tests := []struct {
		name        string
		includeRole bool
		role        interface{}
	}{
		{name: "missing role"},
		{name: "unknown role", includeRole: true, role: "moderator"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var marker string
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body := readBody(r)
				id := body["id"]
				method, _ := body["method"].(string)
				switch method {
				case "SendMessage", "message/send":
					marker = textOf(body)
					taskResult(w, id, "task-unknown-role", "ctx-unknown-role")
				case "GetTask", "tasks/get":
					message := map[string]interface{}{
						"parts": []interface{}{map[string]string{"text": marker}},
					}
					if tt.includeRole {
						message["role"] = tt.role
					}
					writeJSON(w, map[string]interface{}{
						"jsonrpc": "2.0", "id": id,
						"result": map[string]interface{}{
							"id": "task-unknown-role", "history": []interface{}{message},
						},
					})
				default:
					rpcErr(w, id, -32601, "Method not found")
				}
			}))
			defer ts.Close()

			findings, err := a2a.NewSessionSmuggleExecutor(testRuleCtx()).Execute(context.Background(), ts.URL, testOpts())
			if len(findings) != 0 {
				t.Fatalf("unknown role must not produce a finding, got %d: %+v", len(findings), findings)
			}
			if !errors.Is(err, attack.ErrInconclusive) {
				t.Fatalf("expected ErrInconclusive, got %v", err)
			}
			if !strings.Contains(err.Error(), "unrecognized role") {
				t.Fatalf("reason should name the unrecognized role; got: %v", err)
			}
		})
	}
}
