package a2a_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"testing"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/attack/a2a"
)

// pushSSRFServer builds a mock A2A server. When callBack is true, the
// CreateTaskPushNotificationConfig handler actually performs an outbound POST to
// the attacker-supplied callback - simulating the SSRF. When false, it accepts
// the config but never calls back (the normal, non-vulnerable case).
//
// It reads the callback from `url`, which is the field a2a-sdk v1 actually
// defines on TaskPushNotificationConfig. The harness used to read
// pushNotificationUrl, matching what the rule sent rather than what the protocol
// says, so it went on passing while the rule could not register a callback with
// any real agent. Reading only the real field is what keeps that from recurring.
func pushSSRFServer(t *testing.T, callBack bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		req := readBody(r)
		method, _ := req["method"].(string)
		id := req["id"]
		switch method {
		case "SendMessage":
			writeJSON(w, map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{"id": "task-push-001", "contextId": "ctx-push-001"},
			})
		case "CreateTaskPushNotificationConfig":
			if callBack {
				params, _ := req["params"].(map[string]interface{})
				if url, _ := params["url"].(string); url != "" {
					// Outbound request to the attacker-controlled callback = SSRF.
					token, _ := params["token"].(string)
					hc := &http.Client{Timeout: 3 * time.Second}
					if cbReq, err := http.NewRequest(http.MethodPost, url, nil); err == nil {
						cbReq.Header.Set("X-A2A-Notification-Token", token)
						if resp, err := hc.Do(cbReq); err == nil {
							_ = resp.Body.Close()
						}
					}
				}
			}
			writeJSON(w, map[string]interface{}{"jsonrpc": "2.0", "id": id, "result": map[string]interface{}{"ok": true}})
		default:
			writeJSON(w, jsonRPCError(-32601, "Method not found"))
		}
	}))
}

// TestPushSSRF_VulnerableCallbackConfirmed: the server makes a real outbound
// request to the attacker-supplied callback URL. The executor's own OOB listener
// receives it, so a confirmed high-severity SSRF finding MUST be produced.
func TestPushSSRF_VulnerableCallbackConfirmed(t *testing.T) {
	ts := pushSSRFServer(t, true)
	defer ts.Close()

	// No OOBListenerURL => the executor spins up its own local listener.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	findings, err := a2a.NewPushSSRFExecutor(testRuleCtx()).Execute(ctx, ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one confirmed SSRF finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Severity != "high" || findings[0].Confidence != attack.ConfirmedExploit {
		t.Errorf("want high/ConfirmedExploit, got %q/%q", findings[0].Severity, findings[0].Confidence)
	}
}

// v03PushServer speaks only the v0.3 methods: SendMessage is unknown, message/send
// returns a task, and tasks/pushNotificationConfig/set performs the outbound
// call. It exists because the v0.3 path used to send tasks/send, a v0.2-era
// method name that a2a-sdk answers -32601, so that whole branch was dead against
// any current server and no test noticed.
func v03PushServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		req := readBody(r)
		method, _ := req["method"].(string)
		id := req["id"]
		params, _ := req["params"].(map[string]interface{})

		switch method {
		case "message/send":
			writeJSON(w, map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{"id": "task-v03-001", "contextId": "ctx-v03-001"},
			})
		case "tasks/pushNotificationConfig/set":
			cfg, _ := params["pushNotificationConfig"].(map[string]interface{})
			if url, _ := cfg["url"].(string); url != "" {
				token, _ := cfg["token"].(string)
				hc := &http.Client{Timeout: 3 * time.Second}
				if cbReq, err := http.NewRequest(http.MethodPost, url, nil); err == nil {
					cbReq.Header.Set("X-A2A-Notification-Token", token)
					if resp, err := hc.Do(cbReq); err == nil {
						_ = resp.Body.Close()
					}
				}
			}
			writeJSON(w, map[string]interface{}{"jsonrpc": "2.0", "id": id, "result": map[string]interface{}{"ok": true}})
		default:
			// Covers SendMessage and tasks/send alike: a v0.3-only server knows
			// neither.
			writeJSON(w, jsonRPCError(-32601, "Method not found"))
		}
	}))
}

func TestPushSSRF_V03BindingConfirmed(t *testing.T) {
	ts := v03PushServer(t)
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	findings, err := a2a.NewPushSSRFExecutor(testRuleCtx()).Execute(ctx, ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one confirmed SSRF finding over the v0.3 binding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Severity != "high" || findings[0].Confidence != attack.ConfirmedExploit {
		t.Errorf("want high/ConfirmedExploit, got %q/%q", findings[0].Severity, findings[0].Confidence)
	}
}

// A server that answers message/send with a Message rather than a Task has
// nothing to attach a push config to. Treating that as an accepted registration
// would have the rule wait for a callback nobody agreed to send, and, on the
// external-OOB path, report a task acceptance that never happened.
func TestPushSSRF_MessageReplyIsNotARegistration(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		req := readBody(r)
		method, _ := req["method"].(string)
		if method == "message/send" {
			writeJSON(w, map[string]interface{}{
				"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]interface{}{
					"kind": "message", "messageId": "m-1", "role": "agent",
					"parts": []interface{}{map[string]string{"kind": "text", "text": "Echo: ping"}},
				},
			})
			return
		}
		writeJSON(w, jsonRPCError(-32601, "Method not found"))
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	findings, err := a2a.NewPushSSRFExecutor(testRuleCtx()).Execute(ctx, ts.URL, attack.Options{
		TimeoutSeconds: 5,
		OOBListenerURL: "http://oob.batesian.invalid",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no finding when the agent replies with a Message, got %d: %+v", len(findings), findings)
	}
}

// TestPushSSRF_AcceptedNoCallback: the server accepts the push config but never
// calls back (normal A2A behaviour). No SSRF is demonstrated, so the rule MUST
// stay silent rather than flag the by-design feature.
func TestPushSSRF_AcceptedNoCallback(t *testing.T) {
	ts := pushSSRFServer(t, false)
	defer ts.Close()

	// Short context so the listener wait returns quickly instead of blocking 10s.
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	findings, err := a2a.NewPushSSRFExecutor(testRuleCtx()).Execute(ctx, ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings when no callback is made, got %d: %+v", len(findings), findings)
	}
}

// TestPushSSRFExecutor_MethodNotFound verifies that a server rejecting all A2A
// methods with JSON-RPC -32601 produces zero findings.
func TestPushSSRFExecutor_MethodNotFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			writeJSON(w, jsonRPCError(-32601, "Method not found"))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	findings, err := a2a.NewPushSSRFExecutor(testRuleCtx()).Execute(ctx, ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings, got %d: %+v", len(findings), findings)
	}
}

// TestPushSSRF_DryRunBindsNoListener verifies that a dry run previews the SSRF
// probe against the non-resolving placeholder callback instead of binding a local
// OOB listener. A dry run must open no socket, so the recorded plan must carry the
// placeholder host and never a real listener address.
func TestPushSSRF_DryRunBindsNoListener(t *testing.T) {
	rec := &attack.Recorder{}
	rec.SetCurrentRule("a2a-push-ssrf-001")
	opts := attack.Options{DryRun: true, Recorder: rec}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := a2a.NewPushSSRFExecutor(testRuleCtx()).Execute(ctx, "http://target.invalid", opts); err != nil {
		t.Fatalf("dry-run Execute returned error: %v", err)
	}

	reqs := rec.Requests()
	if len(reqs) == 0 {
		t.Fatal("dry run recorded no requests")
	}
	var sawPlaceholder bool
	for _, r := range reqs {
		if strings.Contains(r.Body, "oob.batesian.invalid") {
			sawPlaceholder = true
		}
		if strings.Contains(r.Body, "127.0.0.1") || strings.Contains(r.Body, "0.0.0.0") {
			t.Errorf("dry-run request body references a real listener address: %s", r.Body)
		}
	}
	if !sawPlaceholder {
		t.Error("dry-run plan never used the placeholder OOB callback URL")
	}
}
