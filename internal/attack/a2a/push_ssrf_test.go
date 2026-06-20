package a2a_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"time"

	"testing"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/attack/a2a"
)

// pushSSRFServer builds a mock A2A server. When callBack is true, the
// CreateTaskPushNotificationConfig handler actually performs an outbound GET to
// the attacker-supplied pushNotificationUrl - simulating the SSRF. When false,
// it accepts the config but never calls back (the normal, non-vulnerable case).
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
				if url, _ := params["pushNotificationUrl"].(string); url != "" {
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
