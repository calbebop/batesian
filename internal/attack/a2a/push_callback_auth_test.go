package a2a_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/calbebop/batesian/internal/attack"
	a2a "github.com/calbebop/batesian/internal/attack/a2a"
)

func cbAuthRC() attack.RuleContext {
	return attack.RuleContext{
		ID:          "a2a-push-callback-auth-001",
		Name:        "A2A Push Callback Authentication",
		Severity:    "high",
		Remediation: "Present the configured token on every push callback.",
	}
}

// cbAuthServer models a v1.0 agent that registers the caller's push config
// verbatim and then calls the webhook once. signed decides whether the
// outbound call carries X-A2A-Notification-Token; callOut decides whether it
// calls at all.
type cbAuthServer struct {
	signed  bool
	callOut bool
}

func (s *cbAuthServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
			ID     string `json:"id"`
			Params struct {
				TaskID string `json:"taskId"`
				URL    string `json:"url"`
				Token  string `json:"token"`
			} `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)

		switch req.Method {
		case "SendMessage":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID,
				"result": map[string]interface{}{
					"id":        "task-cbauth-1",
					"contextId": "ctx-cbauth",
					"status":    map[string]interface{}{"state": "TASK_STATE_WORKING"},
				},
			})
		case "CreateTaskPushNotificationConfig":
			url, token := req.Params.URL, req.Params.Token
			if s.callOut {
				go func() {
					time.Sleep(150 * time.Millisecond)
					body := map[string]interface{}{
						"kind": "status-update", "taskId": req.Params.TaskID,
						"status": map[string]string{"state": "TASK_STATE_COMPLETED"},
					}
					b, _ := json.Marshal(body)
					req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(string(b)))
					if err != nil {
						return
					}
					req.Header.Set("Content-Type", "application/json")
					if s.signed {
						req.Header.Set("X-A2A-Notification-Token", token)
					}
					client := &http.Client{Timeout: 5 * time.Second}
					resp, err := client.Do(req)
					if err == nil {
						_ = resp.Body.Close()
					}
				}()
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID,
				"result": map[string]interface{}{
					"taskId": req.Params.TaskID, "url": url, "token": token,
				},
			})
		default:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID,
				"error": map[string]interface{}{"code": -32601, "message": "Method not found"},
			})
		}
	}
}

func runCbAuth(t *testing.T, target string, oobURL string) ([]attack.Finding, error) {
	t.Helper()
	opts := attack.Options{TimeoutSeconds: 10}
	if oobURL != "" {
		opts.OOBListenerURL = oobURL
	}
	return a2a.NewPushCallbackAuthExecutor(cbAuthRC()).Execute(context.Background(), target, opts)
}

// TestCbAuth_UnsignedCallbackFires: the agent accepted the token at
// registration and dropped it on the way out. Receivers get nothing to
// verify; MUST fire confirmed/high.
func TestCbAuth_UnsignedCallbackFires(t *testing.T) {
	target := httptest.NewServer((&cbAuthServer{signed: false, callOut: true}).handler())
	defer target.Close()

	findings, err := runCbAuth(t, target.URL, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != "high" || f.Confidence != attack.ConfirmedExploit {
		t.Errorf("want high/ConfirmedExploit, got %q/%q", f.Severity, f.Confidence)
	}
	if !strings.Contains(f.Evidence, "token echoed: no") {
		t.Errorf("evidence should record the missing echo, got: %q", f.Evidence)
	}
}

// TestCbAuth_SignedCallbackSilent: the callback presents the configured token,
// so receivers can authenticate it. The boundary held; MUST stay silent.
func TestCbAuth_SignedCallbackSilent(t *testing.T) {
	target := httptest.NewServer((&cbAuthServer{signed: true, callOut: true}).handler())
	defer target.Close()

	findings, err := runCbAuth(t, target.URL, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings when the token is echoed, got %d: %+v", len(findings), findings)
	}
}

// TestCbAuth_NoCallbackNotTested: registration accepted, webhook never hit.
// The oracle never ran, so the rule reports not tested rather than clean.
func TestCbAuth_NoCallbackNotTested(t *testing.T) {
	target := httptest.NewServer((&cbAuthServer{callOut: false}).handler())
	defer target.Close()

	findings, err := runCbAuth(t, target.URL, "")
	if err == nil {
		t.Fatalf("expected an inconclusive error when no callback arrived")
	}
	if !strings.Contains(err.Error(), "provenance") {
		t.Errorf("expected the reason to name provenance, got: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings alongside the inconclusive result, got %d", len(findings))
	}
}

// TestCbAuth_ExternalOOBInfoIndicator: with an external collector the scanner
// cannot see the callback itself; an info indicator names the token to check
// for instead.
func TestCbAuth_ExternalOOBInfoIndicator(t *testing.T) {
	target := httptest.NewServer((&cbAuthServer{signed: false, callOut: true}).handler())
	defer target.Close()

	findings, err := runCbAuth(t, target.URL, "http://127.0.0.1:9/oob")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Severity != "info" || findings[0].Confidence != attack.RiskIndicator {
		t.Errorf("want info/RiskIndicator for external OOB, got %q/%q",
			findings[0].Severity, findings[0].Confidence)
	}
}

// TestCbAuth_AnonymousRefusedNotTested: a secured agent refuses the task
// creation from an anonymous scan. Not tested, naming the refusal - never a
// clean claim about callbacks nobody agreed to send.
func TestCbAuth_AnonymousRefusedNotTested(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string      `json:"method"`
			ID     json.Number `json:"id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Method == "SendMessage" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID,
				"error": map[string]interface{}{"code": -32000, "message": "unauthorized"},
			})
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer ts.Close()

	findings, err := a2a.NewPushCallbackAuthExecutor(cbAuthRC()).
		Execute(context.Background(), ts.URL, attack.Options{TimeoutSeconds: 5})
	if err == nil {
		t.Fatalf("expected an inconclusive error against a secured anonymous scan")
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings alongside the inconclusive result, got %d", len(findings))
	}
}
