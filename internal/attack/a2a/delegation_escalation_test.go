package a2a_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	a2aattack "github.com/calbebop/batesian/internal/attack/a2a"
)

func delegationEscalationRC() attack.RuleContext {
	return attack.RuleContext{
		ID:          "a2a-delegation-escalation-001",
		Name:        "A2A Privilege Escalation via Delegation Metadata Injection",
		Severity:    "high",
		Remediation: "Ignore privilege-related metadata in SendMessage configuration from untrusted callers.",
	}
}

// authRequiredServer returns 401 for all requests.
func authRequiredServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
}

// delegationVulnerableServer returns a different task status when the configuration
// block contains role=orchestrator, simulating a server that processes injected
// delegation metadata and changes task behavior accordingly.
func delegationVulnerableServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)

		params, _ := req["params"].(map[string]interface{})
		cfg, _ := params["configuration"].(map[string]interface{})
		role, _ := cfg["role"].(string)

		// Simulate escalation: when caller asserts orchestrator role, the server
		// returns a different task state (running instead of completed).
		state := "completed"
		if role == "orchestrator" {
			state = "running"
		}

		writeJSON(w, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      req["id"],
			"result": map[string]interface{}{
				"id":     "task-1",
				"status": map[string]interface{}{"state": state},
			},
		})
	}))
}

// delegationEchoServer echoes the injected role back into the response body
// when the configuration contains role=orchestrator, simulating metadata reflection.
func delegationEchoServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)

		params, _ := req["params"].(map[string]interface{})
		cfg, _ := params["configuration"].(map[string]interface{})
		role, _ := cfg["role"].(string)

		result := map[string]interface{}{
			"id":     "task-1",
			"status": map[string]interface{}{"state": "completed"},
		}
		// Echo the injected role back; same status so statusDiffers stays false.
		if role == "orchestrator" {
			result["delegatedRole"] = "orchestrator"
		}

		writeJSON(w, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      req["id"],
			"result":  result,
		})
	}))
}

// delegationSafeServer returns an identical response regardless of what
// configuration metadata is supplied, ignoring injected delegation fields.
func delegationSafeServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)

		writeJSON(w, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      req["id"],
			"result": map[string]interface{}{
				"id":     "task-1",
				"status": map[string]interface{}{"state": "completed"},
			},
		})
	}))
}

// TestDelegationEscalation_AuthRequired verifies the executor skips when the
// baseline request is rejected with 401.
func TestDelegationEscalation_AuthRequired(t *testing.T) {
	ts := authRequiredServer(t)
	defer ts.Close()

	exec := a2aattack.NewDelegationEscalationExecutor(delegationEscalationRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings when auth is required, got %d: %v", len(findings), findings)
	}
}

// TestDelegationEscalation_VulnerableServer verifies a high-severity finding is
// emitted when the server produces a different task status for the escalated probe.
func TestDelegationEscalation_VulnerableServer(t *testing.T) {
	ts := delegationVulnerableServer(t)
	defer ts.Close()

	exec := a2aattack.NewDelegationEscalationExecutor(delegationEscalationRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings on delegation-vulnerable server, got none")
	}
	if findings[0].Severity != "high" {
		t.Errorf("expected high severity, got %q", findings[0].Severity)
	}
	if findings[0].Confidence != attack.ConfirmedExploit {
		t.Errorf("expected ConfirmedExploit confidence, got %q", findings[0].Confidence)
	}
}

// TestDelegationEscalation_EchoKeyword verifies a medium-severity finding is
// emitted when the server echoes injected delegation keywords in the response.
func TestDelegationEscalation_EchoKeyword(t *testing.T) {
	ts := delegationEchoServer(t)
	defer ts.Close()

	exec := a2aattack.NewDelegationEscalationExecutor(delegationEscalationRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings on echo server, got none")
	}
	if findings[0].Severity != "medium" {
		t.Errorf("expected medium severity, got %q", findings[0].Severity)
	}
	if findings[0].Confidence != attack.RiskIndicator {
		t.Errorf("expected RiskIndicator confidence, got %q", findings[0].Confidence)
	}
}

// TestDelegationEscalation_SafeServer verifies no finding is emitted when the
// server returns an identical response for all probes.
func TestDelegationEscalation_SafeServer(t *testing.T) {
	ts := delegationSafeServer(t)
	defer ts.Close()

	exec := a2aattack.NewDelegationEscalationExecutor(delegationEscalationRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings on safe server, got %d: %v", len(findings), findings)
	}
}

// TestDelegationEscalation_NotA2AServer verifies no finding is emitted against
// a server that returns 404 for all requests.
func TestDelegationEscalation_NotA2AServer(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	defer ts.Close()

	exec := a2aattack.NewDelegationEscalationExecutor(delegationEscalationRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings on non-A2A server, got %d", len(findings))
	}
}
