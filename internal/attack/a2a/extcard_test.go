package a2a_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/attack/a2a"
)

// Shared helpers used by all test files in this package.

func testRuleCtx() attack.RuleContext {
	return attack.RuleContext{
		ID:          "a2a-test-001",
		Name:        "Test",
		Severity:    "high",
		Remediation: "Fix it",
	}
}

func testOpts() attack.Options {
	return attack.Options{TimeoutSeconds: 5}
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func jsonRPCError(code int, message string) map[string]interface{} {
	return map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "1",
		"error": map[string]interface{}{
			"code":    code,
			"message": message,
		},
	}
}

// TestExtCardExecutor_Vulnerable verifies that a server which returns HTTP 200
// for all requests (including GetExtendedAgentCard without auth and with an
// invalid Bearer token) produces at least one high or critical severity finding.
func TestExtCardExecutor_Vulnerable(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "test",
			"result": map[string]interface{}{
				"name":        "Extended Agent Card",
				"description": "Private extended capabilities",
			},
		})
	}))
	defer ts.Close()

	ex := a2a.NewExtCardExecutor(testRuleCtx())
	findings, err := ex.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding, got zero")
	}
	var hasHighOrCritical bool
	for _, f := range findings {
		if f.Severity == "high" || f.Severity == "critical" {
			hasHighOrCritical = true
			break
		}
	}
	if !hasHighOrCritical {
		t.Errorf("expected at least one high or critical finding, got: %+v", findings)
	}
	for _, f := range findings {
		if f.Confidence != attack.ConfirmedExploit {
			t.Errorf("finding %q: want ConfirmedExploit, got %q", f.Title, f.Confidence)
		}
	}
}

// TestExtCardExecutor_Clean verifies that a server enforcing authentication
// (returning 401 for all requests) produces zero findings.
func TestExtCardExecutor_Clean(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
	}))
	defer ts.Close()

	ex := a2a.NewExtCardExecutor(testRuleCtx())
	findings, err := ex.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings, got %d: %+v", len(findings), findings)
	}
}
