package mcp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

func mcpInitResponse(w http.ResponseWriter, req map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"jsonrpc": "2.0", "id": req["id"],
		"result": map[string]interface{}{
			"protocolVersion": "2025-03-26",
			"serverInfo":      map[string]interface{}{"name": "test"},
			"capabilities":    map[string]interface{}{},
		},
	})
}

func TestMCPSecurityHeaders_MissingAll(t *testing.T) {
	rc := attack.RuleContext{ID: "mcp-security-headers-001", Remediation: "add headers"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		json.NewDecoder(r.Body).Decode(&req)
		// No security headers.
		mcpInitResponse(w, req)
	}))
	defer srv.Close()

	exec := mcpattack.NewMCPSecurityHeadersExecutor(rc)
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings when all security headers are absent")
	}
	for _, f := range findings {
		if f.RuleID != rc.ID {
			t.Errorf("finding has wrong RuleID: got %q, want %q", f.RuleID, rc.ID)
		}
		if f.Confidence != attack.RiskIndicator {
			t.Errorf("expected RiskIndicator confidence, got %v for %q", f.Confidence, f.Title)
		}
		if f.Title == "" {
			t.Error("finding has empty Title")
		}
	}
}

func TestMCPSecurityHeaders_AllPresent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		var req map[string]interface{}
		json.NewDecoder(r.Body).Decode(&req)
		mcpInitResponse(w, req)
	}))
	defer srv.Close()

	exec := mcpattack.NewMCPSecurityHeadersExecutor(attack.RuleContext{ID: "mcp-security-headers-001", Remediation: "add headers"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings when all security headers present, got %d: %v", len(findings), findings)
	}
}
