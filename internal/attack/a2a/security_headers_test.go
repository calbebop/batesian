package a2a_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	a2aattack "github.com/calbebop/batesian/internal/attack/a2a"
)

func agentCardHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"name":"Test Agent","version":"1.0"}`))
}

func TestSecurityHeaders_MissingAll(t *testing.T) {
	// Server returns no security headers at all.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agentCardHandler(w, r)
	}))
	defer srv.Close()

	exec := a2aattack.NewSecurityHeadersExecutor(attack.RuleContext{ID: "a2a-security-headers-001", Remediation: "add headers"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings when all security headers are absent")
	}
	for _, f := range findings {
		if f.Confidence != attack.RiskIndicator {
			t.Errorf("expected RiskIndicator, got %v for %q", f.Confidence, f.Title)
		}
	}
}

func TestSecurityHeaders_AllPresent(t *testing.T) {
	// Server returns all required security headers.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		agentCardHandler(w, r)
	}))
	defer srv.Close()

	exec := a2aattack.NewSecurityHeadersExecutor(attack.RuleContext{ID: "a2a-security-headers-001", Remediation: "add headers"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// All required headers are present; executor must return zero findings.
	if len(findings) != 0 {
		for _, f := range findings {
			t.Errorf("unexpected finding when all required headers are present: %q (severity: %s)", f.Title, f.Severity)
		}
	}
}

func TestSecurityHeaders_PartialHeaders(t *testing.T) {
	// Server returns HSTS but not XCTO or frame protection.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		agentCardHandler(w, r)
	}))
	defer srv.Close()

	exec := a2aattack.NewSecurityHeadersExecutor(attack.RuleContext{ID: "a2a-security-headers-001", Remediation: "add headers"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// At least XCTO and frame protection should be flagged.
	if len(findings) < 2 {
		t.Errorf("expected at least 2 findings for partial headers, got %d", len(findings))
	}

	// HSTS should NOT be flagged.
	for _, f := range findings {
		if f.Title == "A2A endpoint missing Strict-Transport-Security header" {
			t.Error("HSTS should not be flagged when header is present")
		}
	}
}
