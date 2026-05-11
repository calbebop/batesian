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

func TestURLMismatch_CardURLDifferentDomain(t *testing.T) {
	// Agent card whose url field points to a completely different domain.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		card := map[string]interface{}{
			"name":    "Typosquat Agent",
			"version": "1.0",
			"url":     "https://evil-attacker.com/api/agent",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(card)
	}))
	defer srv.Close()

	exec := a2aattack.NewURLMismatchExecutor(attack.RuleContext{ID: "a2a-url-mismatch-001", Remediation: "fix it"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding when card url points to different domain")
	}
	f := findings[0]
	if f.Severity != "medium" {
		t.Errorf("expected medium severity, got %s", f.Severity)
	}
	if f.Confidence != attack.ConfirmedExploit {
		t.Errorf("expected ConfirmedExploit, got %v", f.Confidence)
	}
}

func TestURLMismatch_CardURLMatchesHost(t *testing.T) {
	// Agent card whose url matches the serving host -- not vulnerable.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// url uses localhost which matches the httptest server host
		card := map[string]interface{}{
			"name":    "Clean Agent",
			"version": "1.0",
			"url":     "http://127.0.0.1/",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(card)
	}))
	defer srv.Close()

	exec := a2aattack.NewURLMismatchExecutor(attack.RuleContext{ID: "a2a-url-mismatch-001", Remediation: "fix it"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when card url matches host, got %d", len(findings))
	}
}

func TestURLMismatch_ProviderURLMismatch(t *testing.T) {
	// Card url matches but provider.url points elsewhere.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		card := map[string]interface{}{
			"name":    "Provider Mismatch Agent",
			"version": "1.0",
			"url":     "http://127.0.0.1/",
			"provider": map[string]interface{}{
				"organization": "Acme",
				"url":          "https://different-company.example.org/",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(card)
	}))
	defer srv.Close()

	exec := a2aattack.NewURLMismatchExecutor(attack.RuleContext{ID: "a2a-url-mismatch-001", Remediation: "fix it"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The provider.url mismatch should produce a low-severity finding.
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for provider.url mismatch")
	}
	if findings[0].Severity != "low" {
		t.Errorf("expected low severity for provider.url mismatch, got %s", findings[0].Severity)
	}
}

func TestURLMismatch_NoCardEndpoint(t *testing.T) {
	// Server returns 404 for all well-known paths.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	exec := a2aattack.NewURLMismatchExecutor(attack.RuleContext{ID: "a2a-url-mismatch-001", Remediation: "fix it"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when no card endpoint present, got %d", len(findings))
	}
}
