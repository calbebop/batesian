package a2a_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	a2aattack "github.com/calbebop/batesian/internal/attack/a2a"
)

func TestWellKnownHostInject_XForwardedHostReflected(t *testing.T) {
	// Server reflects X-Forwarded-Host into the agent card url field.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Header.Get("X-Forwarded-Host")
		if host == "" {
			host = r.Host
		}
		card := map[string]interface{}{
			"name":    "Test Agent",
			"version": "1.0",
			"url":     "http://" + host + "/",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(card)
	}))
	defer srv.Close()

	exec := a2aattack.NewWellKnownHostInjectExecutor(attack.RuleContext{ID: "a2a-wellknown-hostinject-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for server that reflects X-Forwarded-Host")
	}
	for _, f := range findings {
		if f.Severity != "high" {
			t.Errorf("expected high severity, got %s", f.Severity)
		}
		if f.Confidence != attack.ConfirmedExploit {
			t.Errorf("expected ConfirmedExploit, got %v", f.Confidence)
		}
	}
}

func TestWellKnownHostInject_HardcodedURL(t *testing.T) {
	// Server always returns the same hardcoded URL - not vulnerable.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		card := map[string]interface{}{
			"name":    "Secure Agent",
			"version": "1.0",
			"url":     "https://agent.example.com/",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(card)
	}))
	defer srv.Close()

	exec := a2aattack.NewWellKnownHostInjectExecutor(attack.RuleContext{ID: "a2a-wellknown-hostinject-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for hardcoded URL, got %d", len(findings))
	}
}

// TestWellKnownHostInject_HostHeaderReflected verifies the forged Host header
// actually reaches the server (req.Host plumbing) and a reflection into the url
// field is reported as a high/ConfirmedExploit.
func TestWellKnownHostInject_HostHeaderReflected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only trusts the real Host header (not X-Forwarded-*).
		card := map[string]interface{}{
			"name":    "Host-Reflect Agent",
			"version": "1.0",
			"url":     "http://" + r.Host + "/",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(card)
	}))
	defer srv.Close()

	exec := a2aattack.NewWellKnownHostInjectExecutor(attack.RuleContext{ID: "a2a-wellknown-hostinject-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected a finding when the forged Host header is reflected into url")
	}
	if findings[0].Severity != "high" || findings[0].Confidence != attack.ConfirmedExploit {
		t.Errorf("expected high/ConfirmedExploit, got %q/%q", findings[0].Severity, findings[0].Confidence)
	}
}

// TestWellKnownHostInject_NonURLFieldReflected verifies that reflection into a
// non-URL field (description) is downgraded to medium/RiskIndicator.
func TestWellKnownHostInject_NonURLFieldReflected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Header.Get("X-Forwarded-Host")
		if host == "" {
			host = "static-host"
		}
		card := map[string]interface{}{
			"name":        "Desc-Reflect Agent",
			"version":     "1.0",
			"url":         "https://agent.example.com/", // hardcoded, safe
			"description": "Operated from origin " + host,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(card)
	}))
	defer srv.Close()

	exec := a2aattack.NewWellKnownHostInjectExecutor(attack.RuleContext{ID: "a2a-wellknown-hostinject-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected a finding for non-URL reflection")
	}
	for _, f := range findings {
		if f.Severity != "medium" || f.Confidence != attack.RiskIndicator {
			t.Errorf("expected medium/RiskIndicator for non-URL reflection, got %q/%q (%s)",
				f.Severity, f.Confidence, f.Title)
		}
	}
}

func TestWellKnownHostInject_ReflectsInProviderField(t *testing.T) {
	// Server reflects X-Original-Host into both url and provider.url.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Header.Get("X-Original-Host")
		if host == "" {
			host = "static.example.com"
		}
		card := map[string]interface{}{
			"name":    "Multi-Reflect Agent",
			"version": "1.0",
			"url":     fmt.Sprintf("http://%s/api", host),
			"provider": map[string]interface{}{
				"organization": "Acme",
				"url":          fmt.Sprintf("https://%s/company", host),
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(card)
	}))
	defer srv.Close()

	exec := a2aattack.NewWellKnownHostInjectExecutor(attack.RuleContext{ID: "a2a-wellknown-hostinject-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings for server that reflects X-Original-Host")
	}
}
