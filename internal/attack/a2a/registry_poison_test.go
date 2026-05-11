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

func TestRegistryPoison_AcceptsUnauthenticated(t *testing.T) {
	// Server exposes an open registry that accepts unauthenticated POSTs.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/registry", "/agents":
			if r.Method == http.MethodGet {
				json.NewEncoder(w).Encode([]interface{}{
					map[string]interface{}{"name": "existing-agent", "url": "https://agent.example.com"},
				})
				return
			}
			if r.Method == http.MethodPost {
				// Accept without requiring authentication.
				w.WriteHeader(http.StatusCreated)
				json.NewEncoder(w).Encode(map[string]interface{}{"id": "new-agent-123", "status": "registered"})
				return
			}
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	exec := a2aattack.NewRegistryPoisonExecutor(attack.RuleContext{ID: "a2a-registry-poison-001", Remediation: "require auth"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding when registry accepts unauthenticated registration")
	}
	if findings[0].Confidence != attack.ConfirmedExploit {
		t.Errorf("expected ConfirmedExploit, got %v", findings[0].Confidence)
	}
	if findings[0].Severity != "high" {
		t.Errorf("expected high severity, got %s", findings[0].Severity)
	}
}

func TestRegistryPoison_RequiresAuth(t *testing.T) {
	// Server requires authentication for registration (returns 401).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/registry":
			if r.Method == http.MethodGet {
				json.NewEncoder(w).Encode([]interface{}{})
				return
			}
			if r.Method == http.MethodPost {
				w.Header().Set("WWW-Authenticate", `Bearer realm="registry"`)
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]interface{}{"error": "unauthorized"})
				return
			}
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	exec := a2aattack.NewRegistryPoisonExecutor(attack.RuleContext{ID: "a2a-registry-poison-001", Remediation: "require auth"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when registry requires authentication, got %d", len(findings))
	}
}

func TestRegistryPoison_NoRegistry(t *testing.T) {
	// Server has no registry endpoint at all.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	exec := a2aattack.NewRegistryPoisonExecutor(attack.RuleContext{ID: "a2a-registry-poison-001", Remediation: "require auth"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when no registry endpoint exists, got %d", len(findings))
	}
}
