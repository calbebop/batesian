package mcp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

func TestCORSWildcard_ReflectsOriginWithCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			origin = "*"
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","serverInfo":{"name":"test"},"capabilities":{}}}`))
	}))
	defer srv.Close()

	exec := mcpattack.NewCORSWildcardExecutor(attack.RuleContext{ID: "mcp-cors-wildcard-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for origin reflection with credentials")
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

func TestCORSWildcard_WildcardNoCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","serverInfo":{"name":"test"},"capabilities":{}}}`))
	}))
	defer srv.Close()

	exec := mcpattack.NewCORSWildcardExecutor(attack.RuleContext{ID: "mcp-cors-wildcard-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected a finding for wildcard CORS without credentials")
	}
	if findings[0].Severity != "low" {
		t.Errorf("expected low severity for wildcard-only, got %s", findings[0].Severity)
	}
}

func TestCORSWildcard_NoCORS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer srv.Close()

	exec := mcpattack.NewCORSWildcardExecutor(attack.RuleContext{ID: "mcp-cors-wildcard-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for server with no CORS headers, got %d", len(findings))
	}
}
