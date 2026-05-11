package mcp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

func TestSSEHijack_OpenStreamWithoutAuth(t *testing.T) {
	// Server accepts SSE connections without authentication.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") == "text/event-stream" {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.WriteHeader(http.StatusOK)
			// Send a data event without checking authorization
			w.Write([]byte("data: {\"jsonrpc\":\"2.0\",\"method\":\"ping\"}\n\n"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	exec := mcpattack.NewSSEHijackExecutor(attack.RuleContext{ID: "mcp-sse-hijack-001", Remediation: "require auth"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for server that accepts SSE without auth")
	}
	f := findings[0]
	if f.Confidence != attack.ConfirmedExploit {
		t.Errorf("expected ConfirmedExploit, got %v", f.Confidence)
	}
	if f.Severity != "high" {
		t.Errorf("expected high severity, got %s", f.Severity)
	}
}

func TestSSEHijack_RequiresAuth(t *testing.T) {
	// Server returns 401 for unauthenticated SSE requests.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") == "text/event-stream" {
			if r.Header.Get("Authorization") == "" {
				w.Header().Set("WWW-Authenticate", `Bearer realm="mcp"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("data: {}\n\n"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	exec := mcpattack.NewSSEHijackExecutor(attack.RuleContext{ID: "mcp-sse-hijack-001", Remediation: "require auth"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for server requiring auth on SSE, got %d", len(findings))
	}
}

func TestSSEHijack_StreamAcceptedNoData(t *testing.T) {
	// Server returns text/event-stream 200 but with no recognizable MCP data events.
	// This should produce a RiskIndicator finding (SSE accepted but no content confirmed).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") == "text/event-stream" {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			// Emit only a comment line -- no data: event.
			w.Write([]byte(": keep-alive\n\n"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	exec := mcpattack.NewSSEHijackExecutor(attack.RuleContext{ID: "mcp-sse-hijack-001", Remediation: "require auth"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected a RiskIndicator finding for SSE stream accepted without data")
	}
	if findings[0].Confidence != attack.RiskIndicator {
		t.Errorf("expected RiskIndicator, got %v", findings[0].Confidence)
	}
}

func TestSSEHijack_NoSSEEndpoint(t *testing.T) {
	// Server does not serve SSE at any path.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	exec := mcpattack.NewSSEHijackExecutor(attack.RuleContext{ID: "mcp-sse-hijack-001", Remediation: "require auth"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when no SSE endpoint exists, got %d", len(findings))
	}
}
