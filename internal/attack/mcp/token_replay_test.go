package mcp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

func tokenReplayRC() attack.RuleContext {
	return attack.RuleContext{
		ID:          "mcp-token-replay-001",
		Name:        "MCP OAuth Token Audience Validation Bypass",
		Severity:    "high",
		Remediation: "Validate the aud claim and reject alg:none tokens.",
	}
}

// vulnerableTokenServer advertises OAuth metadata and then accepts any bearer
// token on the /mcp endpoint without validating the aud claim or alg field.
func vulnerableTokenServer(t *testing.T) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + srv.Listener.Addr().String()
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer":         base,
				"token_endpoint": base + "/token",
			})
		case "/mcp":
			// Vulnerable: accept any Bearer token without validation.
			if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      1,
					"result": map[string]interface{}{
						"protocolVersion": "2024-11-05",
						"serverInfo":      map[string]interface{}{"name": "test-server", "version": "1.0"},
					},
				})
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		default:
			http.NotFound(w, r)
		}
	}))
	return srv
}

// secureTokenServer advertises OAuth metadata but always rejects tokens on /mcp.
func secureTokenServer(t *testing.T) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + srv.Listener.Addr().String()
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer":         base,
				"token_endpoint": base + "/token",
			})
		case "/mcp":
			// Secure: reject all tokens with 401.
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "invalid_token",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	return srv
}

func TestTokenReplay_VulnerableServer(t *testing.T) {
	ts := vulnerableTokenServer(t)
	defer ts.Close()

	exec := mcpattack.NewTokenReplayExecutor(tokenReplayRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings on vulnerable token server, got none")
	}

	// All findings must use ConfirmedExploit confidence.
	for _, f := range findings {
		if f.Confidence != attack.ConfirmedExploit {
			t.Errorf("finding %q should have ConfirmedExploit confidence, got %q", f.Title, f.Confidence)
		}
	}
}

func TestTokenReplay_AlgNoneIsCritical(t *testing.T) {
	ts := vulnerableTokenServer(t)
	defer ts.Close()

	exec := mcpattack.NewTokenReplayExecutor(tokenReplayRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	hasCritical := false
	for _, f := range findings {
		if f.Severity == "critical" {
			hasCritical = true
		}
	}
	if !hasCritical {
		t.Errorf("expected a critical finding for alg:none acceptance, findings: %v", findings)
	}
}

func TestTokenReplay_SecureServer(t *testing.T) {
	ts := secureTokenServer(t)
	defer ts.Close()

	exec := mcpattack.NewTokenReplayExecutor(tokenReplayRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings on secure server, got %d: %v", len(findings), findings)
	}
}

func TestTokenReplay_NoOAuthMetadata(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	defer ts.Close()

	exec := mcpattack.NewTokenReplayExecutor(tokenReplayRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings when no OAuth metadata present, got %d", len(findings))
	}
}
