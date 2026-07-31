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

// jsonRPCRejectTokenServer advertises OAuth metadata and returns HTTP 200 with a
// JSON-RPC error envelope for forged tokens - a protocol-layer rejection. The
// rule MUST treat this as a rejection and stay silent (the false-positive guard
// for servers that reject at the JSON-RPC layer rather than via HTTP status).
func jsonRPCRejectTokenServer(t *testing.T) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + srv.Listener.Addr().String()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			json.NewEncoder(w).Encode(map[string]interface{}{"issuer": base, "token_endpoint": base + "/token"})
		case "/mcp":
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": 1,
				"error": map[string]interface{}{"code": -32001, "message": "invalid_token: audience mismatch"},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	return srv
}

func TestTokenReplay_JSONRPCErrorIsRejection(t *testing.T) {
	ts := jsonRPCRejectTokenServer(t)
	defer ts.Close()

	exec := mcpattack.NewTokenReplayExecutor(tokenReplayRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings when server rejects via JSON-RPC error envelope, got %d: %+v", len(findings), findings)
	}
}

// tokenServerWithDiscovery models a vulnerable MCP resource server that exposes
// its OAuth discovery document at a single well-known path (other than the
// RFC 8414 authorization-server path) and accepts any bearer token on /mcp.
// Before the multi-path discovery fix the rule skipped these servers entirely.
func tokenServerWithDiscovery(t *testing.T, discoveryPath string) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + srv.Listener.Addr().String()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case discoveryPath:
			json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer":         base,
				"token_endpoint": base + "/token",
			})
		case "/mcp":
			if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0", "id": 1,
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

// TestTokenReplay_AlternateDiscoveryPaths is the regression guard for the
// OIDC-only / PRM-only false negative: a vulnerable server that publishes its
// discovery document at openid-configuration or oauth-protected-resource (but
// not the RFC 8414 authorization-server path) must still be probed and flagged.
func TestTokenReplay_AlternateDiscoveryPaths(t *testing.T) {
	for _, path := range []string{
		"/.well-known/openid-configuration",
		"/.well-known/oauth-protected-resource",
	} {
		t.Run(path, func(t *testing.T) {
			ts := tokenServerWithDiscovery(t, path)
			defer ts.Close()

			exec := mcpattack.NewTokenReplayExecutor(tokenReplayRC())
			findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(findings) == 0 {
				t.Fatalf("expected findings when discovery is at %s, got none", path)
			}
		})
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

// versionRejectingTokenServer advertises OAuth metadata and rejects an
// initialize offered with the stale 2024-11-05 protocol version (returning the
// JSON-RPC error a strict current server sends for an unsupported version),
// while accepting the current version. Proves the mcpInitBody version bump
// closes a false negative: before the bump, every forged-token initialize was
// rejected on version grounds and the rule reported clean.
func versionRejectingTokenServer(t *testing.T) *httptest.Server {
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
			var req map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&req)
			params, _ := req["params"].(map[string]interface{})
			version, _ := params["protocolVersion"].(string)
			if version == "2024-11-05" {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      req["id"],
					"error":   map[string]interface{}{"code": -32600, "message": "Unsupported protocol version"},
				})
				return
			}
			if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      req["id"],
					"result": map[string]interface{}{
						"protocolVersion": version,
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

// TestTokenReplay_CurrentVersionNotRejected: a strict current server rejects an
// initialize offered as 2024-11-05. The rule must offer a current version so the
// forged-token initialize is accepted (and the finding fires), not rejected on
// version grounds.
func TestTokenReplay_CurrentVersionNotRejected(t *testing.T) {
	srv := versionRejectingTokenServer(t)
	defer srv.Close()

	findings, err := mcpattack.NewTokenReplayExecutor(tokenReplayRC()).Execute(context.Background(), srv.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected a finding (current-version initialize accepted, forged token accepted); got 0 - the offered protocolVersion may have been rejected as stale")
	}
}
