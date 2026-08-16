package mcp_test

import (
	"context"
	"encoding/json"
	"errors"
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

// A reachable MCP server with no OAuth metadata is not applicable: clean.
func TestTokenReplay_NoOAuthMetadata(t *testing.T) {
	ts, _ := mountedMCPServer(t)
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

func TestTokenReplay_NothingReachableIsNotTested(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	defer ts.Close()

	_, err := mcpattack.NewTokenReplayExecutor(tokenReplayRC()).
		Execute(context.Background(), ts.URL, testOpts())
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected ErrInconclusive when nothing answered, got err=%v", err)
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

// ungatedInitServer models the posture that broke both forged-token rules:
// initialize answers anyone, and what happens on the calls that follow is what
// mode selects.
//
//   - validate: the follow-up gate accepts only the sentinel bearer - a server
//     that validates tokens and leaves initialize open. The rules must stay
//     silent here; before the anonymous-initialize control they fired three
//     findings claiming absent signature validation.
//   - presence: the gate accepts any bearer - presence-only validation. The
//     findings must fire, judged at the gated method.
//   - open: no gate anywhere. The unauth rules own that surface, and the token
//     rules must report not tested rather than "accepted a forged token".
//
// The initialize result advertises the tools capability so the control probes
// the real listing rather than the ping fallback. Shared with
// oauth_audience_test.go (same package).
func ungatedInitServer(t *testing.T, mode string) *httptest.Server {
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
			var req struct {
				Method string `json:"method"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)

			// initialize is ungated in every mode: it answers anyone.
			if req.Method == "initialize" {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      1,
					"result": map[string]interface{}{
						"protocolVersion": "2025-11-25",
						"serverInfo":      map[string]interface{}{"name": "ungated-init", "version": "1.0"},
						"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
					},
				})
				return
			}

			authz := r.Header.Get("Authorization")
			accepted := false
			switch mode {
			case "open":
				accepted = true
			case "presence":
				accepted = strings.HasPrefix(authz, "Bearer ")
			case "validate":
				accepted = authz == "Bearer good-token"
			}
			if accepted {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      2,
					"result":  map[string]interface{}{"tools": []interface{}{}},
				})
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]interface{}{"error": "invalid_token"})
		default:
			http.NotFound(w, r)
		}
	}))
	return srv
}

// The regression the anonymous-initialize control exists for: initialize
// answers anyone, and the token is validated at the methods that follow. The
// rule used to fire three findings (two high, one critical) claiming absent
// signature validation, against a server that rejects every forged token where
// it matters.
func TestTokenReplay_UngatedInitValidatingGateStaysSilent(t *testing.T) {
	srv := ungatedInitServer(t, "validate")
	defer srv.Close()

	findings, err := mcpattack.NewTokenReplayExecutor(tokenReplayRC()).Execute(context.Background(), srv.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings against an ungated-initialize server that validates tokens at the gate, got %d: %+v", len(findings), findings)
	}
}

// The same posture with a presence-only gate: any bearer is accepted at the
// gated method. The findings must still fire - attributed to the method that
// actually examined (and failed to validate) the token, not to initialize.
func TestTokenReplay_UngatedInitPresenceOnlyGateFiresAtMethod(t *testing.T) {
	srv := ungatedInitServer(t, "presence")
	defer srv.Close()

	findings, err := mcpattack.NewTokenReplayExecutor(tokenReplayRC()).Execute(context.Background(), srv.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected one finding per forged probe, got %d: %+v", len(findings), findings)
	}
	for _, f := range findings {
		if !strings.Contains(f.Evidence, "judged at tools/list") {
			t.Errorf("evidence must name the gated method the token was judged at: %s", f.Evidence)
		}
	}
}

// A server that answers everyone everywhere presents no credential-gated
// surface; the unauth rules report it, and this rule reports not tested rather
// than "accepted a forged token".
func TestTokenReplay_FullyOpenServerIsNotTested(t *testing.T) {
	srv := ungatedInitServer(t, "open")
	defer srv.Close()

	findings, err := mcpattack.NewTokenReplayExecutor(tokenReplayRC()).Execute(context.Background(), srv.URL, testOpts())
	if len(findings) != 0 {
		t.Fatalf("expected no findings against a fully open server, got %d: %+v", len(findings), findings)
	}
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected ErrInconclusive, got %v", err)
	}
	if !strings.Contains(err.Error(), "no credential-gated surface") {
		t.Errorf("reason should explain the open surface: %v", err)
	}
}
