package mcp_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

func oauthRC() attack.RuleContext {
	return attack.RuleContext{
		ID:          "mcp-oauth-dcr-001",
		Name:        "MCP OAuth DCR Scope Escalation",
		Severity:    "high",
		Remediation: "Restrict DCR to registered scopes only.",
	}
}

// vulnerableOAuthServer returns a server that:
// - Advertises a registration endpoint
// - Accepts any scopes without validation
// - Accepts any redirect URIs
func vulnerableOAuthServer(t *testing.T) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + srv.Listener.Addr().String()
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer":                 base,
				"authorization_endpoint": base + "/authorize",
				"token_endpoint":         base + "/token",
				"registration_endpoint":  base + "/register",
			})
		case "/register":
			var body map[string]interface{}
			json.NewDecoder(r.Body).Decode(&body)
			b := make([]byte, 8)
			rand.Read(b)
			clientID := "test-" + hex.EncodeToString(b)
			// Echo back the requested scope unchanged (vulnerable behavior)
			scope, _ := body["scope"].(string)
			if scope == "" {
				scope = "tools:read"
			}
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"client_id":     clientID,
				"client_secret": "secret-" + hex.EncodeToString(b),
				"scope":         scope,
				"redirect_uris": body["redirect_uris"],
			})
		default:
			http.NotFound(w, r)
		}
	}))
	return srv
}

// secureOAuthServer only allows the declared valid scope and rejects elevated requests.
func secureOAuthServer(t *testing.T) *httptest.Server {
	t.Helper()
	validScope := "tools:read"
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + srv.Listener.Addr().String()
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer":                 base,
				"authorization_endpoint": base + "/authorize",
				"token_endpoint":         base + "/token",
				"registration_endpoint":  base + "/register",
			})
		case "/register":
			var body map[string]interface{}
			json.NewDecoder(r.Body).Decode(&body)
			reqScope, _ := body["scope"].(string)

			// Reject elevated scopes
			for _, s := range strings.Fields(reqScope) {
				if s != validScope {
					w.WriteHeader(http.StatusBadRequest)
					json.NewEncoder(w).Encode(map[string]interface{}{
						"error":             "invalid_client_metadata",
						"error_description": "requested scope not permitted",
					})
					return
				}
			}

			b := make([]byte, 8)
			rand.Read(b)
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"client_id": "test-" + hex.EncodeToString(b),
				"scope":     validScope,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	return srv
}

// authGatedDCRServer advertises a registration endpoint but requires an Initial
// Access Token: anonymous registration is rejected with 401. This models a
// server where the anonymous-attacker path is not exploitable.
func authGatedDCRServer(t *testing.T) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + srv.Listener.Addr().String()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer":                 base,
				"registration_endpoint":  base + "/register",
				"authorization_endpoint": base + "/authorize",
				"token_endpoint":         base + "/token",
			})
		case "/register":
			if r.Header.Get("Authorization") == "" {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]interface{}{"error": "invalid_token"})
				return
			}
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{"client_id": "x", "scope": "tools:read"})
		default:
			http.NotFound(w, r)
		}
	}))
	return srv
}

// TestOAuthDCR_VulnerableScopeEscalation: anonymous registration is accepted and
// admin/write scopes are granted. The rule MUST fire with a single finding at the
// declared severity, as an indicator (registration-time evidence; token issuance
// is not demonstrated).
func TestOAuthDCR_VulnerableScopeEscalation(t *testing.T) {
	ts := vulnerableOAuthServer(t)
	defer ts.Close()

	findings, err := mcpattack.NewOAuthDCRExecutor(oauthRC()).Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly one finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != oauthRC().Severity {
		t.Errorf("want declared severity %q, got %q", oauthRC().Severity, f.Severity)
	}
	if f.Confidence != attack.RiskIndicator {
		t.Errorf("want RiskIndicator, got %q", f.Confidence)
	}
	if f.RuleID != oauthRC().ID {
		t.Errorf("RuleID = %q, want %q", f.RuleID, oauthRC().ID)
	}
}

// TestOAuthDCR_ScopeRestrictingServer: open registration is allowed (spec-OK)
// but the server reduces the granted scope to read-only. Open DCR alone is not a
// vulnerability, so the rule MUST stay silent.
func TestOAuthDCR_ScopeRestrictingServer(t *testing.T) {
	ts := secureOAuthServer(t)
	defer ts.Close()

	findings, err := mcpattack.NewOAuthDCRExecutor(oauthRC()).Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings when scopes are restricted, got %d: %+v", len(findings), findings)
	}
}

// TestOAuthDCR_AuthGatedRegistration: registration requires an Initial Access
// Token, so the anonymous path is rejected. The rule MUST stay silent.
func TestOAuthDCR_AuthGatedRegistration(t *testing.T) {
	ts := authGatedDCRServer(t)
	defer ts.Close()

	findings, err := mcpattack.NewOAuthDCRExecutor(oauthRC()).Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings when registration is auth-gated, got %d: %+v", len(findings), findings)
	}
}

// A reachable MCP server with no OAuth metadata is not applicable: clean.
func TestOAuthDCR_NoOAuthServer(t *testing.T) {
	ts, _ := mountedMCPServer(t)
	defer ts.Close()

	findings, err := mcpattack.NewOAuthDCRExecutor(oauthRC()).Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings on a non-OAuth MCP server, got %d", len(findings))
	}
}

// Nothing answered, so the rule was never exercised.
func TestOAuthDCR_NothingReachableIsNotTested(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	defer ts.Close()

	_, err := mcpattack.NewOAuthDCRExecutor(oauthRC()).Execute(context.Background(), ts.URL, testOpts())
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected ErrInconclusive when nothing answered, got err=%v", err)
	}
}
