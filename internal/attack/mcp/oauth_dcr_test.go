package mcp_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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

func TestOAuthDCR_ScopeEscalation(t *testing.T) {
	ts := vulnerableOAuthServer(t)
	defer ts.Close()

	exec := mcpattack.NewOAuthDCRExecutor(oauthRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings on vulnerable OAuth server, got none")
	}

	// Must have a critical finding for scope escalation
	hasCritical := false
	for _, f := range findings {
		if f.Severity == "critical" {
			hasCritical = true
		}
	}
	if !hasCritical {
		t.Errorf("expected critical finding for scope escalation, findings: %v", findings)
	}
	rc := oauthRC()
	for _, f := range findings {
		if f.RuleID != rc.ID {
			t.Errorf("finding RuleID = %q, want %q", f.RuleID, rc.ID)
		}
		if f.Confidence == "" {
			t.Errorf("finding %q is missing Confidence field", f.Title)
		}
		if f.Confidence != attack.ConfirmedExploit {
			t.Errorf("expected ConfirmedExploit confidence for DCR finding %q, got %q", f.Title, f.Confidence)
		}
	}
}

func TestOAuthDCR_UnauthRegistration(t *testing.T) {
	ts := vulnerableOAuthServer(t)
	defer ts.Close()

	exec := mcpattack.NewOAuthDCRExecutor(oauthRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Must have at least a medium finding for unauthenticated registration
	hasMediumOrAbove := false
	for _, f := range findings {
		switch f.Severity {
		case "critical", "high", "medium":
			hasMediumOrAbove = true
		}
	}
	if !hasMediumOrAbove {
		t.Errorf("expected medium+ finding for unauthenticated DCR, findings: %v", findings)
	}
}

func TestOAuthDCR_RedirectURIAccepted(t *testing.T) {
	ts := vulnerableOAuthServer(t)
	defer ts.Close()

	exec := mcpattack.NewOAuthDCRExecutor(oauthRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have a finding about localhost/open-redirect URIs being accepted
	hasRedirectFinding := false
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Title), "redirect") {
			hasRedirectFinding = true
		}
	}
	if !hasRedirectFinding {
		t.Errorf("expected redirect URI finding, findings: %v", findings)
	}
}

func TestOAuthDCR_SecureServer(t *testing.T) {
	ts := secureOAuthServer(t)
	defer ts.Close()

	exec := mcpattack.NewOAuthDCRExecutor(oauthRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// A secure server still accepts baseline registration (unauthenticated DCR is
	// a medium finding even if scopes are restricted), but must NOT have critical.
	hasCritical := false
	for _, f := range findings {
		if f.Severity == "critical" {
			hasCritical = true
		}
	}
	if hasCritical {
		t.Errorf("secure server should not produce critical findings, got: %v", findings)
	}
}

func TestOAuthDCR_NoOAuthServer(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	defer ts.Close()

	exec := mcpattack.NewOAuthDCRExecutor(oauthRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings on non-OAuth server, got %d", len(findings))
	}
}
