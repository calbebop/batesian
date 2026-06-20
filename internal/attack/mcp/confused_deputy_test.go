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

func confusedDeputyRC() attack.RuleContext {
	return attack.RuleContext{
		ID:          "mcp-confused-deputy-001",
		Name:        "MCP OAuth Confused Deputy",
		Severity:    "high",
		Remediation: "Validate redirect_uri with exact string matching.",
	}
}

// confusedDeputyServer models an MCP OAuth authorization server. mode selects
// redirect_uri handling:
//   - "vulnerable":     /authorize redirects to ANY supplied redirect_uri
//   - "exact-match":    DCR accepts the off-origin redirect, but /authorize rejects
//     an unregistered redirect_uri (only the DCR-precondition indicator can fire)
//   - "dcr-restricted": DCR rejects an off-origin redirect (allowlist enforced)
//   - "not-oauth":      no authorization-server metadata
func confusedDeputyServer(mode string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		writeJSON := func(code int, v map[string]interface{}) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(v)
		}
		switch {
		case r.URL.Path == "/.well-known/oauth-authorization-server":
			if mode == "not-oauth" {
				http.NotFound(w, r)
				return
			}
			writeJSON(http.StatusOK, map[string]interface{}{
				"issuer":                 base,
				"registration_endpoint":  base + "/register",
				"authorization_endpoint": base + "/authorize",
				"token_endpoint":         base + "/token",
			})
		case r.URL.Path == "/register" && r.Method == http.MethodPost:
			var body map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			redirects, _ := body["redirect_uris"].([]interface{})
			if mode == "dcr-restricted" && hasInvalidTLDRedirect(redirects) {
				writeJSON(http.StatusBadRequest, map[string]interface{}{"error": "invalid_redirect_uri"})
				return
			}
			writeJSON(http.StatusCreated, map[string]interface{}{
				"client_id":     "cd-client-123",
				"redirect_uris": redirects,
			})
		case r.URL.Path == "/authorize" && r.Method == http.MethodGet:
			redirectURI := r.URL.Query().Get("redirect_uri")
			if mode == "vulnerable" {
				// No exact-match: redirect to whatever was supplied.
				http.Redirect(w, r, redirectURI+"?code=fake", http.StatusFound)
				return
			}
			// exact-match / dcr-restricted: the probe's redirect_uri was never
			// registered for this client, so reject WITHOUT redirecting to it.
			writeJSON(http.StatusBadRequest, map[string]interface{}{"error": "invalid_request"})
		default:
			http.NotFound(w, r)
		}
	}))
}

func hasInvalidTLDRedirect(redirects []interface{}) bool {
	for _, ru := range redirects {
		if s, _ := ru.(string); strings.Contains(s, ".invalid") {
			return true
		}
	}
	return false
}

func runConfusedDeputy(t *testing.T, ts *httptest.Server) []attack.Finding {
	t.Helper()
	findings, err := mcpattack.NewConfusedDeputyExecutor(confusedDeputyRC()).Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return findings
}

// TestConfusedDeputy_Vulnerable: /authorize redirects to an unregistered
// off-origin redirect_uri. MUST fire confirmed/high.
func TestConfusedDeputy_Vulnerable(t *testing.T) {
	ts := confusedDeputyServer("vulnerable")
	defer ts.Close()

	findings := runConfusedDeputy(t, ts)
	if len(findings) != 1 {
		t.Fatalf("expected exactly one finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Confidence != attack.ConfirmedExploit || f.Severity != "high" {
		t.Errorf("want high/ConfirmedExploit, got %q/%q", f.Severity, f.Confidence)
	}
	if !strings.Contains(f.Title, "confused deputy") {
		t.Errorf("unexpected title: %q", f.Title)
	}
}

// TestConfusedDeputy_DCRPreconditionIsIndicator: DCR accepts the off-origin
// redirect but /authorize enforces exact match. Only the precondition indicator
// fires (medium/RiskIndicator).
func TestConfusedDeputy_DCRPreconditionIsIndicator(t *testing.T) {
	ts := confusedDeputyServer("exact-match")
	defer ts.Close()

	findings := runConfusedDeputy(t, ts)
	if len(findings) != 1 {
		t.Fatalf("expected exactly one indicator finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Confidence != attack.RiskIndicator || findings[0].Severity != "medium" {
		t.Errorf("want medium/RiskIndicator, got %q/%q", findings[0].Severity, findings[0].Confidence)
	}
}

// TestConfusedDeputy_DCRRestricted: DCR rejects the off-origin redirect (the
// server enforces a redirect allowlist). The rule MUST stay silent.
func TestConfusedDeputy_DCRRestricted(t *testing.T) {
	ts := confusedDeputyServer("dcr-restricted")
	defer ts.Close()

	if findings := runConfusedDeputy(t, ts); len(findings) != 0 {
		t.Errorf("expected zero findings when DCR rejects an off-origin redirect, got %d: %+v", len(findings), findings)
	}
}

// TestConfusedDeputy_NotOAuth: no authorization-server metadata. The rule does
// not apply and MUST stay silent.
func TestConfusedDeputy_NotOAuth(t *testing.T) {
	ts := confusedDeputyServer("not-oauth")
	defer ts.Close()

	if findings := runConfusedDeputy(t, ts); len(findings) != 0 {
		t.Errorf("expected zero findings against a non-OAuth server, got %d", len(findings))
	}
}
