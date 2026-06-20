package mcp_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/calbebop/batesian/internal/attack"
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

func omRuleCtx() attack.RuleContext {
	return attack.RuleContext{ID: "mcp-oauth-metadata-ssrf-001", Name: "MCP OAuth Metadata SSRF", Severity: "high", Remediation: "Allow-list metadata fetches."}
}

// metadataSSRFServer models an OAuth authorization server with a DCR endpoint.
// mode controls behaviour on registration:
//   - "fetch":   fetches the registrant-supplied jwks_uri (vulnerable SSRF)
//   - "nofetch": stores metadata without fetching (safe)
//   - "no-oauth": serves no authorization-server metadata
func metadataSSRFServer(mode string) *httptest.Server {
	mux := http.NewServeMux()
	ts := httptest.NewServer(mux)

	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		if mode == "no-oauth" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                ts.URL,
			"registration_endpoint": ts.URL + "/register",
		})
	})

	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)

		if mode == "fetch" {
			if u, _ := body["jwks_uri"].(string); u != "" {
				// VULNERABLE: fetch the registrant-supplied URL server-side.
				c := &http.Client{Timeout: 3 * time.Second}
				if req, err := http.NewRequest(http.MethodGet, u, nil); err == nil {
					if resp, err := c.Do(req); err == nil {
						_ = resp.Body.Close()
					}
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"client_id": "c-123", "client_name": body["client_name"]})
	})

	return ts
}

func runMetadataSSRF(t *testing.T, ts *httptest.Server) []attack.Finding {
	t.Helper()
	findings, err := mcpattack.NewOAuthMetadataSSRFExecutor(omRuleCtx()).Execute(context.Background(), ts.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return findings
}

// TestMetadataSSRF_Fetch: server fetches jwks_uri => confirmed SSRF.
func TestMetadataSSRF_Fetch(t *testing.T) {
	ts := metadataSSRFServer("fetch")
	defer ts.Close()

	findings := runMetadataSSRF(t, ts)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Confidence != attack.ConfirmedExploit || f.Severity != "high" {
		t.Errorf("want high/ConfirmedExploit, got %q/%q", f.Severity, f.Confidence)
	}
}

// TestMetadataSSRF_NoFetch: server does not fetch => no finding.
func TestMetadataSSRF_NoFetch(t *testing.T) {
	ts := metadataSSRFServer("nofetch")
	defer ts.Close()

	if findings := runMetadataSSRF(t, ts); len(findings) != 0 {
		t.Errorf("expected zero findings when server does not fetch metadata, got %d: %+v", len(findings), findings)
	}
}

// TestMetadataSSRF_NoOAuth: no DCR endpoint => clean skip.
func TestMetadataSSRF_NoOAuth(t *testing.T) {
	ts := metadataSSRFServer("no-oauth")
	defer ts.Close()

	if findings := runMetadataSSRF(t, ts); len(findings) != 0 {
		t.Errorf("expected zero findings against a non-OAuth server, got %d", len(findings))
	}
}
