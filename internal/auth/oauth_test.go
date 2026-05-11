package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/auth"
)

func TestFetchClientCredentialsToken_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.FormValue("grant_type") != "client_credentials" {
			http.Error(w, "bad grant_type", http.StatusBadRequest)
			return
		}
		if r.FormValue("client_id") != "test-client" {
			http.Error(w, "bad client_id", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"scope":        "read write",
		})
	}))
	defer srv.Close()

	tok, err := auth.FetchClientCredentialsTokenWithClient(context.Background(), auth.ClientCredentialsConfig{
		TokenURL:     srv.URL + "/token",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Scopes:       []string{"read", "write"},
	}, srv.Client())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.AccessToken != "test-access-token" {
		t.Errorf("expected access_token=test-access-token, got %q", tok.AccessToken)
	}
	if tok.ExpiresIn != 3600 {
		t.Errorf("expected expires_in=3600, got %d", tok.ExpiresIn)
	}
}

func TestFetchClientCredentialsToken_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
	}))
	defer srv.Close()

	_, err := auth.FetchClientCredentialsTokenWithClient(context.Background(), auth.ClientCredentialsConfig{
		TokenURL: srv.URL + "/token",
		ClientID: "bad-client",
	}, srv.Client())
	if err == nil {
		t.Fatal("expected error for 401 response, got nil")
	}
	if !strings.Contains(err.Error(), "HTTP 401") {
		t.Errorf("expected HTTP 401 in error, got: %v", err)
	}
}

func TestFetchClientCredentialsToken_EmptyToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"token_type":"Bearer"}`)) // Missing access_token.
	}))
	defer srv.Close()

	_, err := auth.FetchClientCredentialsTokenWithClient(context.Background(), auth.ClientCredentialsConfig{
		TokenURL: srv.URL,
		ClientID: "c",
	}, srv.Client())
	if err == nil {
		t.Fatal("expected error for empty access_token, got nil")
	}
}

func TestFetchClientCredentialsToken_RejectsHTTP(t *testing.T) {
	// The public function must reject http:// token URLs to prevent cleartext
	// transmission of client credentials.
	_, err := auth.FetchClientCredentialsToken(context.Background(), auth.ClientCredentialsConfig{
		TokenURL:     "http://auth.example.com/token",
		ClientID:     "c",
		ClientSecret: "s",
	})
	if err == nil {
		t.Fatal("expected error for http:// token URL, got nil")
	}
	if !strings.Contains(err.Error(), "HTTPS") {
		t.Errorf("expected HTTPS-related error, got: %v", err)
	}
}

func TestExchangeAuthCode_RejectsHTTP(t *testing.T) {
	// The public function must reject http:// token URLs to prevent cleartext
	// transmission of authorization codes.
	_, err := auth.ExchangeAuthCode(context.Background(), auth.AuthCodeConfig{
		TokenURL:     "http://auth.example.com/token",
		ClientID:     "c",
		Code:         "abc",
		RedirectURI:  "http://localhost:9876/callback",
		PKCEVerifier: "v",
	})
	if err == nil {
		t.Fatal("expected error for http:// token URL, got nil")
	}
	if !strings.Contains(err.Error(), "HTTPS") {
		t.Errorf("expected HTTPS-related error, got: %v", err)
	}
}

func TestGeneratePKCE(t *testing.T) {
	p, err := auth.GeneratePKCE()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.Verifier) < 43 {
		t.Errorf("PKCE verifier too short: %d chars", len(p.Verifier))
	}
	if p.Challenge == p.Verifier {
		t.Error("PKCE challenge should differ from verifier (must be S256 hash)")
	}

	// Generate twice to confirm uniqueness.
	p2, _ := auth.GeneratePKCE()
	if p.Verifier == p2.Verifier {
		t.Error("PKCE verifiers should be unique across calls")
	}
}

func TestDiscoverTokenURL(t *testing.T) {
	// Serve an OIDC well-known document that returns an https:// token_endpoint.
	// This validates that discovery correctly parses the endpoint from the JSON.
	// The token_endpoint value uses a fake HTTPS URL since the new enforcement
	// in discoverTokenURLWithClient rejects http:// token endpoints.
	const fakeTokenEndpoint = "https://auth.example.com/oauth/token"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer":         "https://auth.example.com",
				"token_endpoint": fakeTokenEndpoint,
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	// Use the test helper that bypasses the HTTPS-only issuer check so we can
	// inject our httptest (http://) server without skipping the discovery logic.
	ep := auth.DiscoverTokenURLWithClient(context.Background(), srv.URL, &http.Client{})
	if ep == "" {
		t.Fatal("expected token endpoint from OIDC discovery, got empty string")
	}
	if ep != fakeTokenEndpoint {
		t.Errorf("unexpected token endpoint: got %q, want %q", ep, fakeTokenEndpoint)
	}
}

func TestDiscoverTokenURL_RejectsHTTPTokenEndpoint(t *testing.T) {
	// Verify that a metadata document advertising an http:// token_endpoint is
	// rejected even when the issuer itself is valid (security: prevent SSRF / plaintext creds).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer":         "https://auth.example.com",
				"token_endpoint": "http://auth.example.com/oauth/token",
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	ep := auth.DiscoverTokenURLWithClient(context.Background(), srv.URL, &http.Client{})
	if ep != "" {
		t.Errorf("expected empty string for http:// token_endpoint, got %q", ep)
	}
}

func TestDiscoverTokenURL_RejectsHTTP(t *testing.T) {
	// DiscoverTokenURL must return "" for http:// issuers (SSRF protection).
	ep := auth.DiscoverTokenURL(context.Background(), "http://malicious.example.com")
	if ep != "" {
		t.Errorf("expected empty string for http:// issuer, got %q", ep)
	}
}

func TestDiscoverTokenURL_NoDiscovery(t *testing.T) {
	// Server has no well-known documents.
	// Use DiscoverTokenURLWithClient to inject the httptest server without triggering
	// the HTTPS-only scheme guard in the public DiscoverTokenURL function.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	ep := auth.DiscoverTokenURLWithClient(context.Background(), srv.URL, &http.Client{})
	if ep != "" {
		t.Errorf("expected empty string for server without discovery, got %q", ep)
	}
}
