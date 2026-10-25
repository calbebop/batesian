package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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
		if r.FormValue("resource") != "https://mcp.example.com/mcp" {
			http.Error(w, "bad resource", http.StatusBadRequest)
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
		Resource:     "https://mcp.example.com/mcp",
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

func TestExchangeAuthCode_SendsResource(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || r.FormValue("resource") != "https://mcp.example.com/mcp" {
			http.Error(w, "bad resource", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"token","token_type":"Bearer"}`))
	}))
	defer srv.Close()

	_, err := auth.ExchangeAuthCodeWithClient(context.Background(), auth.AuthCodeConfig{
		TokenURL: srv.URL, ClientID: "client", Code: "code",
		RedirectURI: "http://127.0.0.1:9876/callback", PKCEVerifier: "verifier",
		Resource: "https://mcp.example.com/mcp",
	}, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
}

func TestTokenExchange_RequiresBearerType(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"missing", `{"access_token":"secret"}`, "no token_type"},
		{"unsupported", `{"access_token":"secret","token_type":"MAC"}`, "unsupported token_type"},
		{"bearer case insensitive", `{"access_token":"secret","token_type":"bearer"}`, ""},
	} {
		for _, grant := range []string{"client_credentials", "authorization_code"} {
			t.Run(grant+"/"+tc.name, func(t *testing.T) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = w.Write([]byte(tc.body))
				}))
				defer srv.Close()
				var err error
				if grant == "client_credentials" {
					_, err = auth.FetchClientCredentialsTokenWithClient(t.Context(), auth.ClientCredentialsConfig{
						TokenURL: srv.URL, ClientID: "client",
					}, srv.Client())
				} else {
					_, err = auth.ExchangeAuthCodeWithClient(t.Context(), auth.AuthCodeConfig{
						TokenURL: srv.URL, ClientID: "client", Code: "code", RedirectURI: "http://127.0.0.1/callback", PKCEVerifier: "verifier",
					}, srv.Client())
				}
				if tc.want == "" {
					if err != nil {
						t.Fatal(err)
					}
				} else if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "secret") {
					t.Fatalf("expected safe %s error, got %v", tc.want, err)
				}
			})
		}
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

func TestFetchClientCredentialsToken_RefusesRedirect(t *testing.T) {
	var redirected atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected.Store(true)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"leaked"}`))
	}))
	defer target.Close()

	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer endpoint.Close()

	_, err := auth.FetchClientCredentialsTokenWithClient(context.Background(), auth.ClientCredentialsConfig{
		TokenURL:     endpoint.URL,
		ClientID:     "client",
		ClientSecret: "secret",
	}, endpoint.Client())
	if err == nil || !strings.Contains(err.Error(), "redirect refused") {
		t.Fatalf("expected redirect refusal, got %v", err)
	}
	if redirected.Load() {
		t.Fatal("token request followed a redirect and replayed its credentials")
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

func TestExchangeAuthCode_RefusesRedirect(t *testing.T) {
	var redirected atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected.Store(true)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"leaked"}`))
	}))
	defer target.Close()

	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusPermanentRedirect)
	}))
	defer endpoint.Close()

	_, err := auth.ExchangeAuthCodeWithClient(context.Background(), auth.AuthCodeConfig{
		TokenURL:     endpoint.URL,
		ClientID:     "client",
		Code:         "authorization-code",
		RedirectURI:  "http://127.0.0.1/callback",
		PKCEVerifier: "verifier",
	}, endpoint.Client())
	if err == nil || !strings.Contains(err.Error(), "redirect refused") {
		t.Fatalf("expected redirect refusal, got %v", err)
	}
	if redirected.Load() {
		t.Fatal("authorization-code exchange followed a redirect and replayed its credentials")
	}
}

func TestExchangeAuthCode_MissingAccessTokenDoesNotExposeResponse(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"missing", `{"refresh_token":"refresh-secret","id_token":"identity-secret"}`},
		{"empty", `{"access_token":"","refresh_token":"refresh-secret","id_token":"identity-secret"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			_, err := auth.ExchangeAuthCodeWithClient(context.Background(), auth.AuthCodeConfig{
				TokenURL:     srv.URL,
				ClientID:     "client",
				Code:         "code",
				RedirectURI:  "http://127.0.0.1/callback",
				PKCEVerifier: "verifier",
			}, srv.Client())
			if err == nil || !strings.Contains(err.Error(), "no access_token") {
				t.Fatalf("expected missing access token error, got %v", err)
			}
			for _, secret := range []string{"refresh-secret", "identity-secret"} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("error exposed %q: %v", secret, err)
				}
			}
		})
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
