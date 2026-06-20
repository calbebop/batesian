// Package auth provides OAuth 2.0 token acquisition for authenticated A2A and MCP targets.
// It supports two flows:
//   - Client credentials (machine-to-machine, no user interaction)
//   - Authorization code with PKCE (for targets that require user consent)
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// TokenResponse holds the fields returned by an OAuth 2.0 token endpoint.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

// ClientCredentialsConfig holds the parameters for a client credentials grant.
type ClientCredentialsConfig struct {
	// TokenURL is the OAuth 2.0 token endpoint (e.g. https://auth.example.com/oauth/token).
	TokenURL string
	// ClientID is the OAuth client identifier.
	ClientID string
	// ClientSecret is the OAuth client secret.
	ClientSecret string
	// Scopes is the list of scopes to request.
	Scopes []string
	// Audience is the target API identifier (optional; used by Auth0, Okta, etc.).
	Audience string
	// Timeout is the HTTP timeout for the token request (default: 15s).
	Timeout time.Duration
}

// FetchClientCredentialsToken performs an OAuth 2.0 client credentials grant
// and returns a bearer token ready to use in Authorization headers.
//
// The TokenURL must use HTTPS to prevent cleartext transmission of client
// credentials. HTTP token endpoints are rejected with an explicit error.
func FetchClientCredentialsToken(ctx context.Context, cfg ClientCredentialsConfig) (*TokenResponse, error) {
	if !strings.HasPrefix(cfg.TokenURL, "https://") {
		return nil, fmt.Errorf("token URL must use HTTPS to protect client credentials in transit (got: %s)", cfg.TokenURL)
	}
	return fetchClientCredentialsTokenWithClient(ctx, cfg, nil)
}

// fetchClientCredentialsTokenWithClient performs the actual HTTP exchange.
// If client is nil, a default client with cfg.Timeout is constructed.
// This indirection exists so unit tests can bypass the HTTPS-only scheme guard
// when targeting an httptest server.
func fetchClientCredentialsTokenWithClient(ctx context.Context, cfg ClientCredentialsConfig, client *http.Client) (*TokenResponse, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = 15 * time.Second
	}

	form := url.Values{
		"grant_type": {"client_credentials"},
		"client_id":  {cfg.ClientID},
	}
	if cfg.ClientSecret != "" {
		form.Set("client_secret", cfg.ClientSecret)
	}
	if len(cfg.Scopes) > 0 {
		form.Set("scope", strings.Join(cfg.Scopes, " "))
	}
	if cfg.Audience != "" {
		form.Set("audience", cfg.Audience)
	}

	httpClient := client
	if httpClient == nil {
		httpClient = &http.Client{Timeout: cfg.Timeout}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.TokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("building token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request to %s: %w", cfg.TokenURL, err)
	}
	defer resp.Body.Close()

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned HTTP %d (check credentials and scopes)", resp.StatusCode)
	}
	if readErr != nil {
		return nil, fmt.Errorf("reading token response: %w", readErr)
	}

	var tok TokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, fmt.Errorf("parsing token response: %w", err)
	}
	if tok.AccessToken == "" {
		return nil, fmt.Errorf("token endpoint returned HTTP 200 but no access_token in response")
	}

	return &tok, nil
}

// PKCEParams holds the PKCE code verifier and challenge for an authorization code flow.
type PKCEParams struct {
	// Verifier is the random secret used to derive the challenge.
	Verifier string
	// Challenge is the S256-encoded value sent to the authorization endpoint.
	Challenge string
}

// GeneratePKCE generates a cryptographically secure PKCE verifier and S256 challenge.
func GeneratePKCE() (*PKCEParams, error) {
	// RFC 7636: verifier must be 43-128 characters of unreserved chars.
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("generating PKCE verifier: %w", err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(raw)

	// S256: BASE64URL(SHA256(ASCII(verifier)))
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	return &PKCEParams{Verifier: verifier, Challenge: challenge}, nil
}

// AuthCodeConfig holds parameters for an authorization code + PKCE token exchange.
type AuthCodeConfig struct {
	// TokenURL is the OAuth 2.0 token endpoint.
	TokenURL string
	// ClientID is the OAuth client identifier.
	ClientID string
	// RedirectURI is the callback URI registered with the authorization server.
	RedirectURI string
	// Code is the authorization code received from the authorization server callback.
	Code string
	// PKCEVerifier is the PKCE code verifier generated before the authorization request.
	PKCEVerifier string
	// Timeout is the HTTP timeout for the token request.
	Timeout time.Duration
}

// ExchangeAuthCode exchanges an authorization code (plus PKCE verifier) for tokens.
//
// The TokenURL must use HTTPS to prevent cleartext transmission of authorization
// codes. HTTP token endpoints are rejected with an explicit error.
func ExchangeAuthCode(ctx context.Context, cfg AuthCodeConfig) (*TokenResponse, error) {
	if !strings.HasPrefix(cfg.TokenURL, "https://") {
		return nil, fmt.Errorf("token URL must use HTTPS to protect authorization codes in transit (got: %s)", cfg.TokenURL)
	}
	return exchangeAuthCodeWithClient(ctx, cfg, nil)
}

// exchangeAuthCodeWithClient performs the actual HTTP exchange.
// If client is nil, a default client with cfg.Timeout is constructed.
// Used by unit tests to bypass the HTTPS-only scheme guard.
func exchangeAuthCodeWithClient(ctx context.Context, cfg AuthCodeConfig, client *http.Client) (*TokenResponse, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = 15 * time.Second
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {cfg.ClientID},
		"code":          {cfg.Code},
		"redirect_uri":  {cfg.RedirectURI},
		"code_verifier": {cfg.PKCEVerifier},
	}

	httpClient := client
	if httpClient == nil {
		httpClient = &http.Client{Timeout: cfg.Timeout}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.TokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("building auth code exchange request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("auth code exchange to %s: %w", cfg.TokenURL, err)
	}
	defer resp.Body.Close()

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned HTTP %d (check authorization code and redirect URI)", resp.StatusCode)
	}
	if readErr != nil {
		return nil, fmt.Errorf("reading auth code token response: %w", readErr)
	}

	var tok TokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, fmt.Errorf("parsing auth code token response: %w", err)
	}
	if tok.AccessToken == "" {
		return nil, fmt.Errorf("token endpoint returned empty access_token: %s", string(body))
	}

	return &tok, nil
}

// DiscoverTokenURL attempts to discover the OAuth 2.0 token endpoint from an
// OpenID Connect or OAuth metadata document at the given issuer URL.
// Returns an empty string if discovery fails; the caller should fall back to
// a manually configured TokenURL.
//
// Only https:// issuer URLs are accepted to avoid SSRF against plaintext endpoints.
func DiscoverTokenURL(ctx context.Context, issuer string) string {
	if !strings.HasPrefix(issuer, "https://") {
		return "" // Reject non-HTTPS issuers to prevent SSRF via plaintext channels.
	}
	return discoverTokenURLWithClient(ctx, issuer, &http.Client{Timeout: 5 * time.Second})
}

// discoverTokenURLWithClient is the inner discovery function used by DiscoverTokenURL.
// It accepts an explicit http.Client to allow unit tests to inject an httptest server client.
func discoverTokenURLWithClient(ctx context.Context, issuer string, client *http.Client) string {
	// Try OIDC well-known first, then OAuth 2.0 authorization server metadata.
	candidates := []string{
		strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration",
		strings.TrimRight(issuer, "/") + "/.well-known/oauth-authorization-server",
	}

	for _, u := range candidates {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			if resp != nil {
				resp.Body.Close()
			}
			continue
		}

		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
		resp.Body.Close()
		if readErr != nil {
			continue
		}

		var meta map[string]interface{}
		if err := json.Unmarshal(body, &meta); err != nil {
			continue
		}
		if ep, ok := meta["token_endpoint"].(string); ok && ep != "" {
			// Reject non-HTTPS token endpoints to prevent SSRF and cleartext
			// credential transmission, even when the issuer itself is valid HTTPS.
			if !strings.HasPrefix(ep, "https://") {
				continue
			}
			return ep
		}
	}

	return ""
}
