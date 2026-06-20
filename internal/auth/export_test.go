package auth

import (
	"context"
	"net/http"
)

// DiscoverTokenURLWithClient is a test-only export of discoverTokenURLWithClient,
// allowing unit tests to inject an httptest server client without bypassing the
// SSRF scheme guard in the public DiscoverTokenURL function.
func DiscoverTokenURLWithClient(ctx context.Context, issuer string, client *http.Client) string {
	return discoverTokenURLWithClient(ctx, issuer, client)
}

// FetchClientCredentialsTokenWithClient is a test-only export that bypasses the
// HTTPS-only scheme guard so unit tests can target an httptest (http://) server.
func FetchClientCredentialsTokenWithClient(ctx context.Context, cfg ClientCredentialsConfig, client *http.Client) (*TokenResponse, error) {
	return fetchClientCredentialsTokenWithClient(ctx, cfg, client)
}

// ExchangeAuthCodeWithClient is a test-only export that bypasses the HTTPS-only
// scheme guard so unit tests can target an httptest (http://) server.
func ExchangeAuthCodeWithClient(ctx context.Context, cfg AuthCodeConfig, client *http.Client) (*TokenResponse, error) {
	return exchangeAuthCodeWithClient(ctx, cfg, client)
}

// PerformPKCEFlowWithClient is a test-only export that lets unit tests inject
// a trusted http.Client for the token-exchange leg. Required when the token
// endpoint is served by httptest.NewTLSServer (self-signed certificate).
func PerformPKCEFlowWithClient(ctx context.Context, cfg PKCEFlowConfig, client *http.Client) (*TokenResponse, error) {
	return performPKCEFlowWithClient(ctx, cfg, client)
}
