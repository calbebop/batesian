package a2a

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// WellKnownPath is the v1.0 spec path for the public Agent Card.
	WellKnownPath = "/.well-known/agent-card.json"

	// WellKnownPathLegacy is the v0.3 path still used by many deployed agents
	// and all official a2a-samples. Probe both paths for maximum compatibility.
	WellKnownPathLegacy = "/.well-known/agent.json"

	// ExtendedCardPath is the path for the authenticated extended Agent Card.
	ExtendedCardPath = "/extendedAgentCard"

	defaultTimeout = 10 * time.Second
	maxBodyBytes   = 1 << 20 // 1 MB
)

// Client fetches and validates A2A endpoints.
type Client struct {
	http    *http.Client
	baseURL string
	headers map[string]string
}

// ClientOption configures a Client.
type ClientOption func(*Client)

// WithTimeout sets the HTTP request timeout.
func WithTimeout(d time.Duration) ClientOption {
	return func(c *Client) {
		c.http.Timeout = d
	}
}

// WithHeader adds a request header to all requests.
func WithHeader(key, value string) ClientOption {
	return func(c *Client) {
		c.headers[key] = value
	}
}

// WithBearerToken adds an Authorization: Bearer header.
func WithBearerToken(token string) ClientOption {
	return WithHeader("Authorization", "Bearer "+token)
}

// WithSkipTLSVerify disables TLS certificate verification.
// Only use for testing against self-signed certificates.
func WithSkipTLSVerify() ClientOption {
	return func(c *Client) {
		if transport, ok := c.http.Transport.(*http.Transport); ok {
			if transport.TLSClientConfig != nil {
				transport.TLSClientConfig.InsecureSkipVerify = true //nolint:gosec
			}
		}
	}
}

// NewClient creates a new A2A client for the given base URL.
func NewClient(baseURL string, opts ...ClientOption) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL %q: %w", baseURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("target URL must use http or https scheme, got %q", u.Scheme)
	}

	// Normalize: strip trailing slash
	base := strings.TrimRight(u.String(), "/")

	c := &Client{
		http: &http.Client{
			Timeout:   defaultTimeout,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{}}, //nolint:gosec
		},
		baseURL: base,
		headers: map[string]string{
			"User-Agent": "batesian/dev (https://github.com/calbebop/batesian)",
			"Accept":     "application/json",
		},
	}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// FetchAgentCard retrieves the public Agent Card. It tries the v1.0 path first
// (/.well-known/agent-card.json), then falls back to the v0.3 legacy path
// (/.well-known/agent.json) for compatibility with older deployments and samples.
func (c *Client) FetchAgentCard(ctx context.Context) (*AgentCard, *ProbeResult, error) {
	paths := []string{WellKnownPath, WellKnownPathLegacy}

	var lastResult *ProbeResult
	for _, path := range paths {
		target := c.baseURL + path
		result, body, err := c.get(ctx, target)
		lastResult = result

		if err != nil {
			// Network error — no point trying the other path
			return nil, result, err
		}
		if !result.IsSuccess() {
			// Not found at this path; try the next one
			continue
		}

		var card AgentCard
		if err := json.Unmarshal(body, &card); err != nil {
			return nil, result, fmt.Errorf("response from %s is not valid JSON: %w", target, err)
		}
		if card.Name == "" {
			return nil, result, fmt.Errorf("response from %s is missing required field 'name' (is this an A2A agent?)", target)
		}
		return &card, result, nil
	}

	return nil, lastResult, fmt.Errorf("no Agent Card found at %s or %s (HTTP %d) — is this an A2A agent?",
		c.baseURL+WellKnownPath, c.baseURL+WellKnownPathLegacy, lastResult.StatusCode)
}

// ProbeExtendedCard attempts to fetch /extendedAgentCard without authentication.
// Returns the HTTP status code and whether the card was disclosed.
func (c *Client) ProbeExtendedCard(ctx context.Context) (*ProbeResult, error) {
	target := c.baseURL + ExtendedCardPath
	result, _, err := c.get(ctx, target)
	return result, err
}

// ProbeExtendedCardWithInvalidToken attempts to fetch /extendedAgentCard with
// a fabricated, invalid Bearer token. If this returns 200, auth is not enforced.
func (c *Client) ProbeExtendedCardWithInvalidToken(ctx context.Context, token string) (*ProbeResult, error) {
	target := c.baseURL + ExtendedCardPath
	req, err := c.newRequest(ctx, http.MethodGet, target)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return c.do(req)
}

// get performs a GET request and returns the ProbeResult and body bytes.
func (c *Client) get(ctx context.Context, target string) (*ProbeResult, []byte, error) {
	req, err := c.newRequest(ctx, http.MethodGet, target)
	if err != nil {
		return nil, nil, err
	}
	result, err := c.do(req)
	if err != nil {
		return result, nil, err
	}
	return result, result.Body, nil
}

// newRequest builds an http.Request with standard headers applied.
func (c *Client) newRequest(ctx context.Context, method, target string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return nil, fmt.Errorf("building request for %s: %w", target, err)
	}
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}
	return req, nil
}

// do executes a request and captures the ProbeResult.
func (c *Client) do(req *http.Request) (*ProbeResult, error) {
	start := time.Now()
	resp, err := c.http.Do(req)
	elapsed := time.Since(start)

	result := &ProbeResult{
		URL:     req.URL.String(),
		Elapsed: elapsed,
	}

	if err != nil {
		result.Error = err
		return result, fmt.Errorf("request to %s failed: %w", req.URL, err)
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.Headers = resp.Header

	lr := io.LimitReader(resp.Body, maxBodyBytes)
	body, err := io.ReadAll(lr)
	if err != nil {
		return result, fmt.Errorf("reading response body from %s: %w", req.URL, err)
	}
	result.Body = body
	return result, nil
}

// ProbeResult captures the raw HTTP response for a single request.
type ProbeResult struct {
	URL        string
	StatusCode int
	Headers    http.Header
	Body       []byte
	Elapsed    time.Duration
	Error      error
}

// IsSuccess returns true if the status code is 2xx.
func (r *ProbeResult) IsSuccess() bool {
	return r.StatusCode >= 200 && r.StatusCode < 300
}

// IsUnauthorized returns true for 401 or 403 responses.
func (r *ProbeResult) IsUnauthorized() bool {
	return r.StatusCode == 401 || r.StatusCode == 403
}
