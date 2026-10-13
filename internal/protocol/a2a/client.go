package a2a

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"time"

	"github.com/calbebop/batesian/internal/endpoint"
	"github.com/calbebop/batesian/internal/httpx"
)

const (
	// WellKnownPath is the public Agent Card path for v0.3 and later.
	WellKnownPath = "/.well-known/agent-card.json"

	// WellKnownPathLegacy supports older deployments that serve agent.json.
	WellKnownPathLegacy = "/.well-known/agent.json"

	// ExtendedCardPath is the path for the authenticated extended Agent Card.
	ExtendedCardPath = "/extendedAgentCard"

	defaultTimeout = 10 * time.Second
	maxBodyBytes   = 32 << 20 // 32 MB; see internal/attack.maxBody
)

// Client fetches and validates A2A endpoints.
type Client struct {
	http    *http.Client
	baseURL string
	headers map[string]string

	// proxyErr records an unusable --proxy value so NewClient can report it
	// rather than let the scan run with interception silently bypassed.
	proxyErr error
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

// WithProxy routes requests through an intercepting proxy. An empty value leaves
// the environment in charge (HTTPS_PROXY, HTTP_PROXY, NO_PROXY), which is also the
// default: a bare &http.Transport{} ignores the environment, so before this the
// recon path proxied nothing even when the operator had set HTTPS_PROXY.
//
// An unusable value is reported at construction rather than dropped, so a mistyped
// proxy cannot silently bypass interception.
func WithProxy(raw string) ClientOption {
	return func(c *Client) {
		proxy, err := httpx.ProxyFunc(raw)
		if err != nil {
			c.proxyErr = err
			return
		}
		if t, ok := c.http.Transport.(*http.Transport); ok {
			t.Proxy = proxy
		}
	}
}

// WithSkipTLSVerify disables TLS certificate verification.
// Only use for testing against self-signed certificates.
func WithSkipTLSVerify() ClientOption {
	return func(c *Client) {
		if transport, ok := c.http.Transport.(*http.Transport); ok {
			if transport.TLSClientConfig == nil {
				transport.TLSClientConfig = &tls.Config{} //nolint:gosec
			}
			transport.TLSClientConfig.InsecureSkipVerify = true //nolint:gosec
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
	base := endpoint.TrimTrailingSlashes(u.String())

	c := &Client{
		http: &http.Client{
			Timeout: defaultTimeout,
			// Do not follow redirects. Matches the scan client (attack/http.go): a
			// server that 302s the agent card to a login page would otherwise have a
			// probe report the login page as the card.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport:     &http.Transport{TLSClientConfig: &tls.Config{}, Proxy: http.ProxyFromEnvironment}, //nolint:gosec
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
	if c.proxyErr != nil {
		return nil, c.proxyErr
	}

	return c, nil
}

// FetchAgentCard retrieves the public Agent Card across v1.0 and v0.3 endpoints.
func (c *Client) FetchAgentCard(ctx context.Context) (*AgentCard, *ProbeResult, error) {
	attempts := []struct {
		path string
		v1   bool
	}{
		{WellKnownPath, true},
		{WellKnownPath, false},
		{WellKnownPathLegacy, false},
	}

	var bestFailure *ProbeResult
	for _, attempt := range attempts {
		target := endpoint.AppendPath(c.baseURL, attempt.path)
		result, body, err := c.get(ctx, target, attempt.v1)

		if err != nil {
			return nil, result, err
		}
		if !result.IsSuccess() {
			if bestFailure == nil || cardFailurePriority(result.StatusCode) > cardFailurePriority(bestFailure.StatusCode) {
				bestFailure = result
			}
			continue
		}

		if err := ValidateAgentCard(body); err != nil {
			return nil, result, fmt.Errorf("invalid Agent Card from %s: %w", target, err)
		}
		var card AgentCard
		if err := json.Unmarshal(body, &card); err != nil {
			return nil, result, fmt.Errorf("response from %s is not valid JSON: %w", target, err)
		}
		return &card, result, nil
	}

	if bestFailure.StatusCode != http.StatusNotFound {
		return nil, bestFailure, fmt.Errorf("agent card request to %s returned HTTP %d", bestFailure.URL, bestFailure.StatusCode)
	}
	return nil, bestFailure, fmt.Errorf("no Agent Card found at %s or %s (HTTP 404) - is this an A2A agent?",
		endpoint.AppendPath(c.baseURL, WellKnownPath), endpoint.AppendPath(c.baseURL, WellKnownPathLegacy))
}

func cardFailurePriority(status int) int {
	switch {
	case status >= 500:
		return 3
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return 2
	case status == http.StatusNotFound:
		return 0
	default:
		return 1
	}
}

// ProbeExtendedCard fetches the v1.0 /extendedAgentCard path without authentication.
func (c *Client) ProbeExtendedCard(ctx context.Context) (*ProbeResult, error) {
	target := endpoint.AppendPath(c.baseURL, ExtendedCardPath)
	req, err := c.newRequest(ctx, http.MethodGet, target)
	if err != nil {
		return nil, err
	}
	defaultV1Version(req)
	req.Header.Del("Authorization")
	return c.do(req)
}

// ProbeExtendedCardWithInvalidToken fetches the v1.0 path with an invalid token.
func (c *Client) ProbeExtendedCardWithInvalidToken(ctx context.Context, token string) (*ProbeResult, error) {
	target := endpoint.AppendPath(c.baseURL, ExtendedCardPath)
	req, err := c.newRequest(ctx, http.MethodGet, target)
	if err != nil {
		return nil, err
	}
	defaultV1Version(req)
	req.Header.Set("Authorization", "Bearer "+token)
	return c.do(req)
}

// get performs a GET request and returns the ProbeResult and body bytes.
func (c *Client) get(ctx context.Context, target string, v1 bool) (*ProbeResult, []byte, error) {
	req, err := c.newRequest(ctx, http.MethodGet, target)
	if err != nil {
		return nil, nil, err
	}
	if v1 {
		defaultV1Version(req)
	} else {
		req.Header.Del("A2A-Version")
	}
	result, err := c.do(req)
	if err != nil {
		return result, nil, err
	}
	return result, result.Body, nil
}

func defaultV1Version(req *http.Request) {
	if req.Header.Get("A2A-Version") == "" {
		req.Header.Set("A2A-Version", "1.0")
	}
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

	// Read one byte past the limit so exceeding it is detectable, matching the
	// scan client. A plain LimitReader at the limit returns a truncated body and no
	// error, which reads downstream as malformed JSON from the server rather than a
	// body this client declined to finish reading.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return result, fmt.Errorf("reading response body from %s: %w", req.URL, err)
	}
	if len(body) > maxBodyBytes {
		return result, fmt.Errorf("response body from %s exceeds the %d byte read limit", req.URL, maxBodyBytes)
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
