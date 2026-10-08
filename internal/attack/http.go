package attack

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/calbebop/batesian/internal/httpx"
	"github.com/calbebop/batesian/internal/sse"
)

// maxBody bounds how much of a response body is read into memory.
//
// It was 1 MB, which a real server exceeds without trying: a tools/list on a
// server with a few hundred tools, or a resources/read of a config file, is
// larger than that. The read truncated silently at the limit, the truncated JSON
// failed to unmarshal, and rules that treat an unparseable probe the same as a
// refused one reported those surfaces clean. A wide-open server was measured
// producing 1 finding at 1.33 MB responses and 7 at 20 KB, with nothing else
// changed.
//
// The engine runs rules sequentially, so the cost is one body at a time rather
// than one per rule. Exceeding the limit is an explicit error (see the read in
// do), never a quietly shortened body.
const maxBody = 32 << 20 // 32 MB

// Version is the build-time version string injected from main via attack.Version.
// It is embedded in the User-Agent header on every outbound HTTP request.
// Defaults to "dev" so go run / unit tests have a useful value.
var Version = "dev"

// HTTPClient is a thin wrapper around net/http.Client with helpers for attack requests.
type HTTPClient struct {
	inner *http.Client
	// discovery is the scan-scoped endpoint cache; nil disables reuse.
	discovery *DiscoveryCache
	vars      Vars
	token     string // bearer token injected into requests to targetOrigin when set
	// targetOrigin is the normalized scheme, host, and port of the scan target.
	// The auto-injected token is withheld from every other origin.
	targetOrigin string
	// oauthOrigins contains exact additional origins the operator authorized for
	// target-advertised OAuth endpoints.
	oauthOrigins map[string]struct{}
}

// RequestAugmenter adds protocol-specific query fields or JSON body fields.
type RequestAugmenter func(method, requestURL string, headers map[string]string, body interface{}) (map[string]string, interface{})

type requestAugmenterKey struct{}

// WithRequestAugmenter applies request changes only within ctx.
func WithRequestAugmenter(ctx context.Context, augment RequestAugmenter) context.Context {
	return context.WithValue(ctx, requestAugmenterKey{}, augment)
}

func augmentRequest(ctx context.Context, method, requestURL string, headers map[string]string, body interface{}) (string, interface{}) {
	augment, ok := ctx.Value(requestAugmenterKey{}).(RequestAugmenter)
	if !ok {
		return requestURL, body
	}
	query, body := augment(method, requestURL, headers, body)
	if len(query) == 0 {
		return requestURL, body
	}
	u, err := url.Parse(requestURL)
	if err != nil {
		return requestURL, body
	}
	values := u.Query()
	for key, value := range query {
		values.Set(key, value)
	}
	u.RawQuery = values.Encode()
	return u.String(), body
}

// tokenAllowedFor reports whether the auto-injected bearer token may be sent to
// this URL. It may not leave the scan target's origin or cross from HTTPS to
// plaintext HTTP on the same host.
//
// Target-controlled discovery URLs must not receive ambient credentials off-origin.
// The transport enforces this for every call site; an explicit Authorization header
// still expresses caller intent. An unknown target origin preserves token delivery.
func (c *HTTPClient) tokenAllowedFor(rawURL string) bool {
	if c.targetOrigin == "" {
		return true
	}
	origin := originOf(rawURL)
	if origin == "" {
		return true
	}
	return origin == c.targetOrigin
}

// PresentsCredential reports whether a request this client sends to rawURL will
// carry the operator's bearer token.
//
// It exists so a rule that could not run can say which of two things happened: a
// server refused an anonymous handshake, or it refused the credential the scan was
// given. Those call for opposite actions, and telling an operator to pass --token
// when they already did is worse than saying nothing. It answers the same question
// the injection site asks, including the off-host guard, so the two cannot drift.
//
// An explicit per-request Authorization header still overrides this, so a caller
// that sets its own header knows more than this reports.
func (c *HTTPClient) PresentsCredential(rawURL string) bool {
	return c.token != "" && c.tokenAllowedFor(rawURL)
}

// originOf returns a normalized scheme, host, and port for an absolute URL.
// Default ports are made explicit so https://host and https://host:443 compare
// as the same origin.
func originOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Hostname() == "" {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	port := u.Port()
	if port == "" {
		switch scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}
	host := strings.ToLower(u.Hostname())
	if port != "" {
		host = net.JoinHostPort(host, port)
	}
	return scheme + "://" + host
}

// ValidateOAuthOrigins checks configured origins before a scan starts.
func ValidateOAuthOrigins(origins []string) error {
	for i, raw := range origins {
		if _, err := normalizeOAuthOrigin(raw); err != nil {
			return fmt.Errorf("invalid OAuth origin at index %d: %w", i, err)
		}
	}
	return nil
}

func normalizeOAuthOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("malformed URL")
	}
	if !u.IsAbs() || u.Hostname() == "" {
		return "", errors.New("must be an absolute HTTP(S) origin")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New("scheme must be http or https")
	}
	if u.User != nil {
		return "", errors.New("userinfo is not allowed")
	}
	if u.Path != "" && u.Path != "/" {
		return "", errors.New("paths are not allowed")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("queries and fragments are not allowed")
	}
	origin := originOf(raw)
	if origin == "" {
		return "", errors.New("could not normalize origin")
	}
	return origin, nil
}

// ValidateOAuthEndpoint confines a target-advertised OAuth URL to the selected
// target origin or an exact additional origin authorized by the operator.
func (c *HTTPClient) ValidateOAuthEndpoint(rawURL string) error {
	rawURL = c.vars.Expand(rawURL)
	u, err := url.Parse(rawURL)
	if err != nil || !u.IsAbs() || u.Hostname() == "" {
		return fmt.Errorf("%w: target advertised an invalid OAuth endpoint %q",
			ErrInconclusive, rawURL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%w: target advertised OAuth endpoint %q with unsupported scheme %q",
			ErrInconclusive, rawURL, u.Scheme)
	}
	if u.User != nil || u.Fragment != "" {
		return fmt.Errorf("%w: target advertised unsafe OAuth endpoint %q (userinfo and fragments are not allowed)",
			ErrInconclusive, rawURL)
	}
	origin := originOf(rawURL)
	if origin == c.targetOrigin {
		return nil
	}
	if _, ok := c.oauthOrigins[origin]; ok {
		return nil
	}
	return fmt.Errorf("%w: target advertised OAuth endpoint %q outside the authorized origin %s; "+
		"authorize %s explicitly with --oauth-origin to test it",
		ErrInconclusive, rawURL, c.targetOrigin, origin)
}

// NewUnauthHTTPClient creates an attack HTTP client with no bearer token.
// Use this for requests that are intentionally unauthenticated (e.g. baseline
// probes that test whether an endpoint can be reached without credentials).
// Using the standard NewHTTPClient would inject opts.Token, which would
// cause "no auth" tests to silently become authenticated when --token is set.
func NewUnauthHTTPClient(opts Options, vars Vars) *HTTPClient {
	unauthed := opts
	unauthed.Token = ""
	return NewHTTPClient(unauthed, vars)
}

// NewHTTPClient creates an attack HTTP client.
func NewHTTPClient(opts Options, vars Vars) *HTTPClient {
	timeout, err := httpx.TimeoutDuration(opts.TimeoutSeconds)
	if err != nil {
		timeout = 10 * time.Second
	}
	oauthOrigins := make(map[string]struct{}, len(opts.OAuthOrigins))
	for _, raw := range opts.OAuthOrigins {
		if origin, err := normalizeOAuthOrigin(raw); err == nil {
			oauthOrigins[origin] = struct{}{}
		}
	}
	return &HTTPClient{
		discovery: opts.Discovery,
		inner: &http.Client{
			Timeout:   timeout,
			Transport: Transport(opts),
			// Do not follow redirects. A scanner must see exactly what the
			// probed endpoint returns: following a 3xx to a login page masks an
			// auth rejection (and would then be misjudged as a 2xx success), and
			// silently bouncing a request that may carry the operator's bearer
			// token to a third-party host is a redirect-leak risk. Rules that
			// need the raw redirect response (e.g. confused-deputy) keep their
			// own client. OAuth token acquisition is unaffected: it uses the
			// separate client in internal/auth, which legitimately follows
			// redirects during the authorization-code flow.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		vars:         vars,
		token:        opts.Token,
		targetOrigin: originOf(vars.BaseURL),
		oauthOrigins: oauthOrigins,
	}
}

// Response captures an HTTP response for assertion evaluation.
type Response struct {
	URL        string
	StatusCode int
	Headers    http.Header
	Body       []byte
	Elapsed    time.Duration
}

// BodyString returns the response body as a string.
func (r *Response) BodyString() string {
	return string(r.Body)
}

// IsSuccess returns true for 2xx status codes.
func (r *Response) IsSuccess() bool {
	return r.StatusCode >= 200 && r.StatusCode < 300
}

// IsAccepted reports whether an HTTP 2xx response contains a JSON-RPC 2.0
// success envelope. Null and empty-object results are valid.
func (r *Response) IsAccepted() bool {
	if !r.IsSuccess() {
		return false
	}
	m, ok := parseJSONObject(r.Body)
	if !ok {
		return false
	}
	_, hasResult := m["result"]
	_, hasError := m["error"]
	_, hasID := m["id"]
	return m["jsonrpc"] == "2.0" && hasID && hasResult && !hasError
}

// IsJSON reports whether the response body is a JSON object. Use it for raw HTTP
// responses that are not JSON-RPC result envelopes (for example an A2A extended
// agent card fetched over HTTP GET) to reject HTML, empty, or non-JSON bodies
// before applying a structural shape check. Prefer IsAccepted for JSON-RPC
// method calls, which additionally requires a result envelope.
func (r *Response) IsJSON() bool {
	_, ok := parseJSONObject(r.Body)
	return ok
}

func parseJSONObject(body []byte) (map[string]interface{}, bool) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var value map[string]interface{}
	if dec.Decode(&value) != nil || value == nil {
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false
	}
	return value, true
}

// NormalizeHeaders returns a lowercase-keyed map of the response headers.
// Multiple values for the same header are joined with ", ".
func (r *Response) NormalizeHeaders() map[string]string {
	out := make(map[string]string, len(r.Headers))
	for k, v := range r.Headers {
		out[strings.ToLower(k)] = strings.Join(v, ", ")
	}
	return out
}

// JSONField extracts a nested field from the response body using a dot-path.
// Example: JSONField("scope") returns the "scope" value from a flat JSON object.
// Returns empty string if the field is absent or the body is not valid JSON.
func (r *Response) JSONField(path string) string {
	m, ok := parseJSONObject(r.Body)
	if !ok {
		return ""
	}
	parts := strings.Split(path, ".")
	var cur interface{} = m
	for _, part := range parts {
		mm, ok := cur.(map[string]interface{})
		if !ok {
			return ""
		}
		cur = mm[part]
	}
	switch v := cur.(type) {
	case string:
		return v
	case nil:
		return ""
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}

// ContainsAny returns true if the body contains any of the given substrings.
// Empty substrings are skipped: strings.Contains(body, "") is always true, so an
// empty needle (e.g. an optional, absent value like a missing contextId) must not
// be treated as a match against any body.
func (r *Response) ContainsAny(substrings ...string) bool {
	body := r.BodyString()
	for _, s := range substrings {
		if s != "" && strings.Contains(body, s) {
			return true
		}
	}
	return false
}

// GET sends a GET request to the expanded URL.
func (c *HTTPClient) GET(ctx context.Context, urlTpl string, headers map[string]string) (*Response, error) {
	url := c.vars.Expand(urlTpl)
	expandedHeaders := c.vars.ExpandMap(headers)
	url, _ = augmentRequest(ctx, http.MethodGet, url, expandedHeaders, nil)
	return c.do(ctx, http.MethodGet, url, nil, expandedHeaders)
}

// GETOAuth sends a GET only when the target-advertised OAuth URL stays within
// the operator-authorized origins.
func (c *HTTPClient) GETOAuth(ctx context.Context, urlTpl string, headers map[string]string) (*Response, error) {
	if err := c.ValidateOAuthEndpoint(urlTpl); err != nil {
		return nil, err
	}
	return c.GET(ctx, urlTpl, headers)
}

// OPTIONS sends an OPTIONS request (used for CORS preflight probes).
func (c *HTTPClient) OPTIONS(ctx context.Context, urlTpl string, headers map[string]string) (*Response, error) {
	return c.do(ctx, http.MethodOptions, c.vars.Expand(urlTpl), nil, c.vars.ExpandMap(headers))
}

// DELETE sends a DELETE request. The OAuth rules use it to remove the client
// registrations they create (RFC 7592), so a scan does not leave them on the target.
// It runs through the same transport as every other verb, so a dry run records it and
// sends nothing.
func (c *HTTPClient) DELETE(ctx context.Context, urlTpl string, headers map[string]string) (*Response, error) {
	return c.do(ctx, http.MethodDelete, c.vars.Expand(urlTpl), nil, c.vars.ExpandMap(headers))
}

// DELETEOAuth sends a DELETE only when the target-advertised OAuth URL stays
// within the operator-authorized origins.
func (c *HTTPClient) DELETEOAuth(ctx context.Context, urlTpl string, headers map[string]string) (*Response, error) {
	if err := c.ValidateOAuthEndpoint(urlTpl); err != nil {
		return nil, err
	}
	return c.DELETE(ctx, urlTpl, headers)
}

// POST sends a POST request with a JSON body. body may be a map or struct.
func (c *HTTPClient) POST(ctx context.Context, urlTpl string, headers map[string]string, body interface{}) (*Response, error) {
	url := c.vars.Expand(urlTpl)
	expandedHeaders := c.vars.ExpandMap(headers)
	url, body = augmentRequest(ctx, http.MethodPost, url, expandedHeaders, body)
	jsonBytes, err := marshalBody(body, c.vars)
	if err != nil {
		return nil, err
	}
	merged := map[string]string{"Content-Type": "application/json"}
	for k, v := range expandedHeaders {
		merged[k] = v
	}
	return c.do(ctx, http.MethodPost, url, bytes.NewReader(jsonBytes), merged)
}

// POSTOAuth sends a POST only when the target-advertised OAuth URL stays within
// the operator-authorized origins.
func (c *HTTPClient) POSTOAuth(ctx context.Context, urlTpl string, headers map[string]string, body interface{}) (*Response, error) {
	if err := c.ValidateOAuthEndpoint(urlTpl); err != nil {
		return nil, err
	}
	return c.POST(ctx, urlTpl, headers, body)
}

// do executes an HTTP request and returns the captured Response.
func (c *HTTPClient) do(ctx context.Context, method, url string, body io.Reader, headers map[string]string) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("building %s %s: %w", method, url, err)
	}
	req.Header.Set("User-Agent", "batesian/"+Version+" (https://github.com/calbebop/batesian)")
	// MCP streamable HTTP requires text/event-stream in Accept; A2A servers ignore it.
	req.Header.Set("Accept", "application/json, text/event-stream")
	// Inject the bearer token unless the caller overrides Authorization explicitly,
	// and never to a host other than the scan target: see tokenAllowedFor.
	if c.token != "" && c.tokenAllowedFor(url) {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	for k, v := range headers {
		// Go ignores a "Host" entry in req.Header - the request Host must be set
		// via req.Host. Honor it here so executors can forge the Host header
		// (e.g. the well-known host-injection probe).
		if strings.EqualFold(k, "Host") {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := c.inner.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, url, err)
	}
	defer resp.Body.Close()

	var respBody []byte
	ct := resp.Header.Get("Content-Type")
	if strings.Contains(ct, "text/event-stream") {
		// SSE streams never close; read only up to the response event then stop.
		respBody, err = readSSEResponse(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("reading SSE response from %s: %w", url, err)
		}
	} else {
		// Read one byte past the limit so exceeding it is detectable. A plain
		// LimitReader at maxBody returns a truncated body and no error, which
		// reads downstream as malformed JSON from the server rather than as a
		// body this scanner declined to finish reading.
		respBody, err = io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
		if err != nil {
			return nil, fmt.Errorf("reading response from %s: %w", url, err)
		}
		if len(respBody) > maxBody {
			return nil, fmt.Errorf("response body from %s exceeds the %d byte read limit", url, maxBody)
		}
	}

	return &Response{
		URL:        url,
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       respBody,
		Elapsed:    elapsed,
	}, nil
}

// readSSEResponse returns the first response candidate, joining multiline data
// fields and skipping notifications. Malformed JSON remains a candidate so the
// caller surfaces it. Reading errors or no candidate within the limits are errors.
func readSSEResponse(r io.Reader) ([]byte, error) {
	payload, found, err := sse.FirstMatching(r, maxBody, sse.IsJSONRPCResponse)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errNoSSEResponse
	}
	return payload, nil
}

// errNoSSEResponse means no response candidate was found within the limits.
var errNoSSEResponse = errors.New("stream carried no JSON-RPC response event")

// marshalBody encodes body as JSON with template variable expansion applied to string values.
func marshalBody(body interface{}, vars Vars) ([]byte, error) {
	if body == nil {
		return nil, nil
	}
	// Encode to JSON, then decode back to interface{} so we can walk and expand strings.
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("encoding request body: %w", err)
	}
	// Expand template vars in the JSON string before re-encoding.
	expanded := vars.Expand(string(raw))
	return []byte(expanded), nil
}

// Discovery returns the scan-scoped discovery cache this client carries, or
// nil when the engine did not provide one.
func (c *HTTPClient) Discovery() *DiscoveryCache {
	if c == nil {
		return nil
	}
	return c.discovery
}
