package attack

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

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
	vars  Vars
	token string // bearer token injected into requests to targetHost when set
	// targetHost is the host:port of the scan target. The auto-injected token is
	// withheld from any other host; see tokenAllowedFor.
	targetHost string
}

// tokenAllowedFor reports whether the auto-injected bearer token may be sent to
// this URL. It may not leave the scan target's host.
//
// The operator supplies one credential, for one target. Several rules follow URLs
// the TARGET chooses: the resource_metadata parameter of its own WWW-Authenticate
// challenge, a registration_endpoint out of its OAuth metadata, a push-notification
// callback. A target that names another host and receives the operator's token has
// harvested a credential it was never issued, and it does so by answering a normal
// discovery request. Demonstrated against a server whose WWW-Authenticate pointed
// resource_metadata at a collector on another port: the collector received
// "Authorization: Bearer <operator token>".
//
// This guard is deliberately at the transport, not at the call sites. The call
// sites are the thing that keeps getting this wrong, and one of them shipped.
// An explicit per-request Authorization header still wins, because that is an
// author stating intent (principal tokens, forged tokens) rather than ambient
// injection.
//
// When the target host is unknown the token is sent, preserving the previous
// behaviour rather than silently dropping credentials.
func (c *HTTPClient) tokenAllowedFor(rawURL string) bool {
	if c.targetHost == "" {
		return true
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return true
	}
	return strings.EqualFold(u.Host, c.targetHost)
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

// hostOf returns the host:port of a URL, or "" when it cannot be determined.
func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Host
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
	timeout := time.Duration(opts.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &HTTPClient{
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
		vars:       vars,
		token:      opts.Token,
		targetHost: hostOf(vars.BaseURL),
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

// IsAccepted reports whether the response represents a successful JSON-RPC
// result: an HTTP 2xx whose body is valid JSON carrying a "result" envelope and
// no "error" envelope. This is the canonical "the JSON-RPC call succeeded"
// oracle.
//
// It exists because the older idiom IsSuccess() && !isJSONRPCError(body) treats
// any 2xx that is not a JSON-RPC error envelope as success - including an HTML
// login page, an empty body, "{}", or a bare object. Those are not results, and
// judging them as "accepted" produces false positives whenever a target answers
// an unauthenticated probe with a 2xx non-JSON body (common: redirects to a
// login page, generic 200 acks, HTML error interstitials).
//
// A JSON-null or empty-object result ({"result":null}, {"result":{}}) still
// counts as accepted: both are valid JSON-RPC success shapes, and rejecting
// them would risk false negatives on methods that legitimately return an empty
// result (e.g. logging/setLevel).
func (r *Response) IsAccepted() bool {
	if !r.IsSuccess() {
		return false
	}
	var m map[string]interface{}
	if err := json.Unmarshal(r.Body, &m); err != nil {
		return false
	}
	_, hasResult := m["result"]
	_, hasError := m["error"]
	return hasResult && !hasError
}

// IsJSON reports whether the response body is a JSON object. Use it for raw HTTP
// responses that are not JSON-RPC result envelopes (for example an A2A extended
// agent card fetched over HTTP GET) to reject HTML, empty, or non-JSON bodies
// before applying a structural shape check. Prefer IsAccepted for JSON-RPC
// method calls, which additionally requires a result envelope.
func (r *Response) IsJSON() bool {
	var m map[string]interface{}
	if err := json.Unmarshal(r.Body, &m); err != nil {
		return false
	}
	// A JSON "null" unmarshals to a nil map without error, but it is not a JSON
	// object, so it must not qualify as one.
	return m != nil
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
	var m map[string]interface{}
	if err := json.Unmarshal(r.Body, &m); err != nil {
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
	return c.do(ctx, http.MethodGet, c.vars.Expand(urlTpl), nil, c.vars.ExpandMap(headers))
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

// POST sends a POST request with a JSON body. body may be a map or struct.
func (c *HTTPClient) POST(ctx context.Context, urlTpl string, headers map[string]string, body interface{}) (*Response, error) {
	jsonBytes, err := marshalBody(body, c.vars)
	if err != nil {
		return nil, err
	}
	merged := map[string]string{"Content-Type": "application/json"}
	for k, v := range c.vars.ExpandMap(headers) {
		merged[k] = v
	}
	return c.do(ctx, http.MethodPost, c.vars.Expand(urlTpl), bytes.NewReader(jsonBytes), merged)
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

// readFirstSSEEvent returns the joined payload of the first SSE event. The
// stream is not drained: the parser stops after the first event so a stream the
// server never closes (standard for MCP streamable HTTP) cannot block the scan.
// readSSEResponse returns the JSON-RPC response carried on an SSE stream. A
// payload split across several "data:" lines is rejoined per spec.
//
// Two things this used to get wrong, both silent:
//
// It discarded sse.FirstData's error, so an over-long line or a mid-stream read
// failure produced a nil body on an HTTP 200. Response.IsAccepted unmarshals the
// body and returns false for nil, so a broken read was indistinguishable from the
// server refusing the request, for every rule using that oracle. The JSON branch
// beside it goes to deliberate lengths to make the same condition an explicit
// error; this branch, which is the one every real MCP server takes, did not.
//
// It also took the FIRST data event as the answer. MCP Streamable HTTP permits the
// server to send notifications and requests on the POST response stream before the
// response, so a progress notification or a data-bearing keepalive arriving first
// became the parsed reply: the real result was never seen, and a rule that gates on
// a result envelope reported the surface clean.
//
// A stream that ends with no response event is reported as an error rather than an
// empty body, because "the server sent no answer" and "the server refused" are
// different claims.
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

// errNoSSEResponse means the stream carried no JSON-RPC response event.
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
