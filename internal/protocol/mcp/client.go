// Package mcp provides a lightweight MCP protocol client for reconnaissance.
// It handles the initialize handshake, SSE response parsing, and session ID
// threading required by the MCP 2025-03-26 specification.
package mcp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"strings"
	"time"

	"github.com/calbebop/batesian/internal/httpx"

	"github.com/calbebop/batesian/internal/endpoint"
	"github.com/calbebop/batesian/internal/sse"
)

const (
	defaultTimeout = 10 * time.Second
	maxBodyBytes   = 32 << 20 // 32 MB; see internal/attack.maxBody
)

// candidatePaths are tried in order when discovering the MCP endpoint.
var candidatePaths = []string{"/mcp", "/", "/api", "/rpc"}

// Client is a lightweight MCP protocol client for use by the probe command.
type Client struct {
	http        *http.Client
	baseURL     string
	bearerToken string

	// proxyErr records an unusable --proxy value so NewClient can report it
	// rather than let the scan run with interception silently bypassed.
	proxyErr error
}

// ClientOption configures a Client.
type ClientOption func(*Client)

// WithTimeout sets the HTTP request timeout.
func WithTimeout(d time.Duration) ClientOption {
	return func(c *Client) { c.http.Timeout = d }
}

// WithBearerToken attaches an Authorization: Bearer header to every request.
func WithBearerToken(token string) ClientOption {
	return func(c *Client) { c.bearerToken = token }
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
func WithSkipTLSVerify() ClientOption {
	return func(c *Client) {
		if t, ok := c.http.Transport.(*http.Transport); ok {
			if t.TLSClientConfig == nil {
				t.TLSClientConfig = &tls.Config{} //nolint:gosec
			}
			t.TLSClientConfig.InsecureSkipVerify = true //nolint:gosec
		}
	}
}

// NewClient creates a new MCP client for the given base URL.
func NewClient(baseURL string, opts ...ClientOption) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL %q: %w", baseURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("target URL must use http or https scheme, got %q", u.Scheme)
	}
	c := &Client{
		http: &http.Client{
			Timeout:   defaultTimeout,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{}, Proxy: http.ProxyFromEnvironment}, //nolint:gosec
		},
		baseURL: strings.TrimRight(u.String(), "/"),
	}
	for _, o := range opts {
		o(c)
	}
	if c.proxyErr != nil {
		return nil, c.proxyErr
	}

	return c, nil
}

// Session represents an active MCP connection after the initialize handshake.
type Session struct {
	Endpoint        string
	SessionID       string
	ProtocolVersion string
	ServerInfo      ServerInfo
	Capabilities    map[string]interface{}
}

// ServerInfo holds the identifying fields from the server's initialize response.
type ServerInfo struct {
	Name    string
	Version string
	Title   string
}

// Tool is a callable function exposed by an MCP server.
type Tool struct {
	Name        string
	Description string
	InputSchema map[string]interface{}
}

// Resource is a data source exposed by an MCP server.
type Resource struct {
	URI         string
	Name        string
	MimeType    string
	Description string
}

// Prompt is a reusable prompt template exposed by an MCP server.
type Prompt struct {
	Name        string
	Description string
	Arguments   []PromptArgument
}

// PromptArgument is a named parameter for a prompt template.
type PromptArgument struct {
	Name     string
	Required bool
}

// Initialize performs the MCP initialize handshake and returns a Session.
// It tries candidate endpoints until one succeeds.
func (c *Client) Initialize(ctx context.Context) (*Session, error) {
	candidates := endpoint.Candidates(c.baseURL, candidatePaths)
	for _, ep := range candidates {
		session, err := c.tryInitialize(ctx, ep)
		if err == nil {
			return session, nil
		}
	}
	return nil, fmt.Errorf("no MCP server found at %s (tried %v)", c.baseURL, candidates)
}

// ListTools calls tools/list and returns all available tools.
func (c *Client) ListTools(ctx context.Context, s *Session) ([]Tool, error) {
	resp, err := c.post(ctx, s, map[string]interface{}{
		"jsonrpc": "2.0", "id": 10, "method": "tools/list", "params": map[string]interface{}{},
	})
	if err != nil {
		return nil, err
	}

	var body map[string]interface{}
	if err := json.Unmarshal(resp, &body); err != nil {
		return nil, err
	}
	result, _ := body["result"].(map[string]interface{})
	rawTools, _ := result["tools"].([]interface{})

	var tools []Tool
	for _, t := range rawTools {
		tm, ok := t.(map[string]interface{})
		if !ok {
			continue
		}
		tool := Tool{
			Name:        strField(tm, "name"),
			Description: strField(tm, "description"),
		}
		if schema, ok := tm["inputSchema"].(map[string]interface{}); ok {
			tool.InputSchema = schema
		}
		tools = append(tools, tool)
	}
	return tools, nil
}

// ListResources calls resources/list and returns all available resources.
func (c *Client) ListResources(ctx context.Context, s *Session) ([]Resource, error) {
	resp, err := c.post(ctx, s, map[string]interface{}{
		"jsonrpc": "2.0", "id": 11, "method": "resources/list", "params": map[string]interface{}{},
	})
	if err != nil {
		return nil, err
	}

	var body map[string]interface{}
	if err := json.Unmarshal(resp, &body); err != nil {
		return nil, err
	}
	// JSON-RPC error means resources are not supported or access was denied.
	if _, hasErr := body["error"]; hasErr {
		return nil, nil
	}
	result, _ := body["result"].(map[string]interface{})
	rawResources, _ := result["resources"].([]interface{})

	var resources []Resource
	for _, r := range rawResources {
		rm, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		resources = append(resources, Resource{
			URI:         strField(rm, "uri"),
			Name:        strField(rm, "name"),
			MimeType:    strField(rm, "mimeType"),
			Description: strField(rm, "description"),
		})
	}
	return resources, nil
}

// ListPrompts calls prompts/list and returns all available prompt templates.
func (c *Client) ListPrompts(ctx context.Context, s *Session) ([]Prompt, error) {
	resp, err := c.post(ctx, s, map[string]interface{}{
		"jsonrpc": "2.0", "id": 12, "method": "prompts/list", "params": map[string]interface{}{},
	})
	if err != nil {
		return nil, err
	}

	var body map[string]interface{}
	if err := json.Unmarshal(resp, &body); err != nil {
		return nil, err
	}
	if _, hasErr := body["error"]; hasErr {
		return nil, nil
	}
	result, _ := body["result"].(map[string]interface{})
	rawPrompts, _ := result["prompts"].([]interface{})

	var prompts []Prompt
	for _, p := range rawPrompts {
		pm, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		prompt := Prompt{
			Name:        strField(pm, "name"),
			Description: strField(pm, "description"),
		}
		if args, ok := pm["arguments"].([]interface{}); ok {
			for _, a := range args {
				am, ok := a.(map[string]interface{})
				if !ok {
					continue
				}
				req, _ := am["required"].(bool)
				prompt.Arguments = append(prompt.Arguments, PromptArgument{
					Name:     strField(am, "name"),
					Required: req,
				})
			}
		}
		prompts = append(prompts, prompt)
	}
	return prompts, nil
}

// tryInitialize attempts the full MCP handshake against a single endpoint.
func (c *Client) tryInitialize(ctx context.Context, ep string) (*Session, error) {
	body, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2025-03-26",
			"capabilities": map[string]interface{}{
				"tools":     map[string]interface{}{},
				"resources": map[string]interface{}{},
				"prompts":   map[string]interface{}{},
			},
			"clientInfo": map[string]interface{}{"name": "batesian", "version": "1.0"},
		},
	})

	req, err := c.newRequest(ctx, ep, body)
	if err != nil {
		return nil, err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, ep)
	}

	sessionID := resp.Header.Get("Mcp-Session-Id")
	respBody := readBody(resp)

	var parsed map[string]interface{}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, fmt.Errorf("non-JSON response from %s", ep)
	}

	result, _ := parsed["result"].(map[string]interface{})
	if result == nil {
		return nil, fmt.Errorf("missing result in initialize response from %s", ep)
	}
	if _, ok := result["protocolVersion"]; !ok {
		return nil, fmt.Errorf("response from %s is not an MCP initialize response", ep)
	}

	si, _ := result["serverInfo"].(map[string]interface{})
	caps, _ := result["capabilities"].(map[string]interface{})

	session := &Session{
		Endpoint:        ep,
		SessionID:       sessionID,
		ProtocolVersion: strField(result, "protocolVersion"),
		ServerInfo: ServerInfo{
			Name:    strField(si, "name"),
			Version: strField(si, "version"),
			Title:   strField(si, "title"),
		},
		Capabilities: caps,
	}

	// Send notifications/initialized (fire and forget; ignore errors).
	notif, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	})
	notifReq, _ := c.newRequest(ctx, ep, notif)
	if sessionID != "" {
		notifReq.Header.Set("Mcp-Session-Id", sessionID)
	}
	resp2, _ := c.http.Do(notifReq)
	if resp2 != nil {
		resp2.Body.Close()
	}

	return session, nil
}

// post sends a JSON-RPC POST to the session endpoint with the session ID header.
func (c *Client) post(ctx context.Context, s *Session, payload interface{}) ([]byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := c.newRequest(ctx, s.Endpoint, body)
	if err != nil {
		return nil, err
	}
	if s.SessionID != "" {
		req.Header.Set("Mcp-Session-Id", s.SessionID)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return readBody(resp), nil
}

// newRequest builds an HTTP POST with the standard MCP headers.
func (c *Client) newRequest(ctx context.Context, ep string, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("User-Agent", "batesian/dev (https://github.com/calbebop/batesian)")
	if c.bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearerToken)
	}
	return req, nil
}

// readBody reads the response body, handling both plain JSON and SSE streams.
// For SSE, it extracts the payload from the first "data:" line.
func readBody(resp *http.Response) []byte {
	ct := resp.Header.Get("Content-Type")
	if strings.Contains(ct, "text/event-stream") {
		return readFirstSSEData(resp.Body)
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	return b
}

// readFirstSSEData returns the joined payload of the first SSE event from r,
// rejoining a payload split across several "data:" lines. The stream is not
// drained. A read error maps to a nil body.
func readFirstSSEData(r io.Reader) []byte {
	payload, _ := sse.FirstData(r, maxBodyBytes)
	return payload
}

// HasCapability returns true if the session's capability map includes the key.
func (s *Session) HasCapability(key string) bool {
	if s.Capabilities == nil {
		return false
	}
	_, ok := s.Capabilities[key]
	return ok
}

func strField(m map[string]interface{}, key string) string {
	v, _ := m[key].(string)
	return v
}
