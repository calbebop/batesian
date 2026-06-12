package mcp

import "encoding/json"

// candidatePaths are tried in order when discovering an MCP endpoint.
// Servers commonly mount the JSON-RPC handler at /mcp, /, /api, or /rpc.
var candidatePaths = []string{"/mcp", "/", "/api", "/rpc"}

// endpointCandidates returns candidate URLs to try for the given base URL.
func endpointCandidates(baseURL string) []string {
	out := make([]string, len(candidatePaths))
	for i, p := range candidatePaths {
		out[i] = baseURL + p
	}
	return out
}

// mcpSession holds the discovered MCP endpoint and the session ID returned by
// the server's initialize response. All subsequent JSON-RPC requests in the
// same MCP connection must echo the session ID via the Mcp-Session-Id header;
// servers that implement the MCP 2025-03-26 spec will reject requests that
// omit it with a 4xx error, which would cause all our rule checks to silently
// return no findings.
type mcpSession struct {
	Endpoint  string
	SessionID string
	// RawInit is the raw JSON body of the server's initialize response, captured
	// once during the handshake so executors can inspect advertised server
	// capabilities without issuing a second initialize.
	RawInit []byte
}

// ServerSupports reports whether the server's initialize response advertised the
// named capability (e.g. "prompts", "resources", "tools") under result.capabilities.
// It parses the structured capabilities object rather than substring-matching the
// whole body, so it won't false-match the word appearing in serverInfo or
// instructions text.
func (s mcpSession) ServerSupports(capability string) bool {
	if len(s.RawInit) == 0 {
		return false
	}
	var body struct {
		Result struct {
			Capabilities map[string]json.RawMessage `json:"capabilities"`
		} `json:"result"`
	}
	if err := json.Unmarshal(s.RawInit, &body); err != nil {
		return false
	}
	_, ok := body.Result.Capabilities[capability]
	return ok
}

// header returns the Mcp-Session-Id header map if a session ID is present,
// or nil if the server did not issue one (older servers, test servers).
func (s mcpSession) header() map[string]string {
	if s.SessionID == "" {
		return nil
	}
	return map[string]string{"Mcp-Session-Id": s.SessionID}
}
