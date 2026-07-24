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
	// ProtocolVersion is the MCP version in effect for this session: the
	// protocolVersion the server returned in its initialize result, or the
	// offered version if the server did not echo one. Sent on subsequent
	// requests via the Mcp-Protocol-Version header.
	ProtocolVersion string
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

// header returns the headers that must accompany subsequent MCP requests on this
// session: Mcp-Protocol-Version (Streamable HTTP servers validate it to route
// and may reject requests that omit it) and, when the server issued one,
// Mcp-Session-Id. Returns nil if neither applies (older servers, test servers).
func (s mcpSession) header() map[string]string {
	h := map[string]string{}
	if s.ProtocolVersion != "" {
		h["Mcp-Protocol-Version"] = s.ProtocolVersion
	}
	if s.SessionID != "" {
		h["Mcp-Session-Id"] = s.SessionID
	}
	if len(h) == 0 {
		return nil
	}
	return h
}

// latestStable is the MCP protocol version offered in initialize requests. The
// spec says clients should offer the latest version they support; the server
// negotiates by responding with its own version. Offering a stale version risks
// an "Unsupported protocol version" rejection on current servers (a silent
// false negative), so this stays current.
const latestStable = "2025-06-18"

// negotiatedVersion reads the protocolVersion the server chose from its
// initialize result body, falling back to latestStable if the server did not
// echo one. The negotiated value is sent in the Mcp-Protocol-Version header on
// subsequent requests.
func negotiatedVersion(initBody []byte) string {
	var body struct {
		Result struct {
			ProtocolVersion string `json:"protocolVersion"`
		} `json:"result"`
	}
	if json.Unmarshal(initBody, &body) == nil && body.Result.ProtocolVersion != "" {
		return body.Result.ProtocolVersion
	}
	return latestStable
}
