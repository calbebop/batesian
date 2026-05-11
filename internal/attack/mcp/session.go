package mcp

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
}

// header returns the Mcp-Session-Id header map if a session ID is present,
// or nil if the server did not issue one (older servers, test servers).
func (s mcpSession) header() map[string]string {
	if s.SessionID == "" {
		return nil
	}
	return map[string]string{"Mcp-Session-Id": s.SessionID}
}
