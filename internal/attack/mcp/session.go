package mcp

import (
	"context"
	"encoding/json"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/endpoint"
)

// candidatePaths are tried in order when discovering an MCP endpoint.
// Servers commonly mount the JSON-RPC handler at /mcp, /, /api, or /rpc.
var candidatePaths = []string{"/mcp", "/", "/api", "/rpc"}

// endpointCandidates returns candidate URLs to try for the given base URL. A
// target that already names a path is probed as given before the conventional
// paths are appended to it; see endpoint.Candidates.
func endpointCandidates(baseURL string) []string {
	return endpoint.Candidates(baseURL, candidatePaths)
}

// probeCandidates runs probe against each candidate endpoint under baseURL and
// returns the first findings produced.
//
// probe reports whether the candidate answered as an MCP endpoint, and the walk
// stops there whether or not that candidate yielded a finding. The candidate list
// exists to locate the server, not to test several of them: once a path has
// answered, the remaining candidates are the same server at paths it does not
// serve, so probing them buys 404s rather than coverage. Measured against
// @modelcontextprotocol/server-everything, that walk was 30% of a scan's requests.
//
// When no candidate answers, the rule was never exercised, which is
// ErrInconclusive rather than a clean pass.
func probeCandidates(baseURL string, probe func(endpoint string) ([]attack.Finding, bool)) ([]attack.Finding, error) {
	for _, ep := range endpointCandidates(baseURL) {
		findings, reached := probe(ep)
		if findings != nil {
			return findings, nil
		}
		if reached {
			return nil, nil
		}
	}
	return nil, attack.ErrInconclusive
}

// oauthNotApplicable converts an OAuth-gated rule's "no OAuth surface here" into
// the right answer for the caller.
//
// These rules gate on an OAuth surface: an authorization-server document, a
// protected-resource document, a registration endpoint. When none is reachable
// they used to report a clean pass, which covers two different situations. An MCP
// server that exposes no OAuth is genuinely not applicable, and clean is honest.
// A target where nothing answered at all was never exercised, and clean there
// says the OAuth handling is sound about a host the rule never reached.
//
// Reachability is settled with responsiveMCP, one request per candidate, stopping
// at the first that answers. On a server mounted at /mcp that is a single extra
// request, paid only on the path where the rule was about to bail. Era detection
// runs only when nothing answered, so a modern-era target is reported as speaking
// an unsupported protocol version rather than as unreachable.
func oauthNotApplicable(ctx context.Context, client *attack.HTTPClient, baseURL string) error {
	endpoints := endpointCandidates(baseURL)
	for _, ep := range endpoints {
		if responsiveMCP(ctx, client, ep) {
			return nil
		}
	}
	if err := modernEraReason(ctx, client, endpoints); err != nil {
		return inconclusive(err)
	}
	return attack.ErrInconclusive
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
	// Era is the wire this session speaks. The zero value, EraUnknown, behaves as
	// legacy so the handshake-based rules that predate era support are unchanged.
	Era Era
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
