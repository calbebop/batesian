package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/calbebop/batesian/internal/attack"
)

// MCP carries the same methods over two incompatible wires, and a server may
// serve both. This file is the transport primitive that lets a rule drive either
// one without knowing which it is on.
//
// Legacy (2024-11-05 through 2025-11-25): an initialize handshake mints a session,
// and every later request echoes Mcp-Session-Id plus the negotiated
// Mcp-Protocol-Version.
//
// Modern (2026-07-28): no handshake and no session. Each request stands alone,
// carrying the protocol version and client capabilities in params._meta, and must
// mirror its own method into the Mcp-Method header. The requirements below were
// taken from the official Python SDK rather than from the specification text:
//
//   - Mcp-Method is mandatory. Omitting it earns -32020, the same code as a
//     mismatch.
//   - params._meta is mandatory. Omitting it earns -32602.
//   - MCP-Protocol-Version is what selects the wire. Omit it on an SDK server that
//     serves both and the request is answered by the legacy handler instead, which
//     is a quiet way to think you are testing one era while testing the other.
//   - No server/discover call is needed first. Methods work immediately.

// nameBearingMethods maps each modern-era method that addresses a named subject to
// the params field carrying that name, which the Mcp-Name header must mirror.
//
// Taken from the SDK's own NAME_BEARING_METHODS table rather than inferred: it is
// exactly three methods, and the server only checks the header when the body
// carries the field.
var nameBearingMethods = map[string]string{
	"tools/call":     "name",
	"prompts/get":    "name",
	"resources/read": "uri",
}

// post sends a JSON-RPC request on whichever wire this session belongs to,
// building the headers and params each era requires.
func (s mcpSession) post(ctx context.Context, client *attack.HTTPClient, id interface{}, method string, params map[string]interface{}) (*attack.Response, error) {
	if params == nil {
		params = map[string]interface{}{}
	}

	headers := s.header()
	if s.Era == EraModern {
		// Copy rather than mutate: callers reuse their params map across eras.
		withMeta := make(map[string]interface{}, len(params)+1)
		for k, v := range params {
			withMeta[k] = v
		}
		withMeta["_meta"] = modernMeta()
		params = withMeta

		headers = map[string]string{
			"MCP-Protocol-Version": modernEraVersion,
			"Mcp-Method":           method,
		}
		// Methods that address a named subject must mirror it into Mcp-Name as
		// well, and a mismatch is the same -32020 a wrong Mcp-Method earns. A rule
		// that omitted it would read that rejection as a server refusing the call
		// and report clean.
		if key, ok := nameBearingMethods[method]; ok {
			if name, ok := params[key].(string); ok && name != "" {
				headers["Mcp-Name"] = name
			}
		}
	}

	return client.POST(ctx, s.Endpoint, headers, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
		"params":  params,
	})
}

// modernMeta is the _meta block every modern request must carry. clientCapabilities
// is present and empty on purpose: the probes here ask what a server exposes, so
// they claim no capability of their own.
func modernMeta() map[string]interface{} {
	return map[string]interface{}{
		metaProtocolVersion: modernEraVersion,
		metaClientInfo: map[string]interface{}{
			"name":    "batesian",
			"version": attack.Version,
		},
		metaClientCapabilities: map[string]interface{}{},
	}
}

// openSessions returns one session per wire the target serves, in the order a
// rule should exercise them: legacy first, then modern.
//
// Both are returned when a server serves both, which is the default for a server
// built on the current SDKs. A rule that only walked the first wire would report
// on one era while the other went untested, and the two need not behave the same:
// a server can enforce authorization on one and not the other, which is the shape
// mcp-init-downgrade-001 already looks for across protocol versions.
//
// The error is ErrInconclusive when neither wire answered, carrying the reason
// from the legacy attempt so a modern-era detail is not lost.
func openSessions(ctx context.Context, client *attack.HTTPClient, baseURL string) ([]mcpSession, error) {
	var out []mcpSession

	legacy, legacyErr := initializeMCP(ctx, client, baseURL)

	// Where to look for a modern wire. A successful handshake already located the
	// server, so only that endpoint is probed; otherwise every candidate is tried,
	// which is also the path a modern-only server takes.
	endpoints := endpointCandidates(baseURL)
	if legacyErr == nil {
		legacy.Era = EraLegacy
		out = append(out, legacy)
		endpoints = []string{legacy.Endpoint}
	}

	for _, ep := range endpoints {
		if modern, ok := discoverModern(ctx, client, ep); ok {
			out = append(out, modern)
			break
		}
	}

	if len(out) == 0 {
		return nil, inconclusive(legacyErr)
	}
	return out, nil
}

// discoverModern asks ep for a modern DiscoverResult and builds a session from it.
//
// server/discover is not required before calling a method, but it is what reports
// the server's capabilities, and the rules that gate on a capability need them.
// The result carries them under the same result.capabilities path an initialize
// result uses, so ServerSupports reads either without knowing the difference.
func discoverModern(ctx context.Context, client *attack.HTTPClient, ep string) (mcpSession, bool) {
	probe := mcpSession{Endpoint: ep, Era: EraModern}
	resp, err := probe.post(ctx, client, "batesian-discover", "server/discover", nil)
	if err != nil || !resp.IsAccepted() {
		return mcpSession{}, false
	}
	if !resp.ContainsAny(`"capabilities"`, `"supportedVersions"`, `"resultType"`) {
		return mcpSession{}, false
	}
	return mcpSession{
		Endpoint:        ep,
		Era:             EraModern,
		ProtocolVersion: modernEraVersion,
		RawInit:         resp.Body,
	}, true
}

// runOnEachWire opens every wire the target serves and runs probe against each,
// returning the findings from all of them.
//
// A server that serves both eras is exposed on both, and the two need not behave
// alike, so each is exercised. Findings from the modern wire are labelled; see
// labelEra.
func runOnEachWire(ctx context.Context, client *attack.HTTPClient, baseURL string,
	probe func(mcpSession) []attack.Finding) ([]attack.Finding, error) {
	sessions, err := openSessions(ctx, client, baseURL)
	if err != nil {
		return nil, err
	}
	var out []attack.Finding
	for _, s := range sessions {
		out = append(out, labelEra(s, probe(s))...)
	}
	return out, nil
}

// labelEra tags findings produced on the modern wire, so that on a server serving
// both they are not read as duplicates of the legacy ones. It also tells an
// operator which surface to fix, which is the point: the two wires can differ.
//
// Legacy findings are returned untouched, so a scan of a legacy-only server, still
// the norm, reports exactly what it reported before.
func labelEra(session mcpSession, findings []attack.Finding) []attack.Finding {
	if session.Era != EraModern {
		return findings
	}
	for i := range findings {
		findings[i].Title += fmt.Sprintf(" [MCP %s wire]", modernEraVersion)
		findings[i].Evidence = fmt.Sprintf("wire: MCP %s (stateless)\n%s", modernEraVersion, findings[i].Evidence)
	}
	return findings
}

// modernResultPayload strips the envelope a modern result wraps its payload in.
//
// A 2026-07-28 result carries cacheScope, resultType, ttlMs and _meta alongside
// the fields a legacy result would have had. Rules that read a named field
// (result.tools, result.resources) are unaffected, but anything that treats the
// result object as the payload needs the envelope keys removed first.
func modernResultPayload(body []byte) (map[string]json.RawMessage, error) {
	var envelope struct {
		Result map[string]json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("parsing modern result: %w", err)
	}
	for _, k := range []string{"cacheScope", "resultType", "ttlMs", "_meta"} {
		delete(envelope.Result, k)
	}
	return envelope.Result, nil
}
