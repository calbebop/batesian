package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

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

const headerMismatchCode = -32020

var errModernDiscoveryDenied = errors.New("modern MCP discovery denied")

// request builds the headers and body this session's era requires for one call.
// It is split out of post so postShaping can reshape the headers without
// duplicating the era rules.
func (s mcpSession) request(id interface{}, method string, params map[string]interface{}) (map[string]string, map[string]interface{}) {
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
				headers["Mcp-Name"] = encodeMCPHeaderValue(name)
			}
		}
	}
	if headers == nil {
		headers = map[string]string{}
	}

	return headers, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
		"params":  params,
	}
}

func (s mcpSession) toolRequest(id interface{}, params, schema map[string]interface{}) (map[string]string, map[string]interface{}, error) {
	headers, body := s.request(id, "tools/call", params)
	if s.Era != EraModern {
		return headers, body, nil
	}
	args, _ := params["arguments"].(map[string]interface{})
	paramHeaders, err := toolParamHeaders(schema, args)
	if err != nil {
		return nil, nil, err
	}
	for key, value := range paramHeaders {
		headers[key] = value
	}
	return headers, body, nil
}

func encodeMCPHeaderValue(value string) string {
	needsEncoding := strings.HasPrefix(value, "=?base64?") && strings.HasSuffix(value, "?=")
	if value != "" && (value[0] == ' ' || value[0] == '\t' || value[len(value)-1] == ' ' || value[len(value)-1] == '\t') {
		needsEncoding = true
	}
	for i := 0; !needsEncoding && i < len(value); i++ {
		b := value[i]
		if b != '\t' && (b < 0x20 || b > 0x7e) {
			needsEncoding = true
		}
	}
	if !needsEncoding {
		return value
	}
	return "=?base64?" + base64.StdEncoding.EncodeToString([]byte(value)) + "?="
}

// post sends a JSON-RPC request on whichever wire this session belongs to,
// building the headers and params each era requires.
func (s mcpSession) post(ctx context.Context, client *attack.HTTPClient, id interface{}, method string, params map[string]interface{}) (*attack.Response, error) {
	headers, body := s.request(id, method, params)
	return client.POST(ctx, s.Endpoint, headers, body)
}

// postShaping is post for a rule that must send a deliberately malformed request.
// shape receives the headers this era would have sent and may change or delete
// any of them, which is how the SEP-2243 rule omits or mismatches Mcp-Method
// without also having to rebuild the _meta block the era requires.
func (s mcpSession) postShaping(ctx context.Context, client *attack.HTTPClient, id interface{}, method string,
	params map[string]interface{}, shape func(map[string]string)) (*attack.Response, error) {
	headers, body := s.request(id, method, params)
	if shape != nil {
		shape(headers)
	}
	return client.POST(ctx, s.Endpoint, headers, body)
}

func (s mcpSession) postToolShaping(ctx context.Context, client *attack.HTTPClient, id interface{},
	params, schema map[string]interface{}, shape func(map[string]string)) (*attack.Response, error) {
	headers, body, err := s.toolRequest(id, params, schema)
	if err != nil {
		return nil, err
	}
	if shape != nil {
		shape(headers)
	}
	return client.POST(ctx, s.Endpoint, headers, body)
}

func isMCPHeaderMismatch(resp *attack.Response) bool {
	if resp == nil || resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return false
	}
	code, ok := jsonRPCErrorCode(resp.Body)
	return ok && code == headerMismatchCode
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

// openSessions resolves both wires. An unjudged modern discovery leaves a
// legacy session usable but makes the combined result incomplete.
func openSessions(ctx context.Context, client *attack.HTTPClient, baseURL string) ([]mcpSession, error) {
	var out []mcpSession

	legacy, legacyErr := initializeMCP(ctx, client, baseURL)

	endpoints := modernDiscoveryEndpoints(baseURL, "")
	if legacyErr == nil {
		legacy.Era = EraLegacy
		out = append(out, legacy)
		endpoints = modernDiscoveryEndpoints(baseURL, legacy.Endpoint)
	}

	var discoveryErr error
	for _, ep := range endpoints {
		modern, ok, discoverErr := discoverModern(ctx, client, ep)
		discoveryErr = errors.Join(discoveryErr, discoverErr)
		if ok {
			out = append(out, modern)
			break
		}
	}

	if len(out) == 0 {
		if errors.Is(discoveryErr, errModernDiscoveryDenied) {
			return nil, errors.Join(inconclusive(legacyErr), discoveryErr)
		}
		return nil, inconclusive(legacyErr)
	}
	return out, discoveryErr
}

// A bare origin may host the two wires at different conventional paths. An
// explicit endpoint is kept narrow so a scan does not cross into sibling APIs.
func modernDiscoveryEndpoints(baseURL, legacyEndpoint string) []string {
	if legacyEndpoint == "" {
		candidates := endpointCandidates(baseURL)
		if len(candidates) == 0 {
			return nil
		}
		legacyEndpoint = candidates[0]
	}
	u, err := url.Parse(baseURL)
	if err != nil || strings.Trim(u.Path, "/") != "" {
		return []string{legacyEndpoint}
	}
	endpoints := []string{legacyEndpoint}
	for _, ep := range endpointCandidates(baseURL) {
		if ep != legacyEndpoint {
			endpoints = append(endpoints, ep)
		}
	}
	return endpoints
}

// discoverModern asks ep for a modern DiscoverResult and builds a session from it.
//
// server/discover is not required before calling a method, but it is what reports
// the server's capabilities, and the rules that gate on a capability need them.
// The result carries them under the same result.capabilities path an initialize
// result uses, so ServerSupports reads either without knowing the difference.
//
// A reply is only taken as a modern wire when it advertises the modern revision
// in its own supportedVersions. Every server implements server/discover whatever
// era it serves, so answering it proves nothing on its own; see
// modernWireAdvertised for what treating the answer as proof cost.
func discoverModern(ctx context.Context, client *attack.HTTPClient, ep string) (mcpSession, bool, error) {
	// An earlier rule's refusal does not establish this rule's access.
	probe := mcpSession{Endpoint: ep, Era: EraModern}
	resp, err := probe.post(ctx, client, "batesian-discover", "server/discover", nil)
	if err != nil || resp == nil {
		return mcpSession{}, false, fmt.Errorf("%w: modern MCP discovery did not answer", attack.ErrInconclusive)
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return mcpSession{}, false, fmt.Errorf("%w: %w: modern MCP discovery returned HTTP %d",
			attack.ErrInconclusive, errModernDiscoveryDenied, resp.StatusCode)
	}
	if resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests ||
		resp.StatusCode >= http.StatusInternalServerError {
		return mcpSession{}, false, fmt.Errorf("%w: modern MCP discovery returned HTTP %d",
			attack.ErrInconclusive, resp.StatusCode)
	}
	if !resp.IsSuccess() {
		return mcpSession{}, false, nil
	}
	if resp.StatusCode == http.StatusAccepted && len(resp.Body) == 0 {
		return mcpSession{}, false, nil
	}
	body, parsed := parseResponseBody(resp.Body)
	if !parsed {
		return mcpSession{}, false, fmt.Errorf("%w: modern MCP discovery returned an unmatched or invalid JSON-RPC response",
			attack.ErrInconclusive)
	}
	if validRPCError(body) && matchesRPCStringID(body, "batesian-discover") {
		rpcErr := body["error"].(map[string]interface{})
		msg, _ := rpcErr["message"].(string)
		if authFlavoredError(rpcErrorCode(rpcErr["code"]), msg) {
			return mcpSession{}, false, fmt.Errorf("%w: %w: modern MCP discovery rejected authorization",
				attack.ErrInconclusive, errModernDiscoveryDenied)
		}
	}
	if !modernWireAdvertised(resp.Body) {
		return mcpSession{}, false, nil
	}
	if !matchesRPCStringID(body, "batesian-discover") || !validRPCResult(body) {
		return mcpSession{}, false, fmt.Errorf("%w: modern MCP discovery returned an unmatched or invalid JSON-RPC response",
			attack.ErrInconclusive)
	}
	return mcpSession{
		Endpoint:        ep,
		Era:             EraModern,
		ProtocolVersion: modernEraVersion,
		RawInit:         resp.Body,
	}, true, nil
}

// runOnEachWire opens every wire the target serves and runs probe against each,
// returning the findings from all of them.
//
// A server that serves both eras is exposed on both, and the two need not behave
// alike, so each is exercised. Findings from the modern wire are labelled; see
// labelEra.
//
// probe reports whether it established a verdict on that wire. A clean result
// requires a verdict from every served wire.
//
// Findings survive an undetermined wire, but the rule outcome stays incomplete.
func runOnEachWire(ctx context.Context, client *attack.HTTPClient, baseURL string,
	probe func(mcpSession) ([]attack.Finding, bool)) ([]attack.Finding, error) {
	sessions, sessionErr := openSessions(ctx, client, baseURL)
	return runOnSessions(sessions, sessionErr, baseURL, probe)
}

// runOnEachWireWithDirect tries a read-only modern list after discovery denies
// anonymous access. Modern-only result fields distinguish MCP from a generic
// JSON-RPC service; an unrecognized reply stays inconclusive.
func runOnEachWireWithDirect(ctx context.Context, client *attack.HTTPClient, baseURL, method, field string,
	probe func(mcpSession) ([]attack.Finding, bool)) ([]attack.Finding, error) {
	sessions, sessionErr := openSessions(ctx, client, baseURL)
	modernSeen := false
	legacyEndpoint := ""
	for _, session := range sessions {
		if session.Era == EraModern {
			modernSeen = true
		} else {
			legacyEndpoint = session.Endpoint
		}
	}
	if !modernSeen && errors.Is(sessionErr, errModernDiscoveryDenied) {
		endpoints := modernDiscoveryEndpoints(baseURL, "")
		if legacyEndpoint != "" {
			endpoints = modernDiscoveryEndpoints(baseURL, legacyEndpoint)
		}
		for _, ep := range endpoints {
			_, _, discoverErr := discoverModern(ctx, client, ep)
			if !errors.Is(discoverErr, errModernDiscoveryDenied) {
				continue
			}
			if modern, ok := directModernList(ctx, client, ep, method, field); ok {
				sessions = append(sessions, modern)
				sessionErr = nil
				break
			}
		}
	}
	return runOnSessions(sessions, sessionErr, baseURL, probe)
}

func directModernList(ctx context.Context, client *attack.HTTPClient, endpoint, method, field string) (mcpSession, bool) {
	session := mcpSession{Endpoint: endpoint, Era: EraModern, ProtocolVersion: modernEraVersion}
	resp, err := session.post(ctx, client, 2, method, nil)
	verdict, body := classifyProbe(resp, err, 2)
	if verdict != probeAnswered || !validRPCResult(body) {
		return mcpSession{}, false
	}
	result, ok := body["result"].(map[string]interface{})
	if !ok || result["resultType"] != "complete" {
		return mcpSession{}, false
	}
	if _, ok := result[field].([]interface{}); !ok {
		return mcpSession{}, false
	}
	ttl, ok := result["ttlMs"].(json.Number)
	if !ok {
		return mcpSession{}, false
	}
	millis, err := strconv.ParseInt(ttl.String(), 10, 64)
	if err != nil || millis < 0 {
		return mcpSession{}, false
	}
	if result["cacheScope"] != "public" && result["cacheScope"] != "private" {
		return mcpSession{}, false
	}
	session.directProof = true
	return session, true
}

func runOnSessions(sessions []mcpSession, sessionErr error, baseURL string,
	probe func(mcpSession) ([]attack.Finding, bool)) ([]attack.Finding, error) {
	if len(sessions) == 0 {
		return nil, sessionErr
	}
	var out []attack.Finding
	var undetermined []string
	for _, s := range sessions {
		findings, determined := probe(s)
		if !determined {
			undetermined = append(undetermined, fmt.Sprintf("%s (%s)", s.Era, s.Endpoint))
		}
		out = append(out, labelEra(s, findings)...)
	}
	if len(undetermined) > 0 {
		return out, errors.Join(sessionErr, fmt.Errorf("%w: the MCP handshake succeeded at %s, but no protocol-level verdict "+
			"from %s wire(s)", attack.ErrInconclusive, baseURL, strings.Join(undetermined, ", ")))
	}
	return out, sessionErr
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
