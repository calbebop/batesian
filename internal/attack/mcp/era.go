package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/calbebop/batesian/internal/attack"
)

// errModernEra marks a target that answered as a modern-era MCP server. It is
// returned by initializeMCP instead of a generic "not found", so a rule can
// report the target as speaking an unsupported protocol version rather than as
// unreachable. Callers match it with errors.Is.
var errModernEra = errors.New("server implements a protocol era these rules do not support")

// IsModernEraErr reports whether err indicates the target is a modern-era MCP
// server rather than an unreachable one.
func IsModernEraErr(err error) bool { return errors.Is(err, errModernEra) }

// inconclusive converts an initializeMCP failure into the error a rule should
// return. Either way the rule was not exercised and the engine records it as
// skipped rather than clean, but a modern-era target carries its reason forward
// so the operator learns the protocol version is unsupported instead of being
// told only that nothing was reachable.
func inconclusive(err error) error {
	if IsModernEraErr(err) {
		return fmt.Errorf("%w: %s", attack.ErrInconclusive, err)
	}
	return attack.ErrInconclusive
}

// MCP split into two incompatible eras. Revisions up to 2025-11-25 ("legacy")
// open with an initialize handshake and carry an Mcp-Session-Id. Revision
// 2026-07-28 ("modern") is stateless: it removes initialize, sessions, the GET
// stream and Last-Event-ID, and instead carries the protocol version and client
// capabilities in each request's _meta.
//
// This rule set targets the legacy era. Era detection exists so a modern server
// is reported as unsupported rather than as unreachable, which is the difference
// between an operator seeing "this scanner does not speak your protocol version"
// and a bare "could not connect".

// Era identifies which protocol era a server implements.
type Era int

const (
	// EraUnknown means nothing answered, so no era could be determined.
	EraUnknown Era = iota
	// EraLegacy is the handshake-based revisions, 2025-11-25 and earlier.
	EraLegacy
	// EraModern is the stateless revisions, 2026-07-28 and later.
	EraModern
)

func (e Era) String() string {
	switch e {
	case EraLegacy:
		return "legacy"
	case EraModern:
		return "modern"
	default:
		return "unknown"
	}
}

// modernEraVersion is the protocol version offered when probing for a modern
// server. It is deliberately separate from latestStable (the version offered in
// legacy initialize handshakes) and from init_downgrade's modernVersion, which
// means the revision that first mandated authorization.
const modernEraVersion = "2026-07-28"

// _meta keys the modern era requires on every request. protocolVersion and
// clientCapabilities are both mandatory; a request missing either is malformed
// and a compliant server rejects it with -32602.
const (
	metaProtocolVersion    = "io.modelcontextprotocol/protocolVersion"
	metaClientInfo         = "io.modelcontextprotocol/clientInfo"
	metaClientCapabilities = "io.modelcontextprotocol/clientCapabilities"
)

// The MCP specification reserves JSON-RPC error codes -32020 to -32099 for
// itself, and states that implementations MUST NOT emit a code from that range
// unless the specification defines it. Codes -32000 to -32019 are explicitly
// legacy and implementation-defined, carrying no agreed meaning.
//
// That split is what makes era detection reliable: a code inside the reserved
// range can only have come from a server implementing a modern revision, while
// an implementation-defined code says nothing about era. The reference server
// answers a modern probe with -32000 "Server not initialized", so keying on
// "did I get a JSON-RPC error?" alone would misclassify it as modern.
const (
	modernErrCodeMin = -32099
	modernErrCodeMax = -32020
)

// The codes the specification currently defines in the reserved range.
// Detection deliberately keys on the range rather than this list, so a code the
// specification adds later is still recognized as modern. The list exists so a
// test can assert every named code really does fall inside the range that
// isModernError accepts: if the two ever disagree, detection would miss a
// server that identified itself with a code the specification defines.
var specDefinedModernErrors = map[string]int{
	"HeaderMismatch":                  -32020,
	"MissingRequiredClientCapability": -32021,
	"UnsupportedProtocolVersion":      -32022,
}

// isModernError reports whether a response body carries a JSON-RPC error whose
// code falls in the range the MCP specification reserves for itself.
func isModernError(body []byte) bool {
	code, ok := jsonRPCErrorCode(body)
	if !ok {
		return false
	}
	return code >= modernErrCodeMin && code <= modernErrCodeMax
}

// jsonRPCErrorCode extracts the numeric code from a JSON-RPC error envelope.
// ok is false when the body is not JSON, carries no error object, or the error
// has no numeric code.
func jsonRPCErrorCode(body []byte) (int, bool) {
	var envelope struct {
		Error *struct {
			Code *float64 `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return 0, false
	}
	if envelope.Error == nil || envelope.Error.Code == nil {
		return 0, false
	}
	return int(*envelope.Error.Code), true
}

// detectEra determines which protocol era the server at endpoint implements by
// sending a modern server/discover request and classifying the reply.
//
// server/discover is the right probe because a modern server MUST implement it,
// so its absence is itself diagnostic. The classification follows the rule the
// Streamable HTTP binding gives for backward compatibility: attempt a modern
// request, and on a rejection inspect the body before concluding anything. A
// recognized modern error means the server speaks a modern revision (the client
// should correct its request rather than fall back); anything else means legacy.
//
// Only a transport failure yields EraUnknown. Any HTTP reply, including 404 or
// 405, tells us something answered, and absent a modern error that answer is
// legacy.
func detectEra(ctx context.Context, client *attack.HTTPClient, endpoint string) Era {
	headers := map[string]string{
		// Both are REQUIRED on every modern POST. Omitting them would earn a
		// -32020 HeaderMismatch, which is itself a modern signal, but sending
		// them correctly keeps the probe a fair test of the server rather than
		// of our own request.
		"MCP-Protocol-Version": modernEraVersion,
		"Mcp-Method":           "server/discover",
	}
	resp, err := client.POST(ctx, endpoint, headers, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "batesian-era-probe",
		"method":  "server/discover",
		"params": map[string]interface{}{
			"_meta": map[string]interface{}{
				metaProtocolVersion: modernEraVersion,
				metaClientInfo: map[string]interface{}{
					"name":    "batesian",
					"version": attack.Version,
				},
				// Required, and deliberately empty: this probe asks only what
				// the server is, so it needs no client capability.
				metaClientCapabilities: map[string]interface{}{},
			},
		},
	})
	if err != nil {
		return EraUnknown
	}

	// A DiscoverResult means the server implements the modern discovery RPC.
	if resp.IsAccepted() {
		return EraModern
	}
	// A spec-reserved error code can only come from a modern server, whatever
	// the HTTP status carrying it.
	if isModernError(resp.Body) {
		return EraModern
	}
	// Something answered, but not as a modern server would.
	return EraLegacy
}
