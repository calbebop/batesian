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

// handshakeRefusal carries why an initialize handshake did not complete, in terms
// an operator can act on.
//
// It is a distinct type so inconclusive can tell a diagnosis apart from an
// internal error: only a refusal the walk actually classified reaches a scan
// report, and anything else collapses to the generic reachability message rather
// than leaking implementation detail as if it were a finding about the target.
type handshakeRefusal struct{ reason string }

func (h handshakeRefusal) Error() string { return h.reason }

// inconclusive converts an initializeMCP failure into the error a rule should
// return. Either way the rule was not exercised and the engine records it as
// skipped rather than clean, but a classified failure carries its reason forward
// so the operator learns what actually happened.
//
// The default message, "could not reach a testable endpoint", sends an operator to
// look at their network. That is right when nothing answered and wrong the rest of
// the time, and the most common wrong case is the ordinary one: scanning a server
// that requires a credential without passing one. The server answers every
// request, refuses the handshake, and twelve rules used to report it as
// unreachable.
func inconclusive(err error) error {
	if IsModernEraErr(err) {
		return fmt.Errorf("%w: %s", attack.ErrInconclusive, err)
	}
	var refusal handshakeRefusal
	if errors.As(err, &refusal) {
		return fmt.Errorf("%w: %s", attack.ErrInconclusive, refusal.reason)
	}
	return attack.ErrInconclusive
}

// How much a failed candidate tells us. The candidate list is walked in a fixed
// order (/mcp, /, /api, /rpc), so a 404 from a path the server does not serve can
// be seen before the auth refusal from the path it does. The reason therefore has
// to be ranked rather than last-one-wins, or the message depends on path order.
const (
	rankNothing = iota
	rankStatusOnly
	rankNotMCP
	rankRefused
	rankUnauthorized
)

// mcpCredentialNote is the shared note plus what it means for MCP specifically: a
// server that refuses an anonymous handshake does not serve the protocol
// anonymously at all, which is worth saying once rather than leaving the operator
// to infer it.
func mcpCredentialNote(credentialed bool) string {
	note := attack.CredentialNote(credentialed)
	if !credentialed {
		note += ", so this server does not serve MCP anonymously"
	}
	return note
}

// initObservation is the best explanation seen while walking the candidates.
type initObservation struct {
	rank   int
	reason string
}

// observe keeps o when it explains more than what is already held.
func (i *initObservation) observe(o initObservation) {
	if o.rank > i.rank {
		*i = o
	}
}

// classifyInitFailure explains why one candidate did not complete a handshake.
//
// The ranking is about what an operator can do next. An unauthorized refusal is
// the top rank because it points at the fix; "answered but does not implement
// initialize" is above a bare status because it says the target is not MCP at all
// rather than unreachable.
//
// credentialed says whether the refused request carried the operator's token,
// because a server refusing an anonymous handshake and a server rejecting the
// credential it was given call for opposite actions. The message states which
// happened and does not prescribe a flag: whether --token would change anything
// depends on the rule, and several of these rules send no credential by design.
func classifyInitFailure(endpoint string, credentialed bool, resp *attack.Response) initObservation {
	// A path the server does not serve explains nothing: the candidate walk exists
	// precisely because the endpoint is unknown, so most of these 404s are the cost
	// of looking rather than a fact about the target. Reporting one as the reason
	// would name an arbitrary candidate and frame a routing miss as a refused
	// handshake. When every candidate is absent, the generic reachability message is
	// the honest answer.
	if endpointAbsent(resp) {
		return initObservation{}
	}

	code, hasErr := jsonRPCErrorCode(resp.Body)
	msg := jsonRPCErrorMessage(resp.Body)

	// An auth refusal can arrive either as an HTTP status or as a JSON-RPC error at
	// HTTP 200, which is what the real SDKs do, so both shapes are checked.
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return initObservation{rankUnauthorized, fmt.Sprintf(
			"the MCP handshake at %s was refused with HTTP %d %s",
			endpoint, resp.StatusCode, mcpCredentialNote(credentialed))}
	}
	if hasErr && authFlavoredError(code, msg) {
		return initObservation{rankUnauthorized, fmt.Sprintf(
			"the MCP handshake at %s was refused as unauthorized (JSON-RPC %d: %q) %s",
			endpoint, code, msg, mcpCredentialNote(credentialed))}
	}
	if hasErr && code == mcpMethodNotFound {
		return initObservation{rankNotMCP, fmt.Sprintf(
			"%s answered but does not implement the MCP initialize method (JSON-RPC %d), so "+
				"nothing at this target speaks MCP", endpoint, code)}
	}
	if hasErr {
		return initObservation{rankRefused, fmt.Sprintf(
			"the MCP handshake at %s was refused (JSON-RPC %d: %q)", endpoint, code, msg)}
	}
	if !resp.IsSuccess() {
		return initObservation{rankStatusOnly, fmt.Sprintf(
			"the MCP handshake at %s was answered with HTTP %d and no JSON-RPC error",
			endpoint, resp.StatusCode)}
	}
	// HTTP 2xx, no JSON-RPC error, and yet not a handshake: something is there and
	// it is not answering as an MCP server.
	return initObservation{rankNotMCP, fmt.Sprintf(
		"%s answered the handshake with HTTP %d but the reply carried no protocolVersion, "+
			"serverInfo or capabilities, so it did not complete an MCP handshake",
		endpoint, resp.StatusCode)}
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

// modernWireAdvertised reports whether a server/discover reply lists the modern
// revision among the versions the server says it supports.
//
// Answering server/discover is not the same as serving the modern wire. The
// specification requires every server to implement the RPC, and describes
// supportedVersions as the list from which "the client should choose a version
// for use in subsequent requests". A server built on the Go SDK takes that
// literally: a handshake-only (non-stateless) deployment answers discovery with
// only 2025-era versions, then rejects any 2026-07-28 request with a plain-text
// HTTP 400 saying the version needs a stateless server. Keying on "discovery
// answered" read that refusal as an authorization refusal, and reported a
// critical era-downgrade bypass against a server enforcing no authorization at
// all.
//
// A reply without supportedVersions is not a DiscoverResult: the field is
// required in the specification and in all three official SDKs.
func modernWireAdvertised(body []byte) bool {
	var envelope struct {
		Result *struct {
			SupportedVersions []string `json:"supportedVersions"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil || envelope.Result == nil {
		return false
	}
	for _, v := range envelope.Result.SupportedVersions {
		if v == modernEraVersion {
			return true
		}
	}
	return false
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
// server/discover is the right probe because its reply names the versions the
// server serves, which is the question being asked. Answering it is not itself
// the signal: every server MUST implement the RPC, so a handshake-only server
// answers too and names only handshake-era versions. The classification follows
// the rule the Streamable HTTP binding gives for backward compatibility: attempt
// a modern request, and on a rejection inspect the body before concluding
// anything. A recognized modern error means the server speaks a modern revision
// (the client should correct its request rather than fall back); anything else
// means legacy.
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

	// A DiscoverResult that advertises the modern revision means the server
	// serves that wire. Discovery answering at all does not, because every
	// server implements the RPC whatever era it serves; see modernWireAdvertised.
	if resp.IsAccepted() && modernWireAdvertised(resp.Body) {
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
