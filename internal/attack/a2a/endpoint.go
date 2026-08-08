package a2a

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/endpoint"
)

// A2A agent cards declare where the JSON-RPC transport actually lives; it is not
// required to be at the target root. resolveA2AEndpoint discovers that endpoint
// the way a real client would, instead of assuming the root path. Without this,
// every JSON-RPC rule silently misses a spec-compliant server that mounts its
// JSON-RPC handler at, for example, /a2a/jsonrpc.

// a2aDiscoveryCard parses only the agent-card fields needed to locate the
// JSON-RPC endpoint, across both the v1.0 and v0.3 card shapes.
type a2aDiscoveryCard struct {
	// v1.0: each entry carries a protocolBinding ("JSONRPC" | "GRPC" | "HTTP+JSON").
	SupportedInterfaces []a2aDiscoveryInterface `json:"supportedInterfaces"`
	// v0.3: each entry carries a transport with the same vocabulary.
	AdditionalInterfaces []a2aDiscoveryInterface `json:"additionalInterfaces"`
	// v0.3 top-level service URL, usable only when preferredTransport is JSONRPC.
	PreferredTransport string `json:"preferredTransport"`
	URL                string `json:"url"`
}

type a2aDiscoveryInterface struct {
	URL string `json:"url"`
	// ProtocolBinding is the v1.0 field name; Transport is the v0.3 field name.
	ProtocolBinding string `json:"protocolBinding"`
	Transport       string `json:"transport"`
	ProtocolVersion string `json:"protocolVersion"`
}

func (i a2aDiscoveryInterface) isJSONRPC() bool {
	return strings.EqualFold(i.ProtocolBinding, "JSONRPC") || strings.EqualFold(i.Transport, "JSONRPC")
}

func (i a2aDiscoveryInterface) isHTTPJSON() bool {
	return strings.EqualFold(i.ProtocolBinding, "HTTP+JSON") || strings.EqualFold(i.Transport, "HTTP+JSON")
}

// resolveHTTPJSONBase returns the base URL of the card's HTTP+JSON (REST)
// interface, pinned to the target host, or "" when none is advertised.
//
// The REST binding's paths cannot be guessed. a2a-sdk mounts them under a
// caller-chosen prefix and lets the deployment decide which protocol version
// sits where, so on one server /message:send is the v1.0 route and
// /v1/message:send is the v0.3 compatibility route. The card is the only thing
// that says where the binding lives, and an agent that advertises no HTTP+JSON
// interface has none to probe.
func resolveHTTPJSONBase(ctx context.Context, client *attack.HTTPClient, baseURL string) string {
	card, found := fetchDiscoveryCard(ctx, client, baseURL)
	if !found {
		return ""
	}
	for _, group := range [][]a2aDiscoveryInterface{card.SupportedInterfaces, card.AdditionalInterfaces} {
		for _, iface := range group {
			if iface.isHTTPJSON() && hasHTTPScheme(iface.URL) {
				return strings.TrimSuffix(pinToTargetHost(iface.URL, baseURL), "/")
			}
		}
	}
	if strings.EqualFold(card.PreferredTransport, "HTTP+JSON") && hasHTTPScheme(card.URL) {
		return strings.TrimSuffix(pinToTargetHost(card.URL, baseURL), "/")
	}
	return ""
}

// resolveA2AEndpoint returns the JSON-RPC endpoint to probe and whether a usable
// endpoint was found. It prefers the URL the agent card declares for the JSON-RPC
// transport; failing that, it probes a small set of conventional paths. The
// returned endpoint is always pinned to the target's scheme+host (see
// pinToTargetHost), so a card that points elsewhere never redirects traffic off
// the operator's authorized target. When ok is false, no JSON-RPC endpoint
// responded and callers should not report the target as tested.
func resolveA2AEndpoint(ctx context.Context, client *attack.HTTPClient, baseURL string) (endpoint string, ok bool) {
	if card, found := fetchDiscoveryCard(ctx, client, baseURL); found {
		if cardURL := selectJSONRPCURL(card); cardURL != "" {
			// The card's path has to answer before it is returned as reachable.
			//
			// It used to be returned on trust, which broke the contract this
			// function's own doc comment states. A card advertises the URL clients
			// reach the agent on, which for anything behind a proxy is not the path
			// the operator is scanning: an agent published at
			// https://public.example/a2a/v1 may be mounted at / on the origin. The
			// card URL then 404s, the candidate walk that would have found / was
			// skipped, and ok=true told a dozen rules their failed probes were a
			// tested-clean result. Measured against a wide-open agent in exactly
			// that shape: two POSTs to the dead path, nothing reached the handler,
			// and a-task-idor reported clean.
			//
			// A card that declares a JSONRPC interface is itself A2A evidence, so the
			// declared path only has to ANSWER; it need not prove A2A again. That
			// keeps an auth-gated agent discoverable, since its 401 is weak evidence
			// alone but the card corroborates it.
			pinned := pinToTargetHost(cardURL, baseURL)
			if probeA2AEvidence(ctx, client, pinned) != a2aEvidenceNone {
				return pinned, true
			}
			// Fall through: the card's claim did not hold at this host, so try the
			// conventional paths rather than reporting an unreachable endpoint.
		}
	}
	// Strong evidence is accepted outright. Weak evidence is remembered and
	// corroborated afterwards, so a single ambiguous candidate cannot decide it.
	weak := ""
	for _, ep := range candidateEndpoints(baseURL) {
		switch probeA2AEvidence(ctx, client, ep) {
		case a2aEvidenceStrong:
			return ep, true
		case a2aEvidenceWeak:
			if weak == "" {
				weak = ep
			}
		}
	}
	if weak != "" && !looksLikeMCPServer(ctx, client, baseURL, weak) {
		return weak, true
	}
	return baseURL + "/", false
}

// looksLikeMCPServer reports whether a path that gave only weak A2A evidence is in
// fact an MCP server. Weak evidence is accepted for A2A unless this says no.
//
// The check stays negative on purpose. A2A servers exist that implement neither
// task-get spelling, including two of this repository's own fixtures, so demanding
// positive A2A proof would lose them. What the previous code got wrong was WHEN it
// asked: only on the method-not-found branch, so a 401 and every other error code
// bypassed it.
//
// Two signals, both cheap and both MCP-specific:
//
//   - The path answers an MCP initialize with a protocolVersion. Conclusive, but
//     useless against a server that gates the handshake.
//   - The host advertises RFC 9728 protected-resource metadata, at the well-known
//     path or in a WWW-Authenticate challenge. That is the MCP authorization spec's
//     discovery mechanism and A2A does not use it. It is what identifies the
//     official C# SDK's OAuth-protected sample, which refuses every unauthenticated
//     request with a 401 and so offers no other evidence at all.
func looksLikeMCPServer(ctx context.Context, client *attack.HTTPClient, baseURL, endpoint string) bool {
	if answersMCPInitialize(ctx, client, endpoint) {
		return true
	}
	return servesMCPResourceMetadata(ctx, client, baseURL, endpoint)
}

// servesMCPResourceMetadata reports whether the host advertises RFC 9728
// protected-resource metadata, either at the well-known path or through a
// WWW-Authenticate challenge on the endpoint itself.
func servesMCPResourceMetadata(ctx context.Context, client *attack.HTTPClient, baseURL, endpoint string) bool {
	if resp, err := client.GET(ctx, baseURL+"/.well-known/oauth-protected-resource", nil); err == nil &&
		resp.IsSuccess() && resp.ContainsAny(`"resource"`, `"authorization_servers"`) {
		return true
	}
	// The challenge itself carries the pointer, which is how the C# sample answers.
	resp, err := client.POST(ctx, endpoint, nil, map[string]interface{}{
		"jsonrpc": "2.0", "id": "batesian-a2a-mcp-check", "method": "initialize",
		"params": map[string]interface{}{"protocolVersion": "2025-06-18",
			"capabilities": map[string]interface{}{},
			"clientInfo":   map[string]interface{}{"name": "batesian", "version": attack.Version}},
	})
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(resp.Headers.Get("WWW-Authenticate")), "resource_metadata")
}

// fetchDiscoveryCard retrieves and parses the public agent card, trying the v1.0
// well-known path then the v0.3 legacy path.
func fetchDiscoveryCard(ctx context.Context, client *attack.HTTPClient, baseURL string) (a2aDiscoveryCard, bool) {
	for _, path := range []string{"/.well-known/agent-card.json", "/.well-known/agent.json"} {
		resp, err := client.GET(ctx, baseURL+path, nil)
		if err != nil || !resp.IsSuccess() {
			continue
		}
		var card a2aDiscoveryCard
		if err := json.Unmarshal(resp.Body, &card); err != nil {
			continue
		}
		return card, true
	}
	return a2aDiscoveryCard{}, false
}

// selectJSONRPCURL picks the JSON-RPC service URL from a card. It checks the v1.0
// supportedInterfaces, then the v0.3 additionalInterfaces, then the v0.3
// top-level url (only when preferredTransport is JSONRPC). Scheme-less entries
// (e.g. a gRPC "host:port") are skipped, since the JSON-RPC probe needs http(s).
func selectJSONRPCURL(card a2aDiscoveryCard) string {
	for _, iface := range card.SupportedInterfaces {
		if iface.isJSONRPC() && hasHTTPScheme(iface.URL) {
			return iface.URL
		}
	}
	for _, iface := range card.AdditionalInterfaces {
		if iface.isJSONRPC() && hasHTTPScheme(iface.URL) {
			return iface.URL
		}
	}
	if strings.EqualFold(card.PreferredTransport, "JSONRPC") && hasHTTPScheme(card.URL) {
		return card.URL
	}
	return ""
}

// pinToTargetHost keeps the operator's target scheme+host and applies only the
// card URL's path when the card points at a different host. A same-host card URL
// is used verbatim. This prevents a card from redirecting scan traffic to a host
// the operator did not authorize.
func pinToTargetHost(cardURL, baseURL string) string {
	cu, err := url.Parse(cardURL)
	if err != nil {
		return baseURL + "/"
	}
	tu, err := url.Parse(baseURL)
	if err != nil {
		return cardURL
	}
	if strings.EqualFold(cu.Host, tu.Host) {
		return cardURL
	}
	pinned := *tu
	pinned.Path = cu.Path
	pinned.RawQuery = ""
	return pinned.String()
}

// candidatePaths lists JSON-RPC paths to probe when the card does not declare
// one. Root is first so servers that mount JSON-RPC at the root keep working.
var candidatePaths = []string{"/", "/a2a/jsonrpc", "/a2a", "/rpc"}

// candidateEndpoints returns the URLs to probe under baseURL. A target that
// already names a path is probed as given before these paths are appended to
// it; see endpoint.Candidates.
func candidateEndpoints(baseURL string) []string {
	return endpoint.Candidates(baseURL, candidatePaths)
}

// methodNotFound is the JSON-RPC code for an unimplemented method. It is the
// one error a task lookup can earn that says nothing about what the server is.
const methodNotFound = -32601

// probeJSONRPCEndpoint reports whether a path answers JSON-RPC as an A2A agent.
// It sends a read-only task lookup for a non-existent id and treats a JSON-RPC
// envelope (result or error) or an auth rejection (401/403) as a live endpoint;
// a 404 or transport error means this is not the endpoint.
//
// It tries both the v0.3 (tasks/get) and v1.0 (GetTask) method names, because a
// server that does not implement one may answer 404 for it while still being a
// JSON-RPC endpoint that handles the other. Probing only one method would miss
// such servers.
//
// Evidence is graded, because weak evidence let MCP servers through and that is
// what this function's own history is about. "Method not found" was already
// treated as weak, but two other shapes were not, and both were measured
// accepting the official MCP C# SDK as an A2A agent:
//
//   - Any JSON-RPC error other than -32601 was accepted, via a body check for the
//     string "jsonrpc" that every JSON-RPC message contains. The SDK answers an
//     A2A tasks/get with -32000 "Bad Request: A new session can only be created by
//     an initialize request... Include a valid Mcp-Session-Id header", which named
//     itself as MCP and was accepted anyway.
//   - A 401 or 403 was accepted outright. The SDK's OAuth-protected sample refuses
//     every unauthenticated request that way, so a secured MCP server was accepted
//     with no A2A evidence at all.
//
// In both cases roughly a dozen A2A rules then reported the target tested-and-clean.
//
// Strong evidence is a JSON-RPC result, or an error in A2A's own -32001..-32006
// range (TaskNotFound and friends) which only something implementing A2A produces.
// Everything else is weak and has to be corroborated by the caller; see
// resolveA2AEndpoint. The grading stays deliberately loose about requiring a
// task-shaped answer, because A2A servers exist that implement neither task-get
// spelling, including two of this repository's own fixtures.
// a2aEvidence grades what a candidate path revealed about being an A2A endpoint.
type a2aEvidence int

const (
	// a2aEvidenceNone: a 404 or a transport failure. Not the endpoint.
	a2aEvidenceNone a2aEvidence = iota
	// a2aEvidenceWeak: it answered, but in a way any JSON-RPC service could. An
	// auth rejection, a method-not-found, a transport-level error envelope.
	a2aEvidenceWeak
	// a2aEvidenceStrong: an answer only an A2A implementation produces.
	a2aEvidenceStrong
)

// a2aErrorCodeMin and a2aErrorCodeMax bound A2A's own application error codes
// (TaskNotFound -32001 through InvalidAgentResponse -32006). Standard JSON-RPC
// codes are excluded on purpose: every JSON-RPC service emits those.
const (
	a2aErrorCodeMax = -32001
	a2aErrorCodeMin = -32006
)

func probeA2AEvidence(ctx context.Context, client *attack.HTTPClient, endpoint string) a2aEvidence {
	probes := []struct {
		method  string
		headers map[string]string
	}{
		{"tasks/get", nil},
		{"GetTask", map[string]string{"A2A-Version": "1.0"}},
	}

	best := a2aEvidenceNone
	for _, p := range probes {
		resp, err := client.POST(ctx, endpoint, p.headers, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "batesian-a2a-discovery",
			"method":  p.method,
			"params":  map[string]interface{}{"id": "batesian-discovery-nonexistent", "historyLength": 1},
		})
		if err != nil || resp.StatusCode == 404 {
			continue
		}
		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			// Something is here and it wants credentials, but nothing says A2A.
			if best < a2aEvidenceWeak {
				best = a2aEvidenceWeak
			}
			continue
		}
		if resp.IsAccepted() {
			return a2aEvidenceStrong
		}
		if code, ok := jsonRPCErrorCode(resp.Body); ok {
			if code >= a2aErrorCodeMin && code <= a2aErrorCodeMax {
				return a2aEvidenceStrong
			}
			if best < a2aEvidenceWeak {
				best = a2aEvidenceWeak
			}
		}
	}
	return best
}

// answersMCPInitialize reports whether the endpoint identifies itself as an MCP
// server. MCP opens with an initialize handshake whose result carries a
// protocolVersion, and no A2A method produces that, so a valid MCP result here
// is conclusive.
//
// This is deliberately not the MCP package's initializeMCP, which does much more
// (candidate paths, session ids, protocol negotiation, era detection). All that
// is wanted here is a yes or no about one URL that has already been located.
func answersMCPInitialize(ctx context.Context, client *attack.HTTPClient, endpoint string) bool {
	resp, err := client.POST(ctx, endpoint, nil, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "batesian-a2a-discovery-mcp",
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]interface{}{},
			"clientInfo":      map[string]interface{}{"name": "batesian", "version": attack.Version},
		},
	})
	if err != nil || !resp.IsAccepted() {
		return false
	}
	return resp.ContainsAny(`"protocolVersion"`)
}

// jsonRPCErrorMessage extracts the message from a JSON-RPC error envelope, or ""
// when there is none. A2A defines no numeric auth code, so the message is what
// decides whether a refusal was about authorization.
func jsonRPCErrorMessage(body []byte) string {
	var envelope struct {
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil || envelope.Error == nil {
		return ""
	}
	return envelope.Error.Message
}

// jsonRPCErrorCode extracts the numeric code from a JSON-RPC error envelope. ok
// is false when the body is not JSON, carries no error object, or the error has
// no numeric code.
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

// hasHTTPScheme reports whether rawURL is an absolute http(s) URL.
func hasHTTPScheme(rawURL string) bool {
	u, err := url.Parse(rawURL)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}
