package a2a

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
	endpointpkg "github.com/calbebop/batesian/internal/endpoint"
)

// Agent cards may put JSON-RPC off the target root.

// a2aDiscoveryCard parses only the agent-card fields needed to locate the
// JSON-RPC endpoint, across both the v1.0 and v0.3 card shapes.
type a2aDiscoveryCard struct {
	// v1.0: each entry carries a protocolBinding ("JSONRPC" | "GRPC" | "HTTP+JSON").
	SupportedInterfaces []a2aDiscoveryInterface `json:"supportedInterfaces"`
	// v0.3: each entry carries a transport with the same vocabulary.
	AdditionalInterfaces []a2aDiscoveryInterface `json:"additionalInterfaces"`
	// v0.3 top-level URL; an omitted transport defaults to JSONRPC.
	PreferredTransport string `json:"preferredTransport"`
	URL                string `json:"url"`
}

type a2aDiscoveryInterface struct {
	URL string `json:"url"`
	// ProtocolBinding is the v1.0 field name; Transport is the v0.3 field name.
	ProtocolBinding string  `json:"protocolBinding"`
	Transport       string  `json:"transport"`
	ProtocolVersion string  `json:"protocolVersion"`
	Tenant          *string `json:"tenant"`
}

func (i a2aDiscoveryInterface) isJSONRPC() bool {
	return strings.EqualFold(i.ProtocolBinding, "JSONRPC") || strings.EqualFold(i.Transport, "JSONRPC")
}

func (i a2aDiscoveryInterface) isHTTPJSON() bool {
	return strings.EqualFold(i.ProtocolBinding, "HTTP+JSON") || strings.EqualFold(i.Transport, "HTTP+JSON")
}

const maxCardHTTPJSONBases = 16

// resolveHTTPJSONBases returns advertised REST bases on the target origin.
func resolveHTTPJSONBases(ctx context.Context, client *attack.HTTPClient, baseURL string) []string {
	card, found := fetchDiscoveryCard(ctx, client, baseURL)
	if !found {
		return nil
	}
	var bases []string
	seen := map[string]bool{}
	add := func(rawURL string, tenant *string) {
		if !hasHTTPScheme(rawURL) {
			return
		}
		base := strings.TrimSuffix(pinToTargetOrigin(rawURL, baseURL), "/")
		if seen[base] || len(bases) == maxCardHTTPJSONBases {
			return
		}
		seen[base] = true
		bases = append(bases, base)
		registerTenantRoute(ctx, base, "HTTP+JSON", tenant)
	}
	for _, group := range [][]a2aDiscoveryInterface{card.SupportedInterfaces, card.AdditionalInterfaces} {
		for _, iface := range group {
			if iface.isHTTPJSON() {
				add(iface.URL, iface.Tenant)
			}
		}
	}
	if strings.EqualFold(card.PreferredTransport, "HTTP+JSON") {
		add(card.URL, nil)
	}
	return bases
}

const maxCardJSONRPCProbes = 16

// resolveA2AEndpoint returns a reachable JSON-RPC URL on the target origin.
// Advertised interfaces take precedence over conventional paths.
func resolveA2AEndpoint(ctx context.Context, client *attack.HTTPClient, baseURL string) (endpoint string, ok bool) {
	if card, found := fetchDiscoveryCard(ctx, client, baseURL); found {
		seen := map[string]bool{}
		for _, iface := range jsonRPCInterfaces(card) {
			pinned := pinToTargetOrigin(iface.URL, baseURL)
			key := pinned
			if iface.Tenant != nil {
				key += "\x00" + *iface.Tenant
			}
			if seen[key] {
				continue
			}
			if len(seen) == maxCardJSONRPCProbes {
				break
			}
			seen[key] = true
			registerTenantRoute(ctx, pinned, "JSONRPC", iface.Tenant)
			// The card corroborates weak JSON-RPC or auth evidence.
			if probeA2AEvidence(ctx, client, pinned) != a2aEvidenceNone {
				return pinned, true
			}
		}
	}
	// Strong evidence is accepted outright. Weak evidence is remembered and
	// corroborated afterwards, so a single ambiguous candidate cannot decide it.
	weak := ""
	for _, ep := range candidateEndpoints(baseURL) {
		registerTenantRoute(ctx, ep, "JSONRPC", nil)
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
	return endpointpkg.AppendPath(baseURL, "/"), false
}

// looksLikeMCPServer rejects weak A2A evidence when MCP discovery or resource
// metadata identifies the target.
func looksLikeMCPServer(ctx context.Context, client *attack.HTTPClient, baseURL, endpoint string) bool {
	if answersMCPInitialize(ctx, client, endpoint) || answersModernMCPDiscover(ctx, client, endpoint) {
		return true
	}
	return servesMCPResourceMetadata(ctx, client, baseURL, endpoint)
}

// servesMCPResourceMetadata reports whether the host advertises RFC 9728
// protected-resource metadata, either at the well-known path or through a
// WWW-Authenticate challenge on the endpoint itself.
func servesMCPResourceMetadata(ctx context.Context, client *attack.HTTPClient, baseURL, endpoint string) bool {
	if resp, err := client.GET(ctx, endpointpkg.AppendPath(baseURL, "/.well-known/oauth-protected-resource"), nil); err == nil &&
		resp.IsSuccess() && resp.ContainsAny(`"resource"`, `"authorization_servers"`) {
		return true
	}
	// The challenge itself carries the pointer, which is how the C# sample answers.
	resp, err := client.POST(ctx, endpoint, nil, map[string]interface{}{
		"jsonrpc": "2.0", "id": "batesian-a2a-mcp-check", "method": "initialize",
		"params": map[string]interface{}{"protocolVersion": mcpProbeVersion,
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
		cardURL := endpointpkg.AppendPath(baseURL, path)
		resp, err := client.GET(ctx, cardURL, cardVersionHeaders(cardURL))
		if err != nil || !resp.IsSuccess() {
			continue
		}
		var card a2aDiscoveryCard
		if err := json.Unmarshal(resp.Body, &card); err != nil {
			continue
		}
		if hasRoutableHTTPInterface(card) {
			return card, true
		}
	}
	return a2aDiscoveryCard{}, false
}

func hasRoutableHTTPInterface(card a2aDiscoveryCard) bool {
	if len(jsonRPCInterfaces(card)) > 0 {
		return true
	}
	for _, group := range [][]a2aDiscoveryInterface{card.SupportedInterfaces, card.AdditionalInterfaces} {
		for _, iface := range group {
			if iface.isHTTPJSON() && hasHTTPScheme(iface.URL) {
				return true
			}
		}
	}
	return strings.EqualFold(card.PreferredTransport, "HTTP+JSON") && hasHTTPScheme(card.URL)
}

func cardVersionHeaders(cardURL string) map[string]string {
	parsed, err := url.Parse(cardURL)
	if err != nil || !strings.HasSuffix(parsed.Path, cardPathPrimary) {
		return nil
	}
	return map[string]string{"A2A-Version": "1.0"}
}

// jsonRPCURLs lists advertised JSON-RPC URLs in preference order.
func jsonRPCURLs(card a2aDiscoveryCard) []string {
	var urls []string
	seen := map[string]bool{}
	for _, iface := range jsonRPCInterfaces(card) {
		if !seen[iface.URL] {
			seen[iface.URL] = true
			urls = append(urls, iface.URL)
		}
	}
	return urls
}

func jsonRPCInterfaces(card a2aDiscoveryCard) []a2aDiscoveryInterface {
	var interfaces []a2aDiscoveryInterface
	add := func(iface a2aDiscoveryInterface) {
		if hasHTTPScheme(iface.URL) {
			interfaces = append(interfaces, iface)
		}
	}
	for _, iface := range card.SupportedInterfaces {
		if iface.isJSONRPC() {
			add(iface)
		}
	}
	for _, iface := range card.AdditionalInterfaces {
		if iface.isJSONRPC() {
			add(iface)
		}
	}
	legacyJSONRPC := card.PreferredTransport == "" || strings.EqualFold(card.PreferredTransport, "JSONRPC")
	if card.SupportedInterfaces == nil && legacyJSONRPC {
		add(a2aDiscoveryInterface{URL: card.URL})
	}
	return interfaces
}

// pinToTargetOrigin keeps the operator's target scheme+host and applies only the
// card URL's path when the card points at a different origin. A same-origin card
// URL is used verbatim. This prevents a card from redirecting scan traffic off
// the authorized origin or downgrading HTTPS to plaintext on the same host.
func pinToTargetOrigin(cardURL, baseURL string) string {
	cu, err := url.Parse(cardURL)
	if err != nil {
		return endpointpkg.AppendPath(baseURL, "/")
	}
	tu, err := url.Parse(baseURL)
	if err != nil {
		return cardURL
	}
	if strings.EqualFold(cu.Scheme, tu.Scheme) && strings.EqualFold(cu.Host, tu.Host) {
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
	return endpointpkg.Candidates(baseURL, candidatePaths)
}

// methodNotFound is the JSON-RPC code for an unimplemented method. It is the
// one error a task lookup can earn that says nothing about what the server is.
const methodNotFound = -32601

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
	discoveryTaskID = "batesian-discovery-nonexistent"
)

// probeA2AEvidence tries both A2A task-get method names. A result or A2A-reserved
// error is strong evidence; generic errors require corroboration to exclude MCP.
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
		requestID := "batesian-a2a-discovery-" + attack.NewVars(endpoint, "").RandID
		resp, err := client.POST(ctx, endpoint, p.headers, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      requestID,
			"method":  p.method,
			"params":  map[string]interface{}{"id": discoveryTaskID, "historyLength": 1},
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
		result, code, hasError, valid := discoveryResponse(resp.Body, requestID)
		if !valid {
			continue
		}
		if resp.IsSuccess() && !hasError && discoveryTaskResult(result) {
			return a2aEvidenceStrong
		}
		if hasError {
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

// discoveryResponse accepts only a JSON-RPC reply to the discovery probe.
func discoveryResponse(body []byte, expectedID string) (result json.RawMessage, code int, hasError, valid bool) {
	var reply struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	if json.Unmarshal(body, &reply) != nil || reply.JSONRPC != "2.0" {
		return nil, 0, false, false
	}
	var id string
	if json.Unmarshal(reply.ID, &id) != nil || id != expectedID {
		return nil, 0, false, false
	}
	if len(reply.Result) != 0 && len(reply.Error) == 0 {
		return reply.Result, 0, false, true
	}
	if len(reply.Error) != 0 && len(reply.Result) == 0 {
		var rpcError struct {
			Code    *int    `json:"code"`
			Message *string `json:"message"`
		}
		if json.Unmarshal(reply.Error, &rpcError) == nil && rpcError.Code != nil && rpcError.Message != nil {
			return nil, *rpcError.Code, true, true
		}
	}
	return nil, 0, false, false
}

func discoveryTaskResult(result json.RawMessage) bool {
	var task struct {
		ID        string `json:"id"`
		ContextID string `json:"contextId"`
		Status    struct {
			State string `json:"state"`
		} `json:"status"`
	}
	return json.Unmarshal(result, &task) == nil && task.ID == discoveryTaskID && task.ContextID != "" && task.Status.State != ""
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
			"protocolVersion": mcpProbeVersion,
			"capabilities":    map[string]interface{}{},
			"clientInfo":      map[string]interface{}{"name": "batesian", "version": attack.Version},
		},
	})
	if err != nil || !resp.IsAccepted() {
		return false
	}
	return resp.ContainsAny(`"protocolVersion"`)
}

// mcpProbeVersion mirrors the MCP package's current handshake revision. A
// successful probe must return protocolVersion.
const mcpProbeVersion = "2025-11-25"

const modernMCPProbeVersion = "2026-07-28"

// answersModernMCPDiscover recognizes the stateless MCP wire, which has no
// initialize method.
func answersModernMCPDiscover(ctx context.Context, client *attack.HTTPClient, endpoint string) bool {
	id := "batesian-a2a-mcp-discover-" + attack.NewVars(endpoint, "").RandID
	resp, err := client.POST(ctx, endpoint, map[string]string{
		"MCP-Protocol-Version": modernMCPProbeVersion,
		"Mcp-Method":           "server/discover",
	}, map[string]interface{}{
		"jsonrpc": "2.0", "id": id, "method": "server/discover",
		"params": map[string]interface{}{"_meta": map[string]interface{}{
			"io.modelcontextprotocol/protocolVersion":    modernMCPProbeVersion,
			"io.modelcontextprotocol/clientInfo":         map[string]interface{}{"name": "batesian", "version": attack.Version},
			"io.modelcontextprotocol/clientCapabilities": map[string]interface{}{},
		}},
	})
	return err == nil && resp.IsSuccess() && modernMCPDiscoverResult(resp.Body, id)
}

func modernMCPDiscoverResult(body []byte, expectedID string) bool {
	var reply struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  *struct {
			ResultType        string                     `json:"resultType"`
			SupportedVersions []string                   `json:"supportedVersions"`
			Capabilities      map[string]json.RawMessage `json:"capabilities"`
		} `json:"result"`
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal(body, &reply) != nil || reply.JSONRPC != "2.0" || reply.Result == nil || len(reply.Error) != 0 {
		return false
	}
	var id string
	if json.Unmarshal(reply.ID, &id) != nil || id != expectedID ||
		reply.Result.ResultType != "complete" || reply.Result.Capabilities == nil {
		return false
	}
	for _, version := range reply.Result.SupportedVersions {
		if version == modernMCPProbeVersion {
			return true
		}
	}
	return false
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
