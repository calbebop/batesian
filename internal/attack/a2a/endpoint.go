package a2a

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
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
			return pinToTargetHost(cardURL, baseURL), true
		}
	}
	for _, ep := range candidateEndpoints(baseURL) {
		if probeJSONRPCEndpoint(ctx, client, ep) {
			return ep, true
		}
	}
	return baseURL + "/", false
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

// candidateEndpoints lists JSON-RPC paths to probe when the card does not declare
// one. Root is first so servers that mount JSON-RPC at the root keep working.
func candidateEndpoints(baseURL string) []string {
	return []string{
		baseURL + "/",
		baseURL + "/a2a/jsonrpc",
		baseURL + "/a2a",
		baseURL + "/rpc",
	}
}

// probeJSONRPCEndpoint reports whether a path answers JSON-RPC. It sends a
// read-only GetTask for a non-existent task id and treats a JSON-RPC envelope
// (result or error) or an auth rejection (401/403) as a live endpoint; a 404 or
// transport error means this is not the endpoint.
func probeJSONRPCEndpoint(ctx context.Context, client *attack.HTTPClient, endpoint string) bool {
	resp, err := client.POST(ctx, endpoint, map[string]string{"A2A-Version": "1.0"}, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "batesian-a2a-discovery",
		"method":  "GetTask",
		"params":  map[string]interface{}{"id": "batesian-discovery-nonexistent", "historyLength": 1},
	})
	if err != nil {
		return false
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return true
	}
	if resp.StatusCode == 404 {
		return false
	}
	return isJSONRPCError(resp.Body) || resp.ContainsAny(`"jsonrpc"`, `"result"`)
}

// hasHTTPScheme reports whether rawURL is an absolute http(s) URL.
func hasHTTPScheme(rawURL string) bool {
	u, err := url.Parse(rawURL)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}
