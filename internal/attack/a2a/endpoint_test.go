package a2a

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
)

// referenceCard mirrors the hybrid v1.0+v0.3 card the official a2a-python sample
// serves: gRPC is listed first (scheme-less) and is the top-level preferred
// transport, while the JSON-RPC interface is what we must select.
const referenceCard = `{
  "name": "Sample Agent",
  "supportedInterfaces": [
    {"url": "127.0.0.1:50051", "protocolBinding": "GRPC", "protocolVersion": "1.0"},
    {"url": "http://HOST/a2a/jsonrpc", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
  ],
  "additionalInterfaces": [
    {"transport": "JSONRPC", "url": "http://HOST/a2a/jsonrpc"}
  ],
  "preferredTransport": "GRPC",
  "url": "127.0.0.1:50052"
}`

func parseDiscoveryCard(t *testing.T, s string) a2aDiscoveryCard {
	t.Helper()
	var c a2aDiscoveryCard
	if err := json.Unmarshal([]byte(s), &c); err != nil {
		t.Fatalf("bad test card: %v", err)
	}
	return c
}

func TestJSONRPCURLs_PrefersJSONRPCOverPreferredGRPC(t *testing.T) {
	got := jsonRPCURLs(parseDiscoveryCard(t, strings.ReplaceAll(referenceCard, "HOST", "h")))
	if !slices.Equal(got, []string{"http://h/a2a/jsonrpc"}) {
		t.Errorf("jsonRPCURLs = %q, want only the JSON-RPC interface", got)
	}
}

func TestJSONRPCURLs_V03AdditionalInterfaces(t *testing.T) {
	card := parseDiscoveryCard(t, `{"additionalInterfaces":[{"transport":"HTTP+JSON","url":"http://h/rest"},{"transport":"JSONRPC","url":"http://h/jr"}]}`)
	if got := jsonRPCURLs(card); !slices.Equal(got, []string{"http://h/jr"}) {
		t.Errorf("jsonRPCURLs = %q, want http://h/jr", got)
	}
}

func TestJSONRPCURLs_V03TopLevel(t *testing.T) {
	for _, tc := range []struct {
		name string
		card string
		want string
	}{
		{"explicit JSONRPC", `{"preferredTransport":"JSONRPC","url":"http://h/agent"}`, "http://h/agent"},
		{"omitted transport", `{"url":"http://h/agent"}`, "http://h/agent"},
		{"empty transport", `{"preferredTransport":"","url":"http://h/agent"}`, "http://h/agent"},
		{"explicit GRPC", `{"preferredTransport":"GRPC","url":"http://h/agent"}`, ""},
		{"explicit HTTP+JSON", `{"preferredTransport":"HTTP+JSON","url":"http://h/agent"}`, ""},
		{"v1 empty interfaces", `{"supportedInterfaces":[],"url":"http://h/agent"}`, ""},
		{"v1 non-JSONRPC interfaces", `{"supportedInterfaces":[{"protocolBinding":"GRPC","url":"http://h/grpc"}],"url":"http://h/agent"}`, ""},
		{"v1 ignores top-level transport", `{"supportedInterfaces":[{"protocolBinding":"GRPC","url":"http://h/grpc"}],"preferredTransport":"JSONRPC","url":"http://h/agent"}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := jsonRPCURLs(parseDiscoveryCard(t, tc.card))
			if tc.want == "" {
				if len(got) != 0 {
					t.Errorf("jsonRPCURLs = %q, want none", got)
				}
				return
			}
			if !slices.Equal(got, []string{tc.want}) {
				t.Errorf("jsonRPCURLs = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestJSONRPCURLs_NoUsableInterface(t *testing.T) {
	// Only a scheme-less gRPC interface and a gRPC top-level url: nothing usable.
	card := parseDiscoveryCard(t, `{"supportedInterfaces":[{"url":"127.0.0.1:50051","protocolBinding":"GRPC"}],"preferredTransport":"GRPC","url":"127.0.0.1:50052"}`)
	if got := jsonRPCURLs(card); len(got) != 0 {
		t.Errorf("jsonRPCURLs = %q, want empty (no http JSON-RPC interface)", got)
	}
}

func TestJSONRPCURLs_PreservesOrder(t *testing.T) {
	card := parseDiscoveryCard(t, `{"supportedInterfaces":[`+
		`{"url":"http://h/first","protocolBinding":"JSONRPC"},`+
		`{"url":"http://h/rest","protocolBinding":"HTTP+JSON"},`+
		`{"url":"http://h/second","protocolBinding":"JSONRPC"}],`+
		`"additionalInterfaces":[{"url":"http://h/second","transport":"JSONRPC"}]}`)
	if got := jsonRPCURLs(card); !slices.Equal(got, []string{"http://h/first", "http://h/second"}) {
		t.Errorf("jsonRPCURLs = %q, want both JSON-RPC interfaces in order", got)
	}
}

func TestPinToTargetOrigin(t *testing.T) {
	// Same origin: used verbatim.
	if got := pinToTargetOrigin("http://h:8080/a2a/jsonrpc", "http://h:8080"); got != "http://h:8080/a2a/jsonrpc" {
		t.Errorf("same-origin pin = %q", got)
	}
	// Different host: keep target scheme+host, take card path.
	if got := pinToTargetOrigin("http://other:9000/a2a/jsonrpc", "http://h:8080"); got != "http://h:8080/a2a/jsonrpc" {
		t.Errorf("cross-host pin = %q, want path applied to target host", got)
	}
	// Same host with a different scheme: keep the target's HTTPS origin.
	if got := pinToTargetOrigin("http://h:8443/a2a/jsonrpc", "https://h:8443"); got != "https://h:8443/a2a/jsonrpc" {
		t.Errorf("scheme-downgrade pin = %q, want target HTTPS origin", got)
	}
}

func TestResolveHTTPJSONBases_PreferenceAndPinning(t *testing.T) {
	var card string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/agent-card.json" {
			_, _ = io.WriteString(w, card)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	card = `{"supportedInterfaces":[` +
		`{"url":"` + srv.URL + `/old/","protocolBinding":"HTTP+JSON"},` +
		`{"url":"grpc.example.test:50051","protocolBinding":"GRPC"},` +
		`{"url":"https://other.example.test/live","protocolBinding":"HTTP+JSON"}],` +
		`"additionalInterfaces":[{"url":"` + srv.URL + `/live","transport":"HTTP+JSON"}],` +
		`"preferredTransport":"HTTP+JSON","url":"` + srv.URL + `/top"}`

	got := resolveHTTPJSONBases(context.Background(), newClient(srv.URL), srv.URL)
	want := []string{srv.URL + "/old", srv.URL + "/live", srv.URL + "/top"}
	if !slices.Equal(got, want) {
		t.Errorf("REST bases = %q, want %q", got, want)
	}
}

func TestFetchDiscoveryCard_VersionHeaderByPath(t *testing.T) {
	for _, tc := range []struct {
		name       string
		cardPath   string
		wantHeader string
	}{
		{"v1", cardPathPrimary, "1.0"},
		{"legacy", cardPathLegacy, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tc.cardPath {
					http.NotFound(w, r)
					return
				}
				if r.Header.Get("A2A-Version") != tc.wantHeader {
					http.Error(w, "wrong A2A version", http.StatusBadRequest)
					return
				}
				_, _ = io.WriteString(w, `{"url":"http://agent.example/rpc"}`)
			}))
			defer server.Close()
			card, found := fetchDiscoveryCard(t.Context(), newClient(server.URL), server.URL)
			if !found || card.URL != "http://agent.example/rpc" {
				t.Fatalf("card=%+v found=%v", card, found)
			}
		})
	}
}

func TestResolveHTTPJSONBases_CapsResults(t *testing.T) {
	interfaces := make([]map[string]string, 18)
	for i := range interfaces {
		interfaces[i] = map[string]string{
			"url": fmt.Sprintf("http://remote.example.test/rest-%d", i), "protocolBinding": "HTTP+JSON",
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/agent-card.json" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"supportedInterfaces": interfaces})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	got := resolveHTTPJSONBases(context.Background(), newClient(srv.URL), srv.URL)
	if len(got) != maxCardHTTPJSONBases || got[0] != srv.URL+"/rest-0" || got[15] != srv.URL+"/rest-15" {
		t.Errorf("bounded REST bases = %q", got)
	}
}

func newClient(target string) *attack.HTTPClient {
	return attack.NewUnauthHTTPClient(attack.Options{TimeoutSeconds: 5}, attack.NewVars(target, ""))
}

func writeTaskNotFound(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID json.RawMessage `json:"id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"jsonrpc": "2.0", "id": req.ID,
		"error": map[string]interface{}{"code": -32001, "message": "Task not found"},
	})
}

// a2aMock answers JSON-RPC at rpcPath (a TaskNotFound error) and 404s
// elsewhere. It deliberately serves no agent card: these are the cardless cases,
// where discovery has to fall back to probing paths. Card-driven discovery
// builds its own server, in TestResolveA2AEndpoint_FromCard.
func a2aMock(rpcPath string) *httptest.Server {
	mux := http.NewServeMux()
	if rpcPath != "" {
		mux.HandleFunc(rpcPath, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			writeTaskNotFound(w, r)
		})
	}
	return httptest.NewServer(mux)
}

func TestResolveA2AEndpoint_FromCard(t *testing.T) {
	// Serve a card (declaring its own host for the JSON-RPC interface) so the
	// same-host path is exercised: discovery must select the JSON-RPC interface
	// even though gRPC is listed first and is the preferred/top-level transport.
	var host string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/agent-card.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(strings.ReplaceAll(referenceCard, "HOST", host)))
	})
	// The declared interface has to answer. Serving only the card made this test
	// assert the defect it was written before: discovery returned the card's path
	// as reachable without ever contacting it.
	mux.HandleFunc("/a2a/jsonrpc", func(w http.ResponseWriter, r *http.Request) {
		writeTaskNotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	host = strings.TrimPrefix(srv.URL, "http://")

	ep, ok := resolveA2AEndpoint(context.Background(), newClient(srv.URL), srv.URL)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if ep != srv.URL+"/a2a/jsonrpc" {
		t.Errorf("endpoint = %q, want %s/a2a/jsonrpc", ep, srv.URL)
	}
}

func TestResolveA2AEndpoint_SecondAdvertisedInterface(t *testing.T) {
	for _, tc := range []struct {
		name string
		card string
	}{
		{
			name: "v1 supported interfaces",
			card: `{"supportedInterfaces":[` +
				`{"url":"BASE/old","protocolBinding":"JSONRPC","protocolVersion":"1.0"},` +
				`{"url":"BASE/custom/live","protocolBinding":"JSONRPC","protocolVersion":"1.0"}]}`,
		},
		{
			name: "legacy additional interfaces",
			card: `{"additionalInterfaces":[` +
				`{"url":"BASE/old","transport":"JSONRPC"},` +
				`{"url":"BASE/custom/live","transport":"JSONRPC"}]}`,
		},
		{
			name: "legacy top-level fallback",
			card: `{"additionalInterfaces":[{"url":"BASE/old","transport":"JSONRPC"}],` +
				`"url":"BASE/custom/live","preferredTransport":"JSONRPC"}`,
		},
		{
			name: "cross-origin alternate stays on target",
			card: `{"supportedInterfaces":[` +
				`{"url":"BASE/old","protocolBinding":"JSONRPC"},` +
				`{"url":"https://other.example.test/custom/live","protocolBinding":"JSONRPC"}]}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var card string
			mux := http.NewServeMux()
			mux.HandleFunc("/.well-known/agent-card.json", func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, card)
			})
			mux.HandleFunc("/custom/live", writeTaskNotFound)
			srv := httptest.NewServer(mux)
			defer srv.Close()
			card = strings.ReplaceAll(tc.card, "BASE", srv.URL)

			ep, ok := resolveA2AEndpoint(context.Background(), newClient(srv.URL), srv.URL)
			if !ok || ep != srv.URL+"/custom/live" {
				t.Errorf("endpoint = %q ok = %v, want %s/custom/live true", ep, ok, srv.URL)
			}
		})
	}
}

func TestResolveA2AEndpoint_PrefersFirstReachableInterface(t *testing.T) {
	var card string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/agent-card.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, card)
	})
	mux.HandleFunc("/secured", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("/open", writeTaskNotFound)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	card = `{"supportedInterfaces":[` +
		`{"url":"` + srv.URL + `/secured","protocolBinding":"JSONRPC"},` +
		`{"url":"` + srv.URL + `/open","protocolBinding":"JSONRPC"}]}`

	ep, ok := resolveA2AEndpoint(context.Background(), newClient(srv.URL), srv.URL)
	if !ok || ep != srv.URL+"/secured" {
		t.Errorf("endpoint = %q ok = %v, want preferred auth-gated interface", ep, ok)
	}
}

func TestResolveA2AEndpoint_LegacyDefaultTransport(t *testing.T) {
	var host string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/agent.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"name":"legacy","url":"http://%s/custom/jsonrpc"}`, host)
	})
	mux.HandleFunc("/custom/jsonrpc", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		writeTaskNotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	host = strings.TrimPrefix(srv.URL, "http://")

	ep, ok := resolveA2AEndpoint(context.Background(), newClient(srv.URL), srv.URL)
	if !ok || ep != srv.URL+"/custom/jsonrpc" {
		t.Errorf("endpoint = %q ok = %v, want %s/custom/jsonrpc true", ep, ok, srv.URL)
	}
}

func TestResolveA2AEndpoint_FallbackToCardlessPath(t *testing.T) {
	// No card; JSON-RPC mounted at /a2a/jsonrpc. Discovery must probe and find it.
	srv := a2aMock("/a2a/jsonrpc")
	defer srv.Close()
	ep, ok := resolveA2AEndpoint(context.Background(), newClient(srv.URL), srv.URL)
	if !ok || ep != srv.URL+"/a2a/jsonrpc" {
		t.Errorf("endpoint = %q ok = %v, want %s/a2a/jsonrpc true", ep, ok, srv.URL)
	}
}

func TestResolveA2AEndpoint_FallbackToRoot(t *testing.T) {
	// No card; JSON-RPC at root, like our existing fixtures. Must resolve to "/".
	srv := a2aMock("/")
	defer srv.Close()
	ep, ok := resolveA2AEndpoint(context.Background(), newClient(srv.URL), srv.URL)
	if !ok || ep != srv.URL+"/" {
		t.Errorf("endpoint = %q ok = %v, want %s/ true", ep, ok, srv.URL)
	}
}

func TestResolveA2AEndpoint_NothingReachable(t *testing.T) {
	// Server 404s everything: no JSON-RPC endpoint, ok must be false.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	if _, ok := resolveA2AEndpoint(context.Background(), newClient(srv.URL), srv.URL); ok {
		t.Error("expected ok=false when no JSON-RPC endpoint responds")
	}
}

// A target that already names the JSON-RPC path must be probed as given.
// Discovery only ever appended to the target, so /a2a became /a2a/,
// /a2a/a2a/jsonrpc, /a2a/a2a and /a2a/rpc, and the endpoint the operator had
// pointed at was never tried. There is no agent card here, which is the case
// that matters: with a card, discovery takes the URL the card declares.
func TestResolveA2AEndpoint_TargetNamesTheEndpointPath(t *testing.T) {
	srv := a2aMock("/a2a/jsonrpc")
	defer srv.Close()

	for _, target := range []string{srv.URL + "/a2a/jsonrpc", srv.URL + "/a2a/jsonrpc/"} {
		t.Run(target, func(t *testing.T) {
			ep, ok := resolveA2AEndpoint(context.Background(), newClient(target), target)
			if !ok || ep != srv.URL+"/a2a/jsonrpc" {
				t.Errorf("endpoint = %q ok = %v, want %s/a2a/jsonrpc true", ep, ok, srv.URL)
			}
		})
	}
}

// jsonRPCServer answers every POST with the given body, whatever the path. It
// stands in for a JSON-RPC service that is not an A2A agent.
func jsonRPCServer(reply func(method string, id json.RawMessage) string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var req struct {
			Method string          `json:"method"`
			ID     json.RawMessage `json:"id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(reply(req.Method, req.ID)))
	}))
}

// An MCP server answers a task lookup with "method not found", exactly as an
// A2A agent that implements neither spelling does. Accepting that as an A2A
// endpoint made sixteen A2A rules report clean against an MCP target instead of
// skipping, which is the difference between "tested, nothing found" and "could
// not test".
func TestResolveA2AEndpoint_MCPServerIsNotAnA2AEndpoint(t *testing.T) {
	srv := jsonRPCServer(func(method string, id json.RawMessage) string {
		if method == "initialize" {
			return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18",`+
				`"serverInfo":{"name":"mcp","version":"1.0"},"capabilities":{}}}`, id)
		}
		return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"Method not found"}}`, id)
	})
	defer srv.Close()

	if ep, ok := resolveA2AEndpoint(context.Background(), newClient(srv.URL), srv.URL); ok {
		t.Errorf("resolved %q against an MCP server, want ok=false so the rules skip", ep)
	}
}

func TestResolveA2AEndpoint_ModernOnlyMCPIsNotAnA2AEndpoint(t *testing.T) {
	var discoveryCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mcp" {
			http.NotFound(w, r)
			return
		}
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Meta map[string]interface{} `json:"_meta"`
			} `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		if req.Method == "server/discover" &&
			r.Header.Get("MCP-Protocol-Version") == "2026-07-28" &&
			r.Header.Get("Mcp-Method") == req.Method &&
			req.Params.Meta["io.modelcontextprotocol/protocolVersion"] == "2026-07-28" &&
			req.Params.Meta["io.modelcontextprotocol/clientCapabilities"] != nil {
			discoveryCalls++
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID,
				"result": map[string]interface{}{
					"resultType": "complete", "supportedVersions": []string{"2026-07-28"},
					"capabilities": map[string]interface{}{"tools": map[string]interface{}{}},
				},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": req.ID,
			"error": map[string]interface{}{"code": -32601, "message": "Method not found"},
		})
	}))
	defer srv.Close()

	if ep, ok := resolveA2AEndpoint(context.Background(), newClient(srv.URL), srv.URL+"/mcp"); ok {
		t.Errorf("resolved %q against a modern-only MCP server", ep)
	}
	if discoveryCalls != 1 {
		t.Errorf("modern discovery calls = %d, want 1", discoveryCalls)
	}
}

func TestModernMCPDiscoverResult_RequiresCorrelatedShape(t *testing.T) {
	const id = "probe-1"
	for _, tc := range []struct {
		name string
		body string
		want bool
	}{
		{"valid", `{"jsonrpc":"2.0","id":"probe-1","result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{}}}`, true},
		{"wrong id", `{"jsonrpc":"2.0","id":"other","result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{}}}`, false},
		{"error", `{"jsonrpc":"2.0","id":"probe-1","error":{"code":-32601,"message":"Method not found"}}`, false},
		{"legacy only", `{"jsonrpc":"2.0","id":"probe-1","result":{"resultType":"complete","supportedVersions":["2025-11-25"],"capabilities":{}}}`, false},
		{"missing capabilities", `{"jsonrpc":"2.0","id":"probe-1","result":{"resultType":"complete","supportedVersions":["2026-07-28"]}}`, false},
		{"missing result type", `{"jsonrpc":"2.0","id":"probe-1","result":{"supportedVersions":["2026-07-28"],"capabilities":{}}}`, false},
		{"bare version", `{"jsonrpc":"2.0","id":"probe-1","result":{"protocolVersion":"2026-07-28"}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := modernMCPDiscoverResult([]byte(tc.body), id); got != tc.want {
				t.Errorf("modernMCPDiscoverResult = %v, want %v", got, tc.want)
			}
		})
	}
}

// The reason the check is negative rather than a stricter test for A2A: agents
// exist that implement neither task-get spelling and answer "method not found"
// for both, including this repository's own delegation and push-binding
// fixtures. They must still be discovered.
func TestResolveA2AEndpoint_AgentWithoutTaskMethodsStillFound(t *testing.T) {
	srv := jsonRPCServer(func(_ string, id json.RawMessage) string {
		return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"Method not found"}}`, id)
	})
	defer srv.Close()

	ep, ok := resolveA2AEndpoint(context.Background(), newClient(srv.URL), srv.URL)
	if !ok {
		t.Fatal("expected ok=true: a JSON-RPC service that is not MCP stays an A2A candidate")
	}
	if ep != srv.URL+"/" {
		t.Errorf("endpoint = %q, want %s/", ep, srv.URL)
	}
}

// A task lookup answered with anything other than "method not found" is
// evidence only something implementing the method could give, so it is accepted
// without the MCP question being asked at all.
func TestResolveA2AEndpoint_TaskNotFoundNeedsNoDisambiguation(t *testing.T) {
	mcpProbes := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		method, _ := req["method"].(string)
		if method == "initialize" {
			mcpProbes++
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": req["id"],
			"error": map[string]interface{}{"code": -32001, "message": "Task not found"},
		})
	}))
	defer srv.Close()

	if _, ok := resolveA2AEndpoint(context.Background(), newClient(srv.URL), srv.URL); !ok {
		t.Fatal("expected ok=true for a server answering TaskNotFound")
	}
	if mcpProbes != 0 {
		t.Errorf("sent %d MCP initialize probes, want 0 when the answer already settles it", mcpProbes)
	}
}

// The origin form is unchanged: appending still finds a handler mounted at a
// conventional path.
func TestResolveA2AEndpoint_OriginTargetUnchanged(t *testing.T) {
	srv := a2aMock("/a2a/jsonrpc")
	defer srv.Close()

	ep, ok := resolveA2AEndpoint(context.Background(), newClient(srv.URL), srv.URL)
	if !ok || ep != srv.URL+"/a2a/jsonrpc" {
		t.Errorf("endpoint = %q ok = %v, want %s/a2a/jsonrpc true", ep, ok, srv.URL)
	}
}

// A card advertises the URL clients reach the agent on, which for anything behind
// a proxy is not the path the operator is scanning: an agent published at
// https://public.example/a2a/v1 may be mounted at / on the origin. The card URL
// was returned as reachable without ever being contacted, so the candidate walk
// that would have found / was skipped and ok=true told a dozen rules their failed
// probes were a tested-clean result.
func TestResolveA2AEndpoint_CardPathThatDoesNotAnswerFallsBack(t *testing.T) {
	var hits []string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/agent-card.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Declares an external path that is not mounted at this origin.
		_, _ = w.Write([]byte(`{"name":"proxied","version":"1.0",` +
			`"url":"https://public.example.test/a2a/v1","preferredTransport":"JSONRPC"}`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// "/" is a catch-all in ServeMux, so the declared /a2a/v1 must be refused
		// explicitly or it would appear to answer and the test would prove nothing.
		if r.URL.Path != "/" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		hits = append(hits, r.Method+" "+r.URL.Path)
		// The real handler, answering a task-shaped probe.
		writeTaskNotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ep, ok := resolveA2AEndpoint(context.Background(), newClient(srv.URL), srv.URL)
	if !ok {
		t.Fatal("expected discovery to fall back to the conventional paths and find the handler")
	}
	if ep != srv.URL+"/" {
		t.Errorf("endpoint = %q, want the path that actually answered (%s/)", ep, srv.URL)
	}
	if len(hits) == 0 {
		t.Error("the real handler was never contacted; the card's claim was taken on trust")
	}
}

// An auth-gated card path must still be accepted, or securing an agent would make
// it look undiscoverable. probeJSONRPCEndpoint treats 401/403 as found.
func TestResolveA2AEndpoint_CardPathBehindAuthIsAccepted(t *testing.T) {
	var host string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/agent-card.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"secured","version":"1.0","url":"http://` + host +
			`/a2a/v1","preferredTransport":"JSONRPC"}`))
	})
	mux.HandleFunc("/a2a/v1", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	host = strings.TrimPrefix(srv.URL, "http://")

	ep, ok := resolveA2AEndpoint(context.Background(), newClient(srv.URL), srv.URL)
	if !ok || ep != srv.URL+"/a2a/v1" {
		t.Errorf("endpoint = %q ok = %v, want %s/a2a/v1 true (a 401 proves the endpoint exists)", ep, ok, srv.URL)
	}
}

// An MCP server is not an A2A endpoint, and both of these shapes were measured
// being accepted as one against the official MCP C# SDK. Roughly a dozen A2A rules
// then reported the target tested-and-clean.
func TestResolveA2AEndpoint_MCPServerShapesAreRejected(t *testing.T) {
	t.Run("session error naming Mcp-Session-Id", func(t *testing.T) {
		// The C# SDK's answer to an A2A tasks/get. The code is -32000, not -32601,
		// so it bypassed the method-not-found branch where the MCP check lived, and
		// the body contains "jsonrpc" like every JSON-RPC message.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				Method string `json:"method"`
			}
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &req)
			w.Header().Set("Content-Type", "application/json")
			if req.Method == "initialize" {
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18",` +
					`"serverInfo":{"name":"csharp","version":"1"},"capabilities":{}}}`))
				return
			}
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"d","error":{"code":-32000,"message":` +
				`"Bad Request: A new session can only be created by an initialize request. ` +
				`Include a valid Mcp-Session-Id header for non-initialize requests."}}`))
		}))
		defer srv.Close()

		if _, ok := resolveA2AEndpoint(context.Background(), newClient(srv.URL), srv.URL); ok {
			t.Error("an MCP server that answers initialize must not be accepted as an A2A endpoint")
		}
	})

	t.Run("OAuth-protected, 401 to everything", func(t *testing.T) {
		// The C# SDK's ProtectedMcpServer sample. It refuses every unauthenticated
		// request, so there is no A2A evidence at all; a bare 401 used to be accepted
		// outright. RFC 9728 protected-resource metadata is what identifies it, and
		// A2A does not use that mechanism.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "oauth-protected-resource") {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"resource":"http://x/","authorization_servers":["http://as"]}`))
				return
			}
			w.Header().Set("WWW-Authenticate",
				`Bearer resource_metadata="http://`+r.Host+`/.well-known/oauth-protected-resource/"`)
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer srv.Close()

		if _, ok := resolveA2AEndpoint(context.Background(), newClient(srv.URL), srv.URL); ok {
			t.Error("an OAuth-protected MCP server must not be accepted as an A2A endpoint on a bare 401")
		}
	})
}

// The negative check must stay negative: an auth-gated A2A agent that publishes no
// MCP discovery is still a candidate, or securing an agent would make every A2A
// rule report not-tested against it.
func TestResolveA2AEndpoint_AuthGatedNonMCPIsStillACandidate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No agent card, no OAuth metadata, no MCP handshake: just a 401.
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	ep, ok := resolveA2AEndpoint(context.Background(), newClient(srv.URL), srv.URL)
	if !ok {
		t.Errorf("a bare auth-gated JSON-RPC service is still an A2A candidate; got ep=%q ok=false", ep)
	}
}

// A2A's own error codes are strong evidence and need no disambiguation, because
// only an A2A implementation emits them.
func TestResolveA2AEndpoint_A2AErrorCodeIsStrongEvidence(t *testing.T) {
	for _, code := range []int{-32001, -32004, -32006} {
		srv := jsonRPCServer(func(_ string, id json.RawMessage) string {
			return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":%d,"message":"A2A error"}}`, id, code)
		})
		if _, ok := resolveA2AEndpoint(context.Background(), newClient(srv.URL), srv.URL); !ok {
			t.Errorf("error code %d is A2A-specific and must be accepted", code)
		}
		srv.Close()
	}
}

func TestProbeA2AEvidence_RequiresMatchingResponse(t *testing.T) {
	tests := []struct {
		name string
		body string
		want a2aEvidence
	}{
		{"matching task error", `{"jsonrpc":"2.0","id":"batesian-a2a-discovery","error":{"code":-32001,"message":"Task not found"}}`, a2aEvidenceStrong},
		{"matching task result", `{"jsonrpc":"2.0","id":"batesian-a2a-discovery","result":{"id":"batesian-discovery-nonexistent","contextId":"ctx-1","status":{"state":"submitted"}}}`, a2aEvidenceStrong},
		{"wrong task id", `{"jsonrpc":"2.0","id":"batesian-a2a-discovery","result":{"id":"task-1","contextId":"ctx-1","status":{"state":"submitted"}}}`, a2aEvidenceNone},
		{"id only result", `{"jsonrpc":"2.0","id":"batesian-a2a-discovery","result":{"id":"batesian-discovery-nonexistent"}}`, a2aEvidenceNone},
		{"wrong result id", `{"jsonrpc":"2.0","id":"other","result":{"id":"task-1","status":{"state":"submitted"}}}`, a2aEvidenceNone},
		{"null result id", `{"jsonrpc":"2.0","id":null,"result":{"id":"task-1","status":{"state":"submitted"}}}`, a2aEvidenceNone},
		{"missing result id", `{"jsonrpc":"2.0","result":{"id":"task-1","status":{"state":"submitted"}}}`, a2aEvidenceNone},
		{"wrong error id", `{"jsonrpc":"2.0","id":"other","error":{"code":-32001,"message":"Task not found"}}`, a2aEvidenceNone},
		{"null error id", `{"jsonrpc":"2.0","id":null,"error":{"code":-32001,"message":"Task not found"}}`, a2aEvidenceNone},
		{"missing error id", `{"jsonrpc":"2.0","error":{"code":-32001,"message":"Task not found"}}`, a2aEvidenceNone},
		{"missing version", `{"id":"batesian-a2a-discovery","error":{"code":-32001,"message":"Task not found"}}`, a2aEvidenceNone},
		{"bare result", `{"jsonrpc":"2.0","id":"batesian-a2a-discovery","result":{}}`, a2aEvidenceNone},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var request struct {
					ID string `json:"id"`
				}
				_ = json.NewDecoder(r.Body).Decode(&request)
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, strings.ReplaceAll(tt.body, "batesian-a2a-discovery", request.ID))
			}))
			defer srv.Close()
			if got := probeA2AEvidence(context.Background(), newClient(srv.URL), srv.URL); got != tt.want {
				t.Errorf("probeA2AEvidence = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResolveA2AEndpoint_UnrelatedTaskResponse(t *testing.T) {
	srv := jsonRPCServer(func(_ string, _ json.RawMessage) string {
		return `{"jsonrpc":"2.0","id":"other","error":{"code":-32001,"message":"Task not found"}}`
	})
	defer srv.Close()

	if ep, ok := resolveA2AEndpoint(context.Background(), newClient(srv.URL), srv.URL); ok {
		t.Errorf("resolved %q from a response to another request", ep)
	}
}

func TestFetchCard_VersionHeaderByPath(t *testing.T) {
	for _, tc := range []struct {
		path       string
		wantHeader string
	}{
		{cardPathPrimary, "1.0"},
		{cardPathLegacy, ""},
	} {
		t.Run(tc.path, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tc.path || r.Header.Get("A2A-Version") != tc.wantHeader {
					http.Error(w, "wrong A2A version", http.StatusBadRequest)
					return
				}
				_, _ = io.WriteString(w, `{"name":"Versioned Agent"}`)
			}))
			defer server.Close()
			if _, _, ok := fetchCard(t.Context(), newClient(server.URL), server.URL+tc.path); !ok {
				t.Fatal("card not fetched")
			}
		})
	}
}

func TestVersionedCardRuleReaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != cardPathPrimary {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("A2A-Version") != "1.0" {
			http.Error(w, "wrong A2A version", http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(w, `{"name":"Versioned Agent","capabilities":{"extensions":[{"uri":"urn:test:required","required":true}]}}`)
	}))
	defer server.Close()

	extensions, served := (&ExtensionDowngradeExecutor{}).requiredExtensions(t.Context(), newClient(server.URL), server.URL)
	if !served || !slices.Equal(extensions, []string{"urn:test:required"}) {
		t.Fatalf("extensions=%q served=%v", extensions, served)
	}
	opts := attack.Options{TimeoutSeconds: 5}
	if _, err := NewJWSAlgConfExecutor(attack.RuleContext{}).Execute(t.Context(), server.URL, opts); err != nil {
		t.Fatalf("JWS card read: %v", err)
	}
	if _, err := NewWellKnownHostInjectExecutor(attack.RuleContext{}).Execute(t.Context(), server.URL, opts); err != nil {
		t.Fatalf("host-injection card read: %v", err)
	}
}
