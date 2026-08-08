package a2a

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

func TestSelectJSONRPCURL_PrefersJSONRPCOverPreferredGRPC(t *testing.T) {
	got := selectJSONRPCURL(parseDiscoveryCard(t, strings.ReplaceAll(referenceCard, "HOST", "h")))
	if got != "http://h/a2a/jsonrpc" {
		t.Errorf("selectJSONRPCURL = %q, want the JSONRPC interface url (not the gRPC top-level url)", got)
	}
}

func TestSelectJSONRPCURL_V03AdditionalInterfaces(t *testing.T) {
	card := parseDiscoveryCard(t, `{"additionalInterfaces":[{"transport":"HTTP+JSON","url":"http://h/rest"},{"transport":"JSONRPC","url":"http://h/jr"}]}`)
	if got := selectJSONRPCURL(card); got != "http://h/jr" {
		t.Errorf("selectJSONRPCURL = %q, want http://h/jr", got)
	}
}

func TestSelectJSONRPCURL_V03TopLevel(t *testing.T) {
	card := parseDiscoveryCard(t, `{"preferredTransport":"JSONRPC","url":"http://h/agent"}`)
	if got := selectJSONRPCURL(card); got != "http://h/agent" {
		t.Errorf("selectJSONRPCURL = %q, want http://h/agent", got)
	}
}

func TestSelectJSONRPCURL_NoUsableInterface(t *testing.T) {
	// Only a scheme-less gRPC interface and a gRPC top-level url: nothing usable.
	card := parseDiscoveryCard(t, `{"supportedInterfaces":[{"url":"127.0.0.1:50051","protocolBinding":"GRPC"}],"preferredTransport":"GRPC","url":"127.0.0.1:50052"}`)
	if got := selectJSONRPCURL(card); got != "" {
		t.Errorf("selectJSONRPCURL = %q, want empty (no http JSON-RPC interface)", got)
	}
}

func TestPinToTargetHost(t *testing.T) {
	// Same host: used verbatim.
	if got := pinToTargetHost("http://h:8080/a2a/jsonrpc", "http://h:8080"); got != "http://h:8080/a2a/jsonrpc" {
		t.Errorf("same-host pin = %q", got)
	}
	// Different host: keep target scheme+host, take card path.
	if got := pinToTargetHost("http://other:9000/a2a/jsonrpc", "http://h:8080"); got != "http://h:8080/a2a/jsonrpc" {
		t.Errorf("cross-host pin = %q, want path applied to target host", got)
	}
}

func newClient(target string) *attack.HTTPClient {
	return attack.NewUnauthHTTPClient(attack.Options{TimeoutSeconds: 5}, attack.NewVars(target, ""))
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
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"Task not found"}}`))
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
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"Task not found"}}`))
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
func jsonRPCServer(reply func(method string) string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		method, _ := req["method"].(string)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(reply(method)))
	}))
}

// An MCP server answers a task lookup with "method not found", exactly as an
// A2A agent that implements neither spelling does. Accepting that as an A2A
// endpoint made sixteen A2A rules report clean against an MCP target instead of
// skipping, which is the difference between "tested, nothing found" and "could
// not test".
func TestResolveA2AEndpoint_MCPServerIsNotAnA2AEndpoint(t *testing.T) {
	srv := jsonRPCServer(func(method string) string {
		if method == "initialize" {
			return `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18",` +
				`"serverInfo":{"name":"mcp","version":"1.0"},"capabilities":{}}}`
		}
		return `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}`
	})
	defer srv.Close()

	if ep, ok := resolveA2AEndpoint(context.Background(), newClient(srv.URL), srv.URL); ok {
		t.Errorf("resolved %q against an MCP server, want ok=false so the rules skip", ep)
	}
}

// The reason the check is negative rather than a stricter test for A2A: agents
// exist that implement neither task-get spelling and answer "method not found"
// for both, including this repository's own delegation and push-binding
// fixtures. They must still be discovered.
func TestResolveA2AEndpoint_AgentWithoutTaskMethodsStillFound(t *testing.T) {
	srv := jsonRPCServer(func(string) string {
		return `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}`
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
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"Task not found"}}`))
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
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"Task not found"}}`))
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
