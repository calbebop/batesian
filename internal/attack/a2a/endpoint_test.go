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

// a2aMock serves an optional card and answers JSON-RPC at rpcPath (a TaskNotFound
// error), 404 elsewhere.
func a2aMock(card string, rpcPath string) *httptest.Server {
	mux := http.NewServeMux()
	if card != "" {
		mux.HandleFunc("/.well-known/agent-card.json", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(card))
		})
	}
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
	srv := a2aMock("", "/a2a/jsonrpc")
	defer srv.Close()
	ep, ok := resolveA2AEndpoint(context.Background(), newClient(srv.URL), srv.URL)
	if !ok || ep != srv.URL+"/a2a/jsonrpc" {
		t.Errorf("endpoint = %q ok = %v, want %s/a2a/jsonrpc true", ep, ok, srv.URL)
	}
}

func TestResolveA2AEndpoint_FallbackToRoot(t *testing.T) {
	// No card; JSON-RPC at root, like our existing fixtures. Must resolve to "/".
	srv := a2aMock("", "/")
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
