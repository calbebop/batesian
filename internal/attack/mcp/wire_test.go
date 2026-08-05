package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
)

// These pin the transport contract each era imposes, taken from probing the
// official Python SDK. Getting any of them wrong is silent: the request is
// answered by the wrong handler, or rejected in a way a rule reads as "secure".

type captured struct {
	method   string
	headers  http.Header
	params   map[string]interface{}
	protoHdr string
	methHdr  string
}

// wireServer records what it receives and answers as the requested eras allow.
// serveLegacy and serveModern decide which wires exist, so a dual-era server, a
// legacy-only one and a modern-only one are all expressible.
func wireServer(t *testing.T, serveLegacy, serveModern bool) (*httptest.Server, *[]captured) {
	t.Helper()

	var seen []captured
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mcp" {
			http.NotFound(w, r)
			return
		}
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		method, _ := body["method"].(string)
		params, _ := body["params"].(map[string]interface{})
		seen = append(seen, captured{
			method:   method,
			headers:  r.Header.Clone(),
			params:   params,
			protoHdr: r.Header.Get("MCP-Protocol-Version"),
			methHdr:  r.Header.Get("Mcp-Method"),
		})

		w.Header().Set("Content-Type", "application/json")
		modern := r.Header.Get("MCP-Protocol-Version") == modernEraVersion

		// A modern server enforces the header mirror and the _meta block, exactly
		// as the SDK does, so a malformed probe fails here rather than passing
		// quietly.
		if modern {
			if !serveModern {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0", "id": body["id"],
					"error": map[string]interface{}{"code": -32022, "message": "UnsupportedProtocolVersion"},
				})
				return
			}
			if r.Header.Get("Mcp-Method") != method {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0", "id": body["id"],
					"error": map[string]interface{}{"code": -32020, "message": "HeaderMismatch"},
				})
				return
			}
			if _, ok := params["_meta"].(map[string]interface{}); !ok {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0", "id": body["id"],
					"error": map[string]interface{}{"code": -32602, "message": "params._meta is required"},
				})
				return
			}
			result := map[string]interface{}{
				"cacheScope": "private", "resultType": "complete", "ttlMs": 0,
				"_meta": map[string]interface{}{},
			}
			switch method {
			case "server/discover":
				result["supportedVersions"] = []string{modernEraVersion}
				result["capabilities"] = map[string]interface{}{
					"tools": map[string]interface{}{}, "resources": map[string]interface{}{},
				}
			case "tools/list":
				result["tools"] = []interface{}{map[string]interface{}{"name": "echo"}}
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": body["id"], "result": result,
			})
			return
		}

		if !serveLegacy {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": body["id"],
				"error": map[string]interface{}{"code": -32000, "message": "Bad Request"},
			})
			return
		}
		switch method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "sess-1")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": body["id"],
				"result": map[string]interface{}{
					"protocolVersion": "2025-06-18",
					"serverInfo":      map[string]interface{}{"name": "wire", "version": "1"},
					"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
				},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		default:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": body["id"],
				"result": map[string]interface{}{"tools": []interface{}{map[string]interface{}{"name": "echo"}}},
			})
		}
	}))
	return srv, &seen
}

func wireClient() *attack.HTTPClient {
	return attack.NewUnauthHTTPClient(attack.Options{TimeoutSeconds: 5}, attack.NewVars("", ""))
}

// A dual-era server must yield both wires. A rule that walked only the first
// would report on one era while the other went untested.
func TestOpenSessions_DualEraYieldsBothWires(t *testing.T) {
	srv, _ := wireServer(t, true, true)
	defer srv.Close()

	sessions, err := openSessions(context.Background(), wireClient(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions (legacy + modern), got %d", len(sessions))
	}
	if sessions[0].Era != EraLegacy || sessions[1].Era != EraModern {
		t.Errorf("expected legacy then modern, got %v then %v", sessions[0].Era, sessions[1].Era)
	}
	if sessions[0].SessionID == "" {
		t.Error("legacy session carries no session id")
	}
	if sessions[1].SessionID != "" {
		t.Error("modern session must carry no session id: the era has none")
	}
}

func TestOpenSessions_LegacyOnly(t *testing.T) {
	srv, _ := wireServer(t, true, false)
	defer srv.Close()

	sessions, err := openSessions(context.Background(), wireClient(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sessions) != 1 || sessions[0].Era != EraLegacy {
		t.Fatalf("expected one legacy session, got %d: %+v", len(sessions), sessions)
	}
}

// A modern-only server is the case the legacy handshake cannot reach at all, and
// the one era detection was built for.
func TestOpenSessions_ModernOnly(t *testing.T) {
	srv, _ := wireServer(t, false, true)
	defer srv.Close()

	sessions, err := openSessions(context.Background(), wireClient(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sessions) != 1 || sessions[0].Era != EraModern {
		t.Fatalf("expected one modern session, got %d: %+v", len(sessions), sessions)
	}
	if !sessions[0].ServerSupports("tools") {
		t.Error("capabilities from server/discover should read through ServerSupports unchanged")
	}
}

func TestOpenSessions_NeitherWireIsInconclusive(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()

	if _, err := openSessions(context.Background(), wireClient(), srv.URL); !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected ErrInconclusive, got %v", err)
	}
}

// The three requirements a modern request must satisfy. The fixture rejects each
// violation the way the SDK does, so a regression fails here rather than being
// mistaken for a secure server.
func TestSessionPost_ModernCarriesHeadersAndMeta(t *testing.T) {
	srv, seen := wireServer(t, false, true)
	defer srv.Close()

	sessions, err := openSessions(context.Background(), wireClient(), srv.URL)
	if err != nil {
		t.Fatalf("openSessions: %v", err)
	}
	resp, err := sessions[0].post(context.Background(), wireClient(), 1, "tools/list", nil)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	if !resp.IsAccepted() {
		t.Fatalf("modern tools/list was rejected: %s", resp.BodyString())
	}

	last := (*seen)[len(*seen)-1]
	if last.protoHdr != modernEraVersion {
		t.Errorf("MCP-Protocol-Version = %q, want %q: it is what selects the wire", last.protoHdr, modernEraVersion)
	}
	if last.methHdr != "tools/list" {
		t.Errorf("Mcp-Method = %q, want the body's method", last.methHdr)
	}
	if _, ok := last.params["_meta"].(map[string]interface{}); !ok {
		t.Errorf("params._meta missing; the SDK rejects that with -32602")
	}
	if last.headers.Get("Mcp-Session-Id") != "" {
		t.Error("a modern request must not carry a session id")
	}
}

// The legacy wire is unchanged: session id and negotiated version, no _meta and
// no Mcp-Method.
func TestSessionPost_LegacyUnchanged(t *testing.T) {
	srv, seen := wireServer(t, true, false)
	defer srv.Close()

	sessions, err := openSessions(context.Background(), wireClient(), srv.URL)
	if err != nil {
		t.Fatalf("openSessions: %v", err)
	}
	if _, err := sessions[0].post(context.Background(), wireClient(), 2, "tools/list", nil); err != nil {
		t.Fatalf("post: %v", err)
	}

	last := (*seen)[len(*seen)-1]
	if last.headers.Get("Mcp-Session-Id") != "sess-1" {
		t.Errorf("legacy request lost its session id, got %q", last.headers.Get("Mcp-Session-Id"))
	}
	if last.methHdr != "" {
		t.Errorf("legacy request should not carry Mcp-Method, got %q", last.methHdr)
	}
	if _, ok := last.params["_meta"]; ok {
		t.Error("legacy request should not carry params._meta")
	}
}

// post must not write into the caller's params, because a rule driving both wires
// reuses one map.
func TestSessionPost_DoesNotMutateCallerParams(t *testing.T) {
	srv, _ := wireServer(t, false, true)
	defer srv.Close()

	sessions, err := openSessions(context.Background(), wireClient(), srv.URL)
	if err != nil {
		t.Fatalf("openSessions: %v", err)
	}
	params := map[string]interface{}{"uri": "file://a"}
	if _, err := sessions[0].post(context.Background(), wireClient(), 3, "resources/read", params); err != nil {
		t.Fatalf("post: %v", err)
	}
	if _, injected := params["_meta"]; injected {
		t.Error("post injected _meta into the caller's map")
	}
}

func TestModernResultPayload_StripsTheEnvelope(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":1,"result":{"cacheScope":"private","resultType":"complete",` +
		`"ttlMs":0,"_meta":{},"tools":[{"name":"echo"}]}}`)

	payload, err := modernResultPayload(body)
	if err != nil {
		t.Fatalf("modernResultPayload: %v", err)
	}
	if len(payload) != 1 {
		t.Fatalf("expected only the payload key to survive, got %v", keysOf(payload))
	}
	if _, ok := payload["tools"]; !ok {
		t.Errorf("payload lost its tools key, got %v", keysOf(payload))
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
