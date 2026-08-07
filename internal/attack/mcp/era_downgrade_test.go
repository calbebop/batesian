package mcp_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

func eraDowngradeRC() attack.RuleContext {
	return attack.RuleContext{
		ID: "mcp-era-downgrade-001", Name: "MCP Protocol Era Downgrade Auth Bypass",
		Severity: "critical", Remediation: "Gate both request paths in one place.",
	}
}

// dualEraGateServer serves both wires and gates tools/list on whichever of them
// gateLegacy / gateModern say. Any combination is expressible, which is what the
// rule's discriminator has to be judged against.
//
// Both wires are always openable: the handshake and server/discover are never
// gated, so the rule is comparing method-level access rather than which era it
// could reach at all.
func dualEraGateServer(t *testing.T, gateLegacy, gateModern bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mcp" {
			http.NotFound(w, r)
			return
		}
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		method, _ := body["method"].(string)
		id := body["id"]
		modern := r.Header.Get("MCP-Protocol-Version") == "2026-07-28"
		w.Header().Set("Content-Type", "application/json")

		result := func(v map[string]interface{}) {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": id, "result": v})
		}
		refuse := func() {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"error": map[string]interface{}{"code": -32001, "message": "Unauthorized"},
			})
		}

		switch method {
		case "server/discover":
			if !modern {
				refuse()
				return
			}
			result(map[string]interface{}{
				"supportedVersions": []string{"2026-07-28"}, "resultType": "complete",
				"capabilities": map[string]interface{}{"tools": map[string]interface{}{}},
			})
		case "initialize":
			if modern {
				refuse()
				return
			}
			w.Header().Set("Mcp-Session-Id", "sess-1")
			result(map[string]interface{}{
				"protocolVersion": "2025-06-18",
				"serverInfo":      map[string]interface{}{"name": "gate", "version": "1"},
				"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			if (modern && gateModern) || (!modern && gateLegacy) {
				refuse()
				return
			}
			result(map[string]interface{}{"tools": []interface{}{map[string]interface{}{"name": "echo"}}})
		default:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"error": map[string]interface{}{"code": -32601, "message": "Method not found"},
			})
		}
	}))
}

func runEraDowngrade(t *testing.T, ts *httptest.Server) []attack.Finding {
	t.Helper()
	findings, err := mcpattack.NewEraDowngradeExecutor(eraDowngradeRC()).
		Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return findings
}

// The bug: the gate is on the handshake era only, so the stateless era answers
// without credentials.
func TestEraDowngrade_ModernWireUngated(t *testing.T) {
	ts := dualEraGateServer(t, true, false)
	defer ts.Close()

	findings := runEraDowngrade(t, ts)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != "critical" || f.Confidence != attack.ConfirmedExploit {
		t.Errorf("want critical/ConfirmedExploit, got %q/%q", f.Severity, f.Confidence)
	}
	if !strings.Contains(f.Evidence, "modern wire: tools/list") {
		t.Errorf("evidence should name the answering wire and method, got:\n%s", f.Evidence)
	}
}

// The same bug the other way round, which is just as exploitable: whichever wire
// is open is the one that gets used.
func TestEraDowngrade_LegacyWireUngated(t *testing.T) {
	ts := dualEraGateServer(t, false, true)
	defer ts.Close()

	findings := runEraDowngrade(t, ts)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Title, "not the legacy wire") {
		t.Errorf("title should name the open wire, got %q", findings[0].Title)
	}
}

// No auth anywhere is the unauth rules' finding, not an asymmetry. Reporting it
// here would double-count every unauthenticated server.
func TestEraDowngrade_NoGateAnywhereIsSuppressed(t *testing.T) {
	ts := dualEraGateServer(t, false, false)
	defer ts.Close()

	if findings := runEraDowngrade(t, ts); len(findings) != 0 {
		t.Errorf("expected zero findings when the server gates nothing, got %d: %+v", len(findings), findings)
	}
}

func TestEraDowngrade_GatedOnBothWiresIsSecure(t *testing.T) {
	ts := dualEraGateServer(t, true, true)
	defer ts.Close()

	if findings := runEraDowngrade(t, ts); len(findings) != 0 {
		t.Errorf("expected zero findings when both wires are gated, got %d: %+v", len(findings), findings)
	}
}

// A server serving one era cannot disagree with itself.
func TestEraDowngrade_SingleEraIsNotApplicable(t *testing.T) {
	for name, srv := range map[string]*httptest.Server{
		"legacy-only": legacyOnlyGateServer(t),
		"modern-only": modernOnlyGateServer(t),
	} {
		t.Run(name, func(t *testing.T) {
			defer srv.Close()
			if findings := runEraDowngrade(t, srv); len(findings) != 0 {
				t.Errorf("expected zero findings against a single-era server, got %d", len(findings))
			}
		})
	}
}

// The false positive this rule shipped with, reproduced. A server built on the
// Go SDK without StreamableHTTPOptions.Stateless answers server/discover, as
// every server must, advertises only handshake-era versions, and rejects a
// 2026-07-28 request with a plain-text HTTP 400 saying the version needs a
// stateless server. Nothing here is gated.
//
// Taking the discovery answer as a modern wire made that 400 the "refused" half
// of an asymmetry, and the rule reported a critical authorization bypass against
// a server enforcing no authorization at all.
func TestEraDowngrade_DiscoveryWithoutModernVersionIsNotAnAsymmetry(t *testing.T) {
	ts := discoveryOnLegacyServer(t)
	defer ts.Close()

	if findings := runEraDowngrade(t, ts); len(findings) != 0 {
		t.Errorf("expected zero findings: the modern wire is absent, not gated. Got %d: %+v",
			len(findings), findings)
	}
}

func discoveryOnLegacyServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		method, _ := body["method"].(string)
		id := body["id"]

		if method == "server/discover" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{"resultType": "complete",
					"supportedVersions": []string{"2025-11-25", "2025-06-18"},
					"capabilities":      map[string]interface{}{"tools": map[string]interface{}{}}}})
			return
		}
		if r.Header.Get("MCP-Protocol-Version") == "2026-07-28" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`Bad Request: protocol version "2026-07-28" is only supported on stateless HTTP servers`))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		switch method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "s")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{"protocolVersion": "2025-06-18",
					"serverInfo":   map[string]interface{}{"name": "discovery-only", "version": "1"},
					"capabilities": map[string]interface{}{"tools": map[string]interface{}{}}}})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		default:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{"tools": []interface{}{map[string]interface{}{"name": "echo"}}}})
		}
	}))
}

func TestEraDowngrade_NothingReachableIsNotTested(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	defer ts.Close()

	_, err := mcpattack.NewEraDowngradeExecutor(eraDowngradeRC()).
		Execute(context.Background(), ts.URL, testOpts())
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected ErrInconclusive, got %v", err)
	}
}

func legacyOnlyGateServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		method, _ := body["method"].(string)
		id := body["id"]
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("MCP-Protocol-Version") == "2026-07-28" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": id,
				"error": map[string]interface{}{"code": -32022, "message": "UnsupportedProtocolVersion"}})
			return
		}
		switch method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "s")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{"protocolVersion": "2025-06-18",
					"serverInfo":   map[string]interface{}{"name": "legacy", "version": "1"},
					"capabilities": map[string]interface{}{"tools": map[string]interface{}{}}}})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		default:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{"tools": []interface{}{}}})
		}
	}))
}

func modernOnlyGateServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		method, _ := body["method"].(string)
		id := body["id"]
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("MCP-Protocol-Version") != "2026-07-28" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": id,
				"error": map[string]interface{}{"code": -32000, "message": "Bad Request"}})
			return
		}
		result := map[string]interface{}{"resultType": "complete"}
		if method == "server/discover" {
			result["supportedVersions"] = []string{"2026-07-28"}
			result["capabilities"] = map[string]interface{}{"tools": map[string]interface{}{}}
		} else {
			result["tools"] = []interface{}{}
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": id, "result": result})
	}))
}
