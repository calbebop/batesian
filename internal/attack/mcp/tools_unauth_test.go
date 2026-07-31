package mcp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

// toolsUnauthServer builds a mock MCP server. callBehavior controls how
// tools/call answers an unknown tool name:
//   - "unknown": JSON-RPC -32602 "Unknown tool" (dispatch reached, no auth)
//   - "internal": JSON-RPC -32603 internal error (dispatch reached, no auth)
//   - "authgate": JSON-RPC -32001 "Unauthorized" (call gated behind auth)
//
// When advertiseTools is false the server omits the tools capability. When
// listAuth is true tools/list itself returns an auth error.
func toolsUnauthServer(advertiseTools, listAuth bool, callBehavior string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		method, _ := req["method"].(string)
		w.Header().Set("Content-Type", "application/json")
		enc := func(v map[string]interface{}) { _ = json.NewEncoder(w).Encode(v) }

		switch method {
		case "initialize":
			caps := map[string]interface{}{"resources": map[string]interface{}{}}
			if advertiseTools {
				caps["tools"] = map[string]interface{}{"listChanged": false}
			}
			enc(map[string]interface{}{
				"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]interface{}{
					"protocolVersion": "2025-03-26",
					"serverInfo":      map[string]interface{}{"name": "tools-srv", "version": "1.0"},
					"capabilities":    caps,
				},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			if listAuth {
				enc(map[string]interface{}{"jsonrpc": "2.0", "id": req["id"],
					"error": map[string]interface{}{"code": -32001, "message": "Unauthorized"}})
				return
			}
			enc(map[string]interface{}{
				"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]interface{}{
					"tools": []interface{}{
						map[string]interface{}{"name": "echo", "description": "Echo input"},
						map[string]interface{}{"name": "run_query", "description": "Run a database query"},
					},
				},
			})
		case "tools/call":
			if callBehavior == "authgate" {
				enc(map[string]interface{}{"jsonrpc": "2.0", "id": req["id"],
					"error": map[string]interface{}{"code": -32001, "message": "Unauthorized"}})
				return
			}
			if callBehavior == "internal" {
				// A non-(-32602) validation path: still proves dispatch without auth.
				enc(map[string]interface{}{"jsonrpc": "2.0", "id": req["id"],
					"error": map[string]interface{}{"code": -32603, "message": "internal error: unknown tool " + paramName(req)}})
				return
			}
			// "unknown": the scanner only ever calls a non-existent tool name.
			enc(map[string]interface{}{"jsonrpc": "2.0", "id": req["id"],
				"error": map[string]interface{}{"code": -32602, "message": "Unknown tool: " + paramName(req)}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func paramName(req map[string]interface{}) string {
	params, _ := req["params"].(map[string]interface{})
	name, _ := params["name"].(string)
	return name
}

func runToolsUnauth(t *testing.T, srv *httptest.Server) []attack.Finding {
	t.Helper()
	exec := mcpattack.NewToolsUnauthExecutor(attack.RuleContext{ID: "mcp-tools-unauth-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return findings
}

// TestToolsUnauth_ToolsExposed: tools/list leaks tools and tools/call dispatch
// is reachable unauthenticated => medium list finding + high call finding.
func TestToolsUnauth_ToolsExposed(t *testing.T) {
	srv := toolsUnauthServer(true, false, "unknown")
	defer srv.Close()

	findings := runToolsUnauth(t, srv)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (list + call), got %d: %+v", len(findings), findings)
	}
	hasMedium, hasHigh := false, false
	for _, f := range findings {
		if f.Confidence != attack.ConfirmedExploit {
			t.Errorf("expected ConfirmedExploit, got %v", f.Confidence)
		}
		switch f.Severity {
		case "medium":
			hasMedium = true
		case "high":
			hasHigh = true
		}
	}
	if !hasMedium {
		t.Error("expected medium finding for tools/list")
	}
	if !hasHigh {
		t.Error("expected high finding for tools/call reachability")
	}
}

// TestToolsUnauth_ListExposedCallEnforced: tools/list leaks but tools/call is
// auth-gated => only the medium list finding fires.
func TestToolsUnauth_ListExposedCallEnforced(t *testing.T) {
	srv := toolsUnauthServer(true, false, "authgate")
	defer srv.Close()

	findings := runToolsUnauth(t, srv)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding (list only), got %d: %+v", len(findings), findings)
	}
	if findings[0].Severity != "medium" {
		t.Errorf("expected medium list finding, got %q", findings[0].Severity)
	}
}

// TestToolsUnauth_AuthEnforced: tools/list itself requires auth => no findings.
func TestToolsUnauth_AuthEnforced(t *testing.T) {
	srv := toolsUnauthServer(true, true, "authgate")
	defer srv.Close()

	if findings := runToolsUnauth(t, srv); len(findings) != 0 {
		t.Errorf("expected 0 findings when auth is enforced, got %d: %+v", len(findings), findings)
	}
}

// TestToolsUnauth_NoToolsCapability: server does not advertise tools => skip.
func TestToolsUnauth_NoToolsCapability(t *testing.T) {
	srv := toolsUnauthServer(false, false, "unknown")
	defer srv.Close()

	if findings := runToolsUnauth(t, srv); len(findings) != 0 {
		t.Errorf("expected 0 findings for a server without the tools capability, got %d", len(findings))
	}
}

// TestToolsUnauth_CallReachableViaInternalError: tools/call surfacing a -32603
// for the non-existent tool still proves the invocation path was reached without
// auth. The old dispatch helper accepted only -32602 and reported just the list
// finding here (false negative).
func TestToolsUnauth_CallReachableViaInternalError(t *testing.T) {
	srv := toolsUnauthServer(true, false, "internal")
	defer srv.Close()

	findings := runToolsUnauth(t, srv)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (list + call via -32603), got %d: %+v", len(findings), findings)
	}
	hasHigh := false
	for _, f := range findings {
		if f.Severity == "high" {
			hasHigh = true
		}
	}
	if !hasHigh {
		t.Error("expected a high tools/call reachability finding for the -32603 response")
	}
}

// TestToolsUnauth_NotMCP: a non-MCP server (no reachable endpoint) must report
// ErrInconclusive, not a clean pass.
func TestToolsUnauth_NotMCP(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	defer ts.Close()

	assertInconclusive(t, mcpattack.NewToolsUnauthExecutor(attack.RuleContext{ID: "mcp-tools-unauth-001"}), ts.URL, testOpts())
}
