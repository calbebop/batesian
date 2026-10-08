package mcp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

// toolsUnauthServer records any invocation, including unknown tool names.
func toolsUnauthServer(advertiseTools bool, listErrorCode int, listTools []interface{}, calls *atomic.Int32) *httptest.Server {
	if listTools == nil {
		listTools = []interface{}{
			map[string]interface{}{"name": "echo", "description": "Echo input"},
			map[string]interface{}{"name": "run_query", "description": "Run a database query"},
		}
	}
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
			if listErrorCode != 0 {
				message := "Internal error"
				if listErrorCode == -32001 {
					message = "Unauthorized"
				}
				enc(map[string]interface{}{"jsonrpc": "2.0", "id": req["id"],
					"error": map[string]interface{}{"code": listErrorCode, "message": message}})
				return
			}
			enc(map[string]interface{}{
				"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]interface{}{
					"tools": listTools,
				},
			})
		case "tools/call":
			if calls != nil {
				calls.Add(1)
			}
			enc(map[string]interface{}{"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]interface{}{"content": []interface{}{}}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
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

// A server that dispatches any tool name must not receive tools/call.
func TestToolsUnauth_ToolsExposed(t *testing.T) {
	var calls atomic.Int32
	srv := toolsUnauthServer(true, 0, nil, &calls)
	defer srv.Close()

	findings := runToolsUnauth(t, srv)
	if len(findings) != 1 {
		t.Fatalf("expected one list finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Severity != "medium" || findings[0].Confidence != attack.ConfirmedExploit {
		t.Errorf("expected a confirmed medium list finding, got %+v", findings[0])
	}
	if calls.Load() != 0 {
		t.Fatalf("scanner sent %d tools/call request(s)", calls.Load())
	}
}

func TestToolsUnauth_IgnoresUnmatchedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "initialize":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID,
				"result": map[string]interface{}{
					"protocolVersion": "2025-03-26",
					"serverInfo":      map[string]string{"name": "mismatched-id", "version": "1"},
					"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
				},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": 999,
				"result": map[string]interface{}{"tools": []map[string]string{{"name": "admin"}}},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	assertInconclusive(t, mcpattack.NewToolsUnauthExecutor(attack.RuleContext{ID: "mcp-tools-unauth-001"}), srv.URL, testOpts())
}

func TestToolsUnauth_FollowsEmptyCursor(t *testing.T) {
	var followed atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string                     `json:"method"`
			ID     json.RawMessage            `json:"id"`
			Params map[string]json.RawMessage `json:"params"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		reply := func(result interface{}) {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID, "result": result,
			})
		}
		switch req.Method {
		case "initialize":
			reply(map[string]interface{}{
				"protocolVersion": "2025-03-26",
				"serverInfo":      map[string]string{"name": "paged-tools", "version": "1"},
				"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			if raw, ok := req.Params["cursor"]; ok {
				var cursor string
				if json.Unmarshal(raw, &cursor) != nil || cursor != "" {
					http.Error(w, "unexpected cursor", http.StatusBadRequest)
					return
				}
				followed.Store(true)
				reply(map[string]interface{}{"tools": []map[string]string{{"name": "later_tool"}}})
				return
			}
			reply(map[string]interface{}{"tools": []interface{}{}, "nextCursor": ""})
		default:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID,
				"error": map[string]interface{}{"code": -32601, "message": "Method not found"},
			})
		}
	}))
	defer srv.Close()

	findings := runToolsUnauth(t, srv)
	if len(findings) != 1 || !followed.Load() {
		t.Fatalf("expected a finding for the later tool, got findings=%+v followed=%t", findings, followed.Load())
	}
	if findings[0].Confidence != attack.ConfirmedExploit {
		t.Fatalf("expected a confirmed finding, got %+v", findings[0])
	}
}

func TestToolsUnauth_IncompleteEmptyListing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string                     `json:"method"`
			ID     json.RawMessage            `json:"id"`
			Params map[string]json.RawMessage `json:"params"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		switch req.Method {
		case "initialize":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID,
				"result": map[string]interface{}{
					"protocolVersion": "2025-03-26",
					"serverInfo":      map[string]string{"name": "paged-tools", "version": "1"},
					"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
				},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			if _, ok := req.Params["cursor"]; ok {
				http.Error(w, "unavailable", http.StatusBadGateway)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID,
				"result": map[string]interface{}{"tools": []interface{}{}, "nextCursor": "later"},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	assertInconclusive(t, mcpattack.NewToolsUnauthExecutor(attack.RuleContext{ID: "mcp-tools-unauth-001"}), srv.URL, testOpts())
}

// TestToolsUnauth_AuthEnforced: tools/list itself requires auth => no findings.
func TestToolsUnauth_AuthEnforced(t *testing.T) {
	srv := toolsUnauthServer(true, -32001, nil, nil)
	defer srv.Close()

	if findings := runToolsUnauth(t, srv); len(findings) != 0 {
		t.Errorf("expected 0 findings when auth is enforced, got %d: %+v", len(findings), findings)
	}
}

// TestToolsUnauth_NoToolsCapability: server does not advertise tools => skip.
func TestToolsUnauth_NoToolsCapability(t *testing.T) {
	srv := toolsUnauthServer(false, 0, nil, nil)
	defer srv.Close()

	if findings := runToolsUnauth(t, srv); len(findings) != 0 {
		t.Errorf("expected 0 findings for a server without the tools capability, got %d", len(findings))
	}
}

func TestToolsUnauth_ListInternalError(t *testing.T) {
	srv := toolsUnauthServer(true, -32603, nil, nil)
	defer srv.Close()

	assertInconclusive(t, mcpattack.NewToolsUnauthExecutor(attack.RuleContext{ID: "mcp-tools-unauth-001"}), srv.URL, testOpts())
}

func TestToolsUnauth_MalformedList(t *testing.T) {
	srv := toolsUnauthServer(true, 0, []interface{}{nil, map[string]interface{}{"name": ""}}, nil)
	defer srv.Close()

	assertInconclusive(t, mcpattack.NewToolsUnauthExecutor(attack.RuleContext{ID: "mcp-tools-unauth-001"}), srv.URL, testOpts())
}

// TestToolsUnauth_NotMCP: a non-MCP server (no reachable endpoint) must report
// ErrInconclusive, not a clean pass.
func TestToolsUnauth_NotMCP(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	defer ts.Close()

	assertInconclusive(t, mcpattack.NewToolsUnauthExecutor(attack.RuleContext{ID: "mcp-tools-unauth-001"}), ts.URL, testOpts())
}
