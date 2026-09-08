package mcp_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcp "github.com/calbebop/batesian/internal/attack/mcp"
)

func scopeRC() attack.RuleContext {
	return attack.RuleContext{
		ID:          "mcp-scope-confusion-001",
		Name:        "MCP Tool Scope Confusion",
		Severity:    "high",
		Remediation: "Check tool scopes at dispatch, after authentication.",
	}
}

func scopeOpts() attack.Options {
	return attack.Options{
		TimeoutSeconds: 5,
		MCPScopeTools:  []string{"delete_item"},
		Principals: []attack.Principal{
			{Name: "full", Token: "tok-full-a"},
			{Name: "limited", Token: "tok-lim-b"},
		},
	}
}

type scopeServer struct {
	auth              bool
	enforceWriteScope bool
	extraTool         bool
	toolCalls         atomic.Int32
}

func (s *scopeServer) validToken(token string) bool {
	return token == "tok-full-a" || token == "tok-lim-b"
}

func (s *scopeServer) hasWrite(token string) bool { return token == "tok-full-a" }

func (s *scopeServer) tools() []map[string]interface{} {
	tools := []map[string]interface{}{
		{
			"name":        "list_items",
			"annotations": map[string]interface{}{"readOnlyHint": true},
			"inputSchema": map[string]interface{}{
				"type": "object", "properties": map[string]interface{}{}, "required": []interface{}{},
			},
		},
		{
			"name":        "delete_item",
			"annotations": map[string]interface{}{"readOnlyHint": false},
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"item_id": map[string]interface{}{"type": "string"},
				},
				"required": []interface{}{"item_id"},
			},
		},
	}
	if s.extraTool {
		tools = append(tools, map[string]interface{}{
			"name":        "send_email",
			"annotations": map[string]interface{}{"readOnlyHint": false},
			"inputSchema": map[string]interface{}{"type": "object"},
		})
	}
	return tools
}

func (s *scopeServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string      `json:"method"`
			ID     json.Number `json:"id"`
			Params struct {
				Name      string                 `json:"name"`
				Arguments map[string]interface{} `json:"arguments"`
			} `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)

		reply := func(payload map[string]interface{}, status int) {
			if status != http.StatusOK {
				w.WriteHeader(status)
			}
			_ = json.NewEncoder(w).Encode(payload)
		}
		rpcErr := func(code int, msg string, status int) {
			reply(map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID,
				"error": map[string]interface{}{"code": code, "message": msg},
			}, status)
		}

		switch req.Method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "sess-scope")
			reply(map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID,
				"result": map[string]interface{}{
					"protocolVersion": "2025-06-18",
					"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
					"serverInfo":      map[string]interface{}{"name": "scope-fixture", "version": "1"},
				},
			}, http.StatusOK)
			return
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
			return
		}

		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if s.auth && !s.validToken(token) {
			rpcErr(-32000, "unauthorized: missing or invalid bearer token", http.StatusUnauthorized)
			return
		}

		switch req.Method {
		case "tools/list":
			reply(map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID,
				"result": map[string]interface{}{"tools": s.tools()},
			}, http.StatusOK)

		case "tools/call":
			s.toolCalls.Add(1)
			switch req.Params.Name {
			case "list_items":
				reply(map[string]interface{}{
					"jsonrpc": "2.0", "id": req.ID,
					"result": map[string]interface{}{
						"content": []map[string]interface{}{{"type": "text", "text": "0 item(s)"}},
					},
				}, http.StatusOK)
			case "delete_item":
				if s.enforceWriteScope && !s.hasWrite(token) {
					rpcErr(-32000, "insufficient_scope: items:write required", http.StatusForbidden)
					return
				}
				itemID, _ := req.Params.Arguments["item_id"].(string)
				msg := "Item " + itemID + " not found"
				if itemID == "" {
					msg = "invalid params: item_id required"
				}
				rpcErr(-32602, msg, http.StatusOK)
			default:
				rpcErr(-32601, "Method not found", http.StatusOK)
			}

		default:
			rpcErr(-32601, "Method not found", http.StatusOK)
		}
	}
}

func runScope(t *testing.T, ts *httptest.Server) ([]attack.Finding, error) {
	t.Helper()
	return mcp.NewScopeConfusionExecutor(scopeRC()).Execute(context.Background(), ts.URL, scopeOpts())
}

func TestScope_VulnerableFires(t *testing.T) {
	ts := httptest.NewServer((&scopeServer{auth: true}).handler())
	defer ts.Close()

	findings, err := runScope(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Confidence != attack.ConfirmedExploit || f.Severity != "high" {
		t.Errorf("want high/ConfirmedExploit, got %q/%q", f.Severity, f.Confidence)
	}
	if !strings.Contains(f.Evidence, "limited principal") {
		t.Errorf("evidence should name the limited principal's dispatch, got: %q", f.Evidence)
	}
}

func TestScope_PatchedStaysSilent(t *testing.T) {
	ts := httptest.NewServer((&scopeServer{auth: true, enforceWriteScope: true}).handler())
	defer ts.Close()

	findings, err := runScope(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings when scopes are enforced, got %d: %+v", len(findings), findings)
	}
}

func TestScope_OpenSuppressed(t *testing.T) {
	ts := httptest.NewServer((&scopeServer{auth: false}).handler())
	defer ts.Close()

	findings, err := runScope(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings against an open server, got %d: %+v", len(findings), findings)
	}
}

func TestScope_MissingPrincipalsNotTested(t *testing.T) {
	ts := httptest.NewServer((&scopeServer{auth: false}).handler())
	defer ts.Close()

	findings, err := mcp.NewScopeConfusionExecutor(scopeRC()).
		Execute(context.Background(), ts.URL, attack.Options{TimeoutSeconds: 5})
	if err == nil {
		t.Fatalf("expected an inconclusive error with fewer than two principals")
	}
	if !strings.Contains(err.Error(), "principal") {
		t.Errorf("expected the reason to name the missing principals, got: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings alongside the inconclusive result, got %d", len(findings))
	}
}

func TestScope_LimitedRefusedNotTested(t *testing.T) {
	ts := httptest.NewServer((&scopeServer{auth: true, enforceWriteScope: true}).handler())
	defer ts.Close()

	opts := scopeOpts()
	opts.Principals[1].Token = "tok-dead"
	findings, err := mcp.NewScopeConfusionExecutor(scopeRC()).Execute(context.Background(), ts.URL, opts)
	if err == nil {
		t.Fatalf("expected an inconclusive error when the limited credential is refused outright")
	}
	if !strings.Contains(err.Error(), "limited principal") {
		t.Errorf("expected the reason to name the limited principal, got: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings alongside the inconclusive result, got %d", len(findings))
	}
}

func TestScope_NoPrivilegedCandidatesClean(t *testing.T) {
	base := (&scopeServer{auth: true}).handler()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		var probe struct {
			Method string `json:"method"`
		}
		if json.Unmarshal(raw, &probe) != nil {
			http.NotFound(w, r)
			return
		}
		if probe.Method == "tools/list" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": 1,
				"result": map[string]interface{}{"tools": []map[string]interface{}{{
					"name":        "list_items",
					"annotations": map[string]interface{}{"readOnlyHint": true},
					"inputSchema": map[string]interface{}{
						"type": "object", "properties": map[string]interface{}{}, "required": []interface{}{},
					},
				}}},
			})
			return
		}
		// Restore the body for the wrapped handler.
		r.Body = io.NopCloser(strings.NewReader(string(raw)))
		base.ServeHTTP(w, r)
	}))
	defer ts.Close()

	findings, err := runScope(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings with no privileged candidates, got %d: %+v", len(findings), findings)
	}
}

func TestScope_RequiresToolApproval(t *testing.T) {
	srv := &scopeServer{auth: true}
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	opts := scopeOpts()
	opts.MCPScopeTools = nil
	findings, err := mcp.NewScopeConfusionExecutor(scopeRC()).Execute(context.Background(), ts.URL, opts)
	if err == nil || !strings.Contains(err.Error(), "--mcp-scope-tool") {
		t.Fatalf("expected an approval error, got findings=%d err=%v", len(findings), err)
	}
	if srv.toolCalls.Load() != 0 {
		t.Fatalf("unapproved tool received %d call(s)", srv.toolCalls.Load())
	}
}

func TestScope_ToolApprovalIsExact(t *testing.T) {
	for _, name := range []string{"delete", "Delete_Item", "*", "delete_item "} {
		t.Run(name, func(t *testing.T) {
			srv := &scopeServer{auth: true}
			ts := httptest.NewServer(srv.handler())
			defer ts.Close()

			opts := scopeOpts()
			opts.MCPScopeTools = []string{name}
			_, err := mcp.NewScopeConfusionExecutor(scopeRC()).Execute(context.Background(), ts.URL, opts)
			if err == nil {
				t.Fatal("expected an approval error")
			}
			if srv.toolCalls.Load() != 0 {
				t.Fatalf("inexact approval made %d call(s)", srv.toolCalls.Load())
			}
		})
	}
}

func TestScope_PartialApprovalBlocksAllCalls(t *testing.T) {
	srv := &scopeServer{auth: true, extraTool: true}
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	_, err := mcp.NewScopeConfusionExecutor(scopeRC()).Execute(context.Background(), ts.URL, scopeOpts())
	if err == nil || !strings.Contains(err.Error(), "send_email") {
		t.Fatalf("expected missing approval for send_email, got %v", err)
	}
	if srv.toolCalls.Load() != 0 {
		t.Fatalf("partial approval made %d call(s)", srv.toolCalls.Load())
	}
}
