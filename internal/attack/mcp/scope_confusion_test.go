package mcp_test

import (
	"context"
	"encoding/json"
	"errors"
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
	auth                    bool
	enforceWriteScope       bool
	extraTool               bool
	modernOnly              bool
	requireInitializedAuth  bool
	rejectInitialized       bool
	bindSessions            bool
	hideLimitedTool         bool
	limitedToolError        string
	limitedResultText       string
	toolResultError         bool
	anonymousCallStatus     int
	anonymousCallError      string
	anonymousCallResult     string
	initializeResponseID    int
	listResponseID          int
	anonymousCallResponseID int
	fullCallResponseID      int
	limitedCallResponseID   int
	initialized             atomic.Bool
	limitedInitialized      atomic.Bool
	toolCalls               atomic.Int32
}

func (s *scopeServer) validToken(token string) bool {
	return token == "tok-full-a" || token == "tok-lim-b"
}

func (s *scopeServer) hasWrite(token string) bool { return token == "tok-full-a" }

func scopeSessionID(token string) string {
	if token == "tok-lim-b" {
		return "sess-limited"
	}
	return "sess-full"
}

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
			Method string          `json:"method"`
			ID     json.RawMessage `json:"id"`
			Params struct {
				Name      string                 `json:"name"`
				Arguments map[string]interface{} `json:"arguments"`
				Meta      map[string]interface{} `json:"_meta"`
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
			id := interface{}(req.ID)
			if req.Method == "tools/call" {
				switch strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") {
				case "tok-full-a":
					if s.fullCallResponseID != 0 {
						id = s.fullCallResponseID
					}
				case "tok-lim-b":
					if s.limitedCallResponseID != 0 {
						id = s.limitedCallResponseID
					}
				}
			}
			reply(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"error": map[string]interface{}{"code": code, "message": msg},
			}, status)
		}

		if s.modernOnly {
			if req.Method == "initialize" {
				rpcErr(-32601, "Method not found", http.StatusOK)
				return
			}
			if r.Header.Get("MCP-Protocol-Version") != "2026-07-28" ||
				r.Header.Get("Mcp-Method") != req.Method ||
				req.Params.Meta["io.modelcontextprotocol/protocolVersion"] != "2026-07-28" ||
				(req.Method == "tools/call" && r.Header.Get("Mcp-Name") != req.Params.Name) {
				rpcErr(-32020, "modern wire required", http.StatusBadRequest)
				return
			}
		} else {
			switch req.Method {
			case "initialize":
				if s.bindSessions {
					token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
					if !s.validToken(token) {
						w.WriteHeader(http.StatusUnauthorized)
						return
					}
					w.Header().Set("Mcp-Session-Id", scopeSessionID(token))
					if token == "tok-lim-b" {
						s.limitedInitialized.Store(true)
					}
				} else {
					w.Header().Set("Mcp-Session-Id", "sess-scope")
				}
				id := interface{}(req.ID)
				if s.initializeResponseID != 0 {
					id = s.initializeResponseID
				}
				reply(map[string]interface{}{
					"jsonrpc": "2.0", "id": id,
					"result": map[string]interface{}{
						"protocolVersion": "2025-06-18",
						"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
						"serverInfo":      map[string]interface{}{"name": "scope-fixture", "version": "1"},
					},
				}, http.StatusOK)
				return
			case "notifications/initialized":
				if s.rejectInitialized {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				if s.bindSessions {
					token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
					if !s.validToken(token) || r.Header.Get("Mcp-Session-Id") != scopeSessionID(token) {
						w.WriteHeader(http.StatusForbidden)
						return
					}
				}
				if s.requireInitializedAuth {
					token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
					if !s.validToken(token) {
						w.WriteHeader(http.StatusUnauthorized)
						return
					}
					s.initialized.Store(true)
				}
				w.WriteHeader(http.StatusAccepted)
				return
			}
		}

		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token == "" && req.Method == "tools/call" {
			if s.anonymousCallStatus != 0 {
				w.WriteHeader(s.anonymousCallStatus)
				return
			}
			if s.anonymousCallError != "" {
				id := interface{}(req.ID)
				if s.anonymousCallResponseID != 0 {
					id = s.anonymousCallResponseID
				}
				reply(map[string]interface{}{
					"jsonrpc": "2.0", "id": id,
					"error": map[string]interface{}{"code": -32602, "message": s.anonymousCallError},
				}, http.StatusOK)
				return
			}
			if s.anonymousCallResult != "" {
				reply(map[string]interface{}{
					"jsonrpc": "2.0", "id": req.ID,
					"result": map[string]interface{}{
						"content": []map[string]interface{}{{"type": "text", "text": s.anonymousCallResult}},
						"isError": true,
					},
				}, http.StatusOK)
				return
			}
		}
		if s.auth && !s.validToken(token) {
			rpcErr(-32000, "unauthorized: missing or invalid bearer token", http.StatusUnauthorized)
			return
		}
		if s.bindSessions && r.Header.Get("Mcp-Session-Id") != scopeSessionID(token) {
			rpcErr(-32000, "session belongs to another principal", http.StatusForbidden)
			return
		}
		if s.requireInitializedAuth && !s.initialized.Load() {
			rpcErr(-32000, "session not initialized", http.StatusConflict)
			return
		}

		switch req.Method {
		case "server/discover":
			if !s.modernOnly {
				rpcErr(-32601, "Method not found", http.StatusOK)
				return
			}
			reply(map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID,
				"result": map[string]interface{}{
					"resultType":        "complete",
					"supportedVersions": []string{"2026-07-28"},
					"capabilities":      map[string]interface{}{"tools": map[string]interface{}{}},
					"serverInfo":        map[string]interface{}{"name": "scope-fixture", "version": "1"},
				},
			}, http.StatusOK)
		case "tools/list":
			tools := s.tools()
			if s.hideLimitedTool && token == "tok-lim-b" {
				tools = tools[:1]
			}
			result := map[string]interface{}{"tools": tools}
			if s.modernOnly {
				result["resultType"] = "complete"
			}
			id := interface{}(req.ID)
			if s.listResponseID != 0 {
				id = s.listResponseID
			}
			reply(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"result": result,
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
				if token == "tok-lim-b" && s.limitedToolError != "" {
					rpcErr(-32602, s.limitedToolError, http.StatusOK)
					return
				}
				if s.enforceWriteScope && !s.hasWrite(token) {
					rpcErr(-32000, "insufficient_scope: items:write required", http.StatusForbidden)
					return
				}
				itemID, _ := req.Params.Arguments["item_id"].(string)
				msg := "Item " + itemID + " not found"
				if itemID == "" {
					msg = "invalid params: item_id required"
				}
				if s.toolResultError {
					if token == "tok-lim-b" && s.limitedResultText != "" {
						msg = s.limitedResultText
					}
					reply(map[string]interface{}{
						"jsonrpc": "2.0", "id": req.ID,
						"result": map[string]interface{}{
							"content": []map[string]interface{}{{"type": "text", "text": msg}},
							"isError": true,
						},
					}, http.StatusOK)
					return
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

func TestScope_MismatchedResponseID(t *testing.T) {
	for _, tc := range []struct {
		name   string
		server *scopeServer
	}{
		{name: "initialization", server: &scopeServer{auth: true, initializeResponseID: 99}},
		{name: "tool listing", server: &scopeServer{auth: true, listResponseID: 99}},
		{name: "anonymous control", server: &scopeServer{auth: true, anonymousCallError: "unauthorized", anonymousCallResponseID: 99}},
		{name: "full call", server: &scopeServer{auth: true, fullCallResponseID: 99}},
		{name: "limited call", server: &scopeServer{auth: true, limitedCallResponseID: 99}},
		{name: "modern limited call", server: &scopeServer{modernOnly: true, auth: true, limitedCallResponseID: 99}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.server
			ts := httptest.NewServer(s.handler())
			defer ts.Close()

			findings, err := runScope(t, ts)
			if !errors.Is(err, attack.ErrInconclusive) || len(findings) != 0 {
				t.Fatalf("expected an inconclusive mismatched response, got findings=%+v err=%v", findings, err)
			}
		})
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

func TestScope_InitializedNotificationUsesPrincipal(t *testing.T) {
	s := &scopeServer{auth: true, requireInitializedAuth: true}
	ts := httptest.NewServer(s.handler())
	defer ts.Close()

	findings, err := runScope(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !s.initialized.Load() || len(findings) != 1 {
		t.Fatalf("expected an authenticated session and one finding, got initialized=%t findings=%d: %+v",
			s.initialized.Load(), len(findings), findings)
	}
}

func TestScope_RejectedInitializedIsInconclusive(t *testing.T) {
	s := &scopeServer{auth: true, rejectInitialized: true}
	ts := httptest.NewServer(s.handler())
	defer ts.Close()

	findings, err := runScope(t, ts)
	if !errors.Is(err, attack.ErrInconclusive) || !strings.Contains(err.Error(), "initialized notification") {
		t.Fatalf("expected an initialization refusal, got findings=%+v err=%v", findings, err)
	}
	if len(findings) != 0 || s.toolCalls.Load() != 0 {
		t.Fatalf("rejected initialization must not be probed: findings=%+v calls=%d", findings, s.toolCalls.Load())
	}
}

func TestScope_PrincipalBoundSessions(t *testing.T) {
	for _, tc := range []struct {
		name              string
		enforceWriteScope bool
		wantFindings      int
	}{
		{name: "vulnerable", wantFindings: 1},
		{name: "scoped", enforceWriteScope: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &scopeServer{auth: true, bindSessions: true, enforceWriteScope: tc.enforceWriteScope}
			ts := httptest.NewServer(s.handler())
			defer ts.Close()

			findings, err := runScope(t, ts)
			if err != nil || len(findings) != tc.wantFindings || !s.limitedInitialized.Load() {
				t.Fatalf("expected %d findings with both principals initialized, got findings=%+v err=%v limited=%t",
					tc.wantFindings, findings, err, s.limitedInitialized.Load())
			}
		})
	}
}

func TestScope_HiddenToolResponses(t *testing.T) {
	for _, tc := range []struct {
		name         string
		toolError    string
		resultText   string
		wantFindings int
	}{
		{name: "hidden but callable", wantFindings: 1},
		{name: "generic tool result", resultText: "Not found", wantFindings: 1},
		{name: "unknown tool", toolError: "Unknown tool: delete_item"},
		{name: "tool not found", toolError: "Tool delete_item not found"},
		{name: "no such tool", toolError: "No such tool: delete_item"},
		{name: "method not found", toolError: "Method not found"},
		{name: "generic protocol not found", toolError: "Not found"},
		{name: "protocol invalid params", toolError: "Invalid params"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &scopeServer{auth: true, hideLimitedTool: true, limitedToolError: tc.toolError,
				limitedResultText: tc.resultText, toolResultError: true}
			ts := httptest.NewServer(s.handler())
			defer ts.Close()

			findings, err := runScope(t, ts)
			if err != nil || len(findings) != tc.wantFindings {
				t.Fatalf("expected %d findings, got findings=%+v err=%v", tc.wantFindings, findings, err)
			}
		})
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

func TestScope_AnonymousControlNeedsVerdict(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		msg    string
		result string
	}{
		{name: "server error", status: http.StatusServiceUnavailable},
		{name: "unknown tool", msg: "Unknown tool: delete_item"},
		{name: "business error", result: "Not allowed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &scopeServer{auth: true, anonymousCallStatus: tc.status,
				anonymousCallError: tc.msg, anonymousCallResult: tc.result}
			ts := httptest.NewServer(s.handler())
			defer ts.Close()

			findings, err := runScope(t, ts)
			if !errors.Is(err, attack.ErrInconclusive) || !strings.Contains(err.Error(), "anonymous control") {
				t.Fatalf("expected an inconclusive anonymous control, got findings=%+v err=%v", findings, err)
			}
			if len(findings) != 0 || s.toolCalls.Load() != 0 {
				t.Fatalf("probes continued after an unanswered control: findings=%+v calls=%d",
					findings, s.toolCalls.Load())
			}
		})
	}
}

func TestScope_AnonymousProtocolAuthRefusal(t *testing.T) {
	s := &scopeServer{auth: true, anonymousCallError: "unauthorized"}
	ts := httptest.NewServer(s.handler())
	defer ts.Close()

	findings, err := runScope(t, ts)
	if err != nil || len(findings) != 1 {
		t.Fatalf("expected one finding after an explicit auth refusal, got findings=%+v err=%v", findings, err)
	}
}

func TestScope_ModernOnly(t *testing.T) {
	for _, tc := range []struct {
		name              string
		auth              bool
		enforceWriteScope bool
		findings          int
	}{
		{name: "vulnerable", auth: true, findings: 1},
		{name: "patched", auth: true, enforceWriteScope: true},
		{name: "open"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := &scopeServer{modernOnly: true, auth: tc.auth, enforceWriteScope: tc.enforceWriteScope}
			ts := httptest.NewServer(srv.handler())
			defer ts.Close()

			findings, err := runScope(t, ts)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(findings) != tc.findings {
				t.Fatalf("expected %d findings, got %d: %+v", tc.findings, len(findings), findings)
			}
			if tc.findings > 0 && !strings.Contains(findings[0].Evidence, "wire: MCP 2026-07-28") {
				t.Errorf("expected modern wire evidence, got: %q", findings[0].Evidence)
			}
		})
	}
}

func TestScope_ModernOnlyRequiresToolApproval(t *testing.T) {
	srv := &scopeServer{modernOnly: true, auth: true}
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	opts := scopeOpts()
	opts.MCPScopeTools = nil
	_, err := mcp.NewScopeConfusionExecutor(scopeRC()).Execute(context.Background(), ts.URL, opts)
	if err == nil || !strings.Contains(err.Error(), "--mcp-scope-tool") {
		t.Fatalf("expected an approval error, got %v", err)
	}
	if srv.toolCalls.Load() != 0 {
		t.Fatalf("unapproved tool received %d call(s)", srv.toolCalls.Load())
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
			Method string          `json:"method"`
			ID     json.RawMessage `json:"id"`
		}
		if json.Unmarshal(raw, &probe) != nil {
			http.NotFound(w, r)
			return
		}
		if probe.Method == "tools/list" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": probe.ID,
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
