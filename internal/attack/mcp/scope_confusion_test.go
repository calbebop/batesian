package mcp_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

// scopeOpts carries the two identities every scope run needs: A full, B
// limited, in the order the rule documents.
func scopeOpts() attack.Options {
	return attack.Options{
		TimeoutSeconds: 5,
		Principals: []attack.Principal{
			{Name: "full", Token: "tok-full-a"},
			{Name: "limited", Token: "tok-lim-b"},
		},
	}
}

// scopeServer models an MCP server with a read-only listing tool and a
// privileged delete tool.
//
//   - auth gates every non-initialize method on a known bearer token
//   - enforceWriteScope additionally refuses delete_item without the write
//     scope, before argument validation (the patched posture)
type scopeServer struct {
	auth              bool
	enforceWriteScope bool
}

func (s *scopeServer) validToken(token string) bool {
	return token == "tok-full-a" || token == "tok-lim-b"
}

func (s *scopeServer) hasWrite(token string) bool { return token == "tok-full-a" }

func (s *scopeServer) tools() []map[string]interface{} {
	return []map[string]interface{}{
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

// TestScope_VulnerableFires: both tokens authenticate; only the full one
// should reach delete_item. The limited one dispatches identically while the
// anonymous control is refused, which is the confirmed failure.
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

// TestScope_PatchedStaysSilent: the limited token is refused with
// insufficient_scope before validation on the privileged call. The boundary
// held; MUST stay silent.
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

// TestScope_OpenSuppressed: no authentication anywhere. The anonymous control
// dispatches, so identity gates nothing and the surface belongs to
// mcp-tools-unauth-001 rather than to a scope verdict.
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

// TestScope_MissingPrincipalsNotTested: one identity cannot cross a scope
// boundary. With no credentials configured but the tool surface reachable,
// the rule reports not tested naming what is missing, never clean.
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

// TestScope_LimitedRefusedNotTested: the limited token is dead, so its
// refusals say nothing about scoping. The rule reports not tested naming it.
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

// TestScope_NoPrivilegedCandidatesClean: only read-only annotated tools are
// listed, so nothing qualifies as privileged and the wire is clean by
// determination rather than by silence.
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
		// Hand the buffered body back before delegating: the probe above
		// consumed the stream, and the wrapped handler routes on it too.
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
