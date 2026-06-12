package mcp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

func canaryRuleCtx() attack.RuleContext {
	return attack.RuleContext{ID: "mcp-secret-canary-001", Name: "MCP Credential Canary", Severity: "medium", Remediation: "Redact secrets."}
}

// canaryServer models an MCP server. mode controls whether it reflects the
// presented bearer token:
//   - "reflect": auth-failure error body echoes the presented token (vulnerable)
//   - "clean":   never echoes the token; returns normal JSON-RPC replies
//   - "nonmcp":  not a JSON-RPC server
func canaryServer(mode string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mode == "nonmcp" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("hello world"))
			return
		}
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		id := req["id"]
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		w.Header().Set("Content-Type", "application/json")

		if mode == "reflect" {
			// VULNERABLE: echo the presented token in the error message.
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"error": map[string]interface{}{"code": -32000, "message": "invalid token: " + token},
			})
			return
		}
		// clean: behave like a normal server, never echoing the token.
		method, _ := req["method"].(string)
		switch method {
		case "initialize":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{
					"protocolVersion": "2025-06-18",
					"serverInfo":      map[string]interface{}{"name": "clean", "version": "1.0"},
					"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
				},
			})
		case "tools/list":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": id, "result": map[string]interface{}{"tools": []interface{}{}}})
		default:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": id, "error": map[string]interface{}{"code": -32601, "message": "method not found"}})
		}
	}))
}

func runCanary(t *testing.T, ts *httptest.Server) []attack.Finding {
	t.Helper()
	findings, err := mcpattack.NewSecretCanaryExecutor(canaryRuleCtx()).Execute(context.Background(), ts.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return findings
}

// TestCanary_Reflect: server echoes the presented token => confirmed.
func TestCanary_Reflect(t *testing.T) {
	ts := canaryServer("reflect")
	defer ts.Close()

	findings := runCanary(t, ts)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Confidence != attack.ConfirmedExploit || findings[0].Severity != "medium" {
		t.Errorf("want medium/ConfirmedExploit, got %q/%q", findings[0].Severity, findings[0].Confidence)
	}
}

// TestCanary_Clean: server never echoes the token => no finding.
func TestCanary_Clean(t *testing.T) {
	ts := canaryServer("clean")
	defer ts.Close()

	if findings := runCanary(t, ts); len(findings) != 0 {
		t.Errorf("expected zero findings against a clean server, got %d: %+v", len(findings), findings)
	}
}

// TestCanary_NonMCP: non-JSON-RPC server => no finding.
func TestCanary_NonMCP(t *testing.T) {
	ts := canaryServer("nonmcp")
	defer ts.Close()

	if findings := runCanary(t, ts); len(findings) != 0 {
		t.Errorf("expected zero findings against a non-MCP server, got %d", len(findings))
	}
}
