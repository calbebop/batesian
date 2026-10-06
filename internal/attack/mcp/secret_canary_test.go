package mcp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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
	return canaryServerWithCalls(mode, nil)
}

func canaryServerWithCalls(mode string, calls *atomic.Int32) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mode == "nonmcp" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("hello world"))
			return
		}
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		method, _ := req["method"].(string)
		if method == "tools/call" && calls != nil {
			calls.Add(1)
		}
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
	var calls atomic.Int32
	ts := canaryServerWithCalls("reflect", &calls)
	defer ts.Close()

	findings := runCanary(t, ts)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Confidence != attack.ConfirmedExploit || findings[0].Severity != "medium" {
		t.Errorf("want medium/ConfirmedExploit, got %q/%q", findings[0].Severity, findings[0].Confidence)
	}
	if calls.Load() != 0 {
		t.Fatalf("canary scan sent %d tools/call request(s)", calls.Load())
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

	assertInconclusive(t, mcpattack.NewSecretCanaryExecutor(canaryRuleCtx()), ts.URL, attack.Options{TimeoutSeconds: 5})
}

func modernCanaryHandler(reflectToken, legacy bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mcp" {
			http.NotFound(w, r)
			return
		}
		var req struct {
			ID     interface{} `json:"id"`
			Method string      `json:"method"`
			Params struct {
				Meta map[string]interface{} `json:"_meta"`
			} `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		write := func(field string, value interface{}) {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": req.ID, field: value})
		}
		if r.Header.Get("MCP-Protocol-Version") != modernVersion {
			if !legacy {
				write("error", map[string]interface{}{"code": -32602, "message": "modern metadata required"})
				return
			}
			switch req.Method {
			case "initialize":
				write("result", map[string]interface{}{
					"protocolVersion": "2025-11-25", "serverInfo": map[string]string{"name": "canary-test", "version": "1"},
					"capabilities": map[string]interface{}{"tools": map[string]interface{}{}},
				})
			case "notifications/initialized":
				w.WriteHeader(http.StatusAccepted)
			default:
				write("result", map[string]interface{}{"tools": []interface{}{}})
			}
			return
		}
		if r.Header.Get("Mcp-Method") != req.Method || req.Params.Meta["io.modelcontextprotocol/protocolVersion"] != modernVersion {
			write("error", map[string]interface{}{"code": -32020, "message": "header mismatch"})
			return
		}
		switch req.Method {
		case "server/discover":
			write("result", map[string]interface{}{"resultType": "complete", "supportedVersions": []string{modernVersion}})
		case "tools/list":
			if reflectToken {
				write("error", map[string]interface{}{"code": -32000, "message": "invalid token: " + strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")})
				return
			}
			write("result", map[string]interface{}{"tools": []interface{}{}})
		case "resources/list":
			write("result", map[string]interface{}{"resources": []interface{}{}})
		default:
			write("error", map[string]interface{}{"code": -32601, "message": "method not found"})
		}
	})
}

func TestCanary_ModernOnlyReflection(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("sse=%t", stream), func(t *testing.T) {
			handler := modernCanaryHandler(true, false)
			if stream {
				handler = sseWrap(handler)
			}
			ts := httptest.NewServer(handler)
			defer ts.Close()
			findings := runCanary(t, ts)
			if len(findings) != 1 {
				t.Fatalf("modern reflection: want one finding, got %+v", findings)
			}
			if !strings.Contains(findings[0].Evidence, "request: modern tools/list") {
				t.Errorf("finding lacks the modern request source: %+v", findings[0])
			}
		})
	}
}

func TestCanary_ModernOnlyClean(t *testing.T) {
	ts := httptest.NewServer(modernCanaryHandler(false, false))
	defer ts.Close()
	if findings := runCanary(t, ts); len(findings) != 0 {
		t.Fatalf("clean modern server: got %+v", findings)
	}
}

func TestCanary_DualWireModernReflection(t *testing.T) {
	ts := httptest.NewServer(modernCanaryHandler(true, true))
	defer ts.Close()
	if findings := runCanary(t, ts); len(findings) != 1 {
		t.Fatalf("dual-wire modern reflection: want one finding, got %+v", findings)
	}
}

func TestCanary_ProtocolErrorsAreInconclusive(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": 1,
			"error": map[string]interface{}{"code": -32602, "message": "invalid request"},
		})
	}))
	defer ts.Close()
	assertInconclusive(t, mcpattack.NewSecretCanaryExecutor(canaryRuleCtx()), ts.URL, attack.Options{TimeoutSeconds: 5})
}

func TestCanary_GenericJSONEchoIsNotMCP(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"error": r.Header.Get("Authorization")})
	}))
	defer ts.Close()
	assertInconclusive(t, mcpattack.NewSecretCanaryExecutor(canaryRuleCtx()), ts.URL, attack.Options{TimeoutSeconds: 5})
}
