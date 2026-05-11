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

func injectionMCPBase(_ *testing.T, toolCallHandler func(http.ResponseWriter, map[string]interface{})) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		method, _ := req["method"].(string)
		switch method {
		case "initialize":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]interface{}{
					"protocolVersion": "2025-03-26",
					"serverInfo":      map[string]interface{}{"name": "injection-test"},
					"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
				},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]interface{}{
					"tools": []interface{}{
						map[string]interface{}{
							"name":        "search",
							"description": "searches a database",
							"inputSchema": map[string]interface{}{
								"type":       "object",
								"properties": map[string]interface{}{"query": map[string]interface{}{"type": "string"}},
							},
						},
					},
				},
			})
		case "tools/call":
			toolCallHandler(w, req)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestInjectionParams_SQLErrorExposed(t *testing.T) {
	// Server interpolates query arg directly into SQL and leaks an error.
	srv := injectionMCPBase(t, func(w http.ResponseWriter, req map[string]interface{}) {
		params, _ := req["params"].(map[string]interface{})
		args, _ := params["arguments"].(map[string]interface{})
		query, _ := args["query"].(string)

		// Simulate SQL error leakage when injection characters are present
		if query == `' OR '1'='1` || query == `' OR 1=1 --` {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req["id"],
				"error": map[string]interface{}{
					"code":    -32603,
					"message": "You have an error in your SQL syntax near ''' at line 1",
				},
			})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": req["id"],
			"result": map[string]interface{}{"content": "no results"},
		})
	})
	defer srv.Close()

	exec := mcpattack.NewInjectionParamsExecutor(attack.RuleContext{ID: "mcp-injection-params-001", Remediation: "parameterize queries"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for SQL error exposure")
	}
	if findings[0].Severity != "high" {
		t.Errorf("expected high severity for SQL injection, got %s", findings[0].Severity)
	}
	if findings[0].Confidence != attack.ConfirmedExploit {
		t.Errorf("expected ConfirmedExploit, got %v", findings[0].Confidence)
	}
}

func TestInjectionParams_CommandOutputLeaked(t *testing.T) {
	// Server executes shell commands and leaks output.
	srv := injectionMCPBase(t, func(w http.ResponseWriter, req map[string]interface{}) {
		params, _ := req["params"].(map[string]interface{})
		args, _ := params["arguments"].(map[string]interface{})
		query, _ := args["query"].(string)

		if query == "; id" || query == "| whoami" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]interface{}{
					"content": "uid=0(root) gid=0(root) groups=0(root)",
				},
			})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": req["id"],
			"result": map[string]interface{}{"content": "no output"},
		})
	})
	defer srv.Close()

	exec := mcpattack.NewInjectionParamsExecutor(attack.RuleContext{ID: "mcp-injection-params-001", Remediation: "avoid shell interpolation"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for command output exposure")
	}
	if findings[0].Severity != "critical" {
		t.Errorf("expected critical severity for command injection, got %s", findings[0].Severity)
	}
	if findings[0].Confidence != attack.ConfirmedExploit {
		t.Errorf("expected ConfirmedExploit, got %v", findings[0].Confidence)
	}
}

func TestInjectionParams_CleanServer(t *testing.T) {
	// Server sanitizes all inputs and never leaks injection artifacts.
	srv := injectionMCPBase(t, func(w http.ResponseWriter, req map[string]interface{}) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": req["id"],
			"result": map[string]interface{}{"content": "no results for your query"},
		})
	})
	defer srv.Close()

	exec := mcpattack.NewInjectionParamsExecutor(attack.RuleContext{ID: "mcp-injection-params-001", Remediation: "sanitize inputs"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean server, got %d", len(findings))
	}
}
