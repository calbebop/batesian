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

func TestContextFlood_AcceptsLargePayload(t *testing.T) {
	// Server accepts any tools/call regardless of argument size.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var req map[string]interface{}
		json.NewDecoder(r.Body).Decode(&req)
		method, _ := req["method"].(string)
		switch method {
		case "initialize":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      req["id"],
				"result": map[string]interface{}{
					"protocolVersion": "2025-03-26",
					"serverInfo":      map[string]interface{}{"name": "flood-server"},
					"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
				},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      req["id"],
				"result": map[string]interface{}{
					"tools": []interface{}{
						map[string]interface{}{
							"name":        "echo",
							"description": "echoes input",
							"inputSchema": map[string]interface{}{"type": "object"},
						},
					},
				},
			})
		case "tools/call":
			// Accept all sizes without error
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      req["id"],
				"result":  map[string]interface{}{"content": "ok"},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	exec := mcpattack.NewContextFloodExecutor(attack.RuleContext{ID: "mcp-context-flood-001", Remediation: "enforce size limits"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 15})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings for server that accepts oversized payloads")
	}
	// At minimum the 1MB finding should fire
	hasMedium := false
	for _, f := range findings {
		if f.Severity == "medium" || f.Severity == "high" {
			hasMedium = true
		}
		if f.Confidence != attack.ConfirmedExploit {
			t.Errorf("expected ConfirmedExploit, got %v", f.Confidence)
		}
	}
	if !hasMedium {
		t.Error("expected at least one medium or high finding")
	}
}

func TestContextFlood_RejectsLargePayload(t *testing.T) {
	// Server enforces size limits by returning HTTP 413.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Reject large bodies
		if r.ContentLength > 65536 {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		var req map[string]interface{}
		json.NewDecoder(r.Body).Decode(&req)
		method, _ := req["method"].(string)
		switch method {
		case "initialize":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      req["id"],
				"result": map[string]interface{}{
					"protocolVersion": "2025-03-26",
					"serverInfo":      map[string]interface{}{"name": "strict-server"},
					"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
				},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      req["id"],
				"result": map[string]interface{}{
					"tools": []interface{}{
						map[string]interface{}{
							"name":        "search",
							"description": "searches",
							"inputSchema": map[string]interface{}{"type": "object"},
						},
					},
				},
			})
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	exec := mcpattack.NewContextFloodExecutor(attack.RuleContext{ID: "mcp-context-flood-001", Remediation: "enforce size limits"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 15})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for server that rejects large payloads, got %d", len(findings))
	}
}

func TestContextFlood_RejectsViaJSONRPCError(t *testing.T) {
	// Server rejects large payloads with a JSON-RPC error message containing "too large".
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var req map[string]interface{}
		json.NewDecoder(r.Body).Decode(&req)
		method, _ := req["method"].(string)
		switch method {
		case "initialize":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      req["id"],
				"result": map[string]interface{}{
					"protocolVersion": "2025-03-26",
					"serverInfo":      map[string]interface{}{"name": "rpc-limit-server"},
					"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
				},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      req["id"],
				"result": map[string]interface{}{
					"tools": []interface{}{
						map[string]interface{}{
							"name":        "process",
							"description": "processes",
							"inputSchema": map[string]interface{}{"type": "object"},
						},
					},
				},
			})
		case "tools/call":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      req["id"],
				"error": map[string]interface{}{
					"code":    -32600,
					"message": "Request too large: argument exceeds maximum size limit",
				},
			})
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	exec := mcpattack.NewContextFloodExecutor(attack.RuleContext{ID: "mcp-context-flood-001", Remediation: "enforce size limits"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 15})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for server that rejects via JSON-RPC error, got %d", len(findings))
	}
}
