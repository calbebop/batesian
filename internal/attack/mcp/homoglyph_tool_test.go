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

func homoglyphMCPBase(w http.ResponseWriter, req map[string]interface{}, toolCallHandler func(http.ResponseWriter, map[string]interface{})) {
	method, _ := req["method"].(string)
	w.Header().Set("Content-Type", "application/json")
	switch method {
	case "initialize":
		json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": req["id"],
			"result": map[string]interface{}{
				"protocolVersion": "2025-03-26",
				"serverInfo":      map[string]interface{}{"name": "homoglyph-test"},
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
					map[string]interface{}{"name": "search", "description": "searches", "inputSchema": map[string]interface{}{"type": "object"}},
				},
			},
		})
	case "tools/call":
		toolCallHandler(w, req)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestHomoglyphTool_AcceptsHomoglyph(t *testing.T) {
	// Server does not normalize tool names and accepts any string.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		json.NewDecoder(r.Body).Decode(&req)
		homoglyphMCPBase(w, req, func(w http.ResponseWriter, req map[string]interface{}) {
			// Accept any tool name without validation (vulnerable).
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]interface{}{"content": "ok"},
			})
		})
	}))
	defer srv.Close()

	exec := mcpattack.NewHomoglyphToolExecutor(attack.RuleContext{ID: "mcp-homoglyph-tool-001", Remediation: "normalize names"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding when server accepts homoglyph tool name")
	}
	if findings[0].Confidence != attack.ConfirmedExploit {
		t.Errorf("expected ConfirmedExploit, got %v", findings[0].Confidence)
	}
}

func TestHomoglyphTool_RejectsHomoglyph(t *testing.T) {
	// Server validates tool names and returns -32601 for unknown names.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		json.NewDecoder(r.Body).Decode(&req)
		homoglyphMCPBase(w, req, func(w http.ResponseWriter, req map[string]interface{}) {
			params, _ := req["params"].(map[string]interface{})
			name, _ := params["name"].(string)
			if name != "search" {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0", "id": req["id"],
					"error": map[string]interface{}{"code": -32601, "message": "tool not found: " + name},
				})
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]interface{}{"content": "ok"},
			})
		})
	}))
	defer srv.Close()

	exec := mcpattack.NewHomoglyphToolExecutor(attack.RuleContext{ID: "mcp-homoglyph-tool-001", Remediation: "normalize names"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when server rejects homoglyph name, got %d", len(findings))
	}
}
