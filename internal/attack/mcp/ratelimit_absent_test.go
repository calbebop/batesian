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

func mcpInitHandler(w http.ResponseWriter, _ *http.Request, req map[string]interface{}) {
	json.NewEncoder(w).Encode(map[string]interface{}{
		"jsonrpc": "2.0", "id": req["id"],
		"result": map[string]interface{}{
			"protocolVersion": "2025-03-26",
			"serverInfo":      map[string]interface{}{"name": "rate-test"},
			"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
		},
	})
}

func mcpToolsListHandler(w http.ResponseWriter, _ *http.Request, req map[string]interface{}) {
	json.NewEncoder(w).Encode(map[string]interface{}{
		"jsonrpc": "2.0", "id": req["id"],
		"result": map[string]interface{}{
			"tools": []interface{}{
				map[string]interface{}{"name": "echo", "description": "echoes input", "inputSchema": map[string]interface{}{"type": "object"}},
			},
		},
	})
}

func TestRateLimitAbsent_NoThrottling(t *testing.T) {
	// Server accepts every request without rate limiting.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var req map[string]interface{}
		json.NewDecoder(r.Body).Decode(&req)
		method, _ := req["method"].(string)
		switch method {
		case "initialize":
			mcpInitHandler(w, r, req)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			mcpToolsListHandler(w, r, req)
		case "tools/call":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]interface{}{"content": "ok"},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	exec := mcpattack.NewRateLimitAbsentExecutor(attack.RuleContext{ID: "mcp-ratelimit-absent-001", Remediation: "add rate limiting"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 15})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding when server accepts all burst requests without throttling")
	}
	if findings[0].Confidence != attack.RiskIndicator {
		t.Errorf("expected RiskIndicator, got %v", findings[0].Confidence)
	}
}

func TestRateLimitAbsent_ThrottlesAfterBurst(t *testing.T) {
	// Server enforces rate limiting by returning 429 after 5 requests.
	var count atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var req map[string]interface{}
		json.NewDecoder(r.Body).Decode(&req)
		method, _ := req["method"].(string)
		switch method {
		case "initialize":
			mcpInitHandler(w, r, req)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			mcpToolsListHandler(w, r, req)
		case "tools/call":
			n := count.Add(1)
			if n > 5 {
				w.WriteHeader(http.StatusTooManyRequests)
				w.Write([]byte(`{"error": "rate limit exceeded"}`))
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]interface{}{"content": "ok"},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	exec := mcpattack.NewRateLimitAbsentExecutor(attack.RuleContext{ID: "mcp-ratelimit-absent-001", Remediation: "add rate limiting"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 15})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when server enforces rate limiting, got %d", len(findings))
	}
}
