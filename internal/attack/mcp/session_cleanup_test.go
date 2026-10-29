package mcp_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

func TestLegacySessionClosedAfterProbe(t *testing.T) {
	var closed atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			if r.Header.Get("Mcp-Session-Id") != "owned-session" ||
				r.Header.Get("Mcp-Protocol-Version") != "2025-11-25" {
				t.Errorf("incorrect session cleanup headers: %v", r.Header)
			}
			closed.Add(1)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "owned-session")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID,
				"result": map[string]interface{}{
					"protocolVersion": "2025-11-25", "serverInfo": map[string]string{"name": "fixture", "version": "1"},
					"capabilities": map[string]interface{}{"tools": map[string]interface{}{}},
				},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID, "result": map[string]interface{}{"tools": []interface{}{}},
			})
		default:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID,
				"error": map[string]interface{}{"code": -32601, "message": "Method not found"},
			})
		}
	}))
	defer server.Close()

	exec := mcpattack.NewToolsUnauthExecutor(attack.RuleContext{ID: "mcp-tools-unauth-001"})
	findings, err := exec.Execute(t.Context(), server.URL, testOpts())
	if err != nil || len(findings) != 0 || closed.Load() != 1 {
		t.Fatalf("session was not closed after probe: findings=%+v closed=%d err=%v", findings, closed.Load(), err)
	}
}
