package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
)

func TestResponsiveMCPClosesIssuedSession(t *testing.T) {
	var deletes atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			if r.Header.Get("Mcp-Session-Id") != "reachability-session" ||
				r.Header.Get("Mcp-Protocol-Version") != "2025-11-25" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			deletes.Add(1)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Mcp-Session-Id", "reachability-session")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": 1,
			"result": map[string]interface{}{
				"protocolVersion": "2025-11-25",
				"serverInfo":      map[string]string{"name": "fixture", "version": "1"},
				"capabilities":    map[string]interface{}{},
			},
		})
	}))
	defer ts.Close()

	opts := attack.Options{TimeoutSeconds: 5}
	vars := attack.NewVars(ts.URL, "")
	client := attack.NewUnauthHTTPClient(opts, vars)
	if !responsiveMCP(context.Background(), client, ts.URL) || deletes.Load() != 1 {
		t.Fatalf("want an MCP response and one session cleanup, got deletes=%d", deletes.Load())
	}
}
