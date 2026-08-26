package mcp_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcp "github.com/calbebop/batesian/internal/attack/mcp"
)

// TestDiscoveryCacheSkipsWalk pins the property the cache exists for: the
// first session resolution may probe several candidate paths - here /mcp
// answers 404 and / carries the handler - but a second resolution over the
// same Options goes straight to the endpoint the first one found, instead of
// repeating the miss.
func TestDiscoveryCacheSkipsWalk(t *testing.T) {
	var misses atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string      `json:"method"`
			ID     json.Number `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Method != "initialize" {
			// notifications, discover probes and other traffic are not the
			// metric this test watches.
			w.WriteHeader(http.StatusAccepted)
			return
		}
		if r.URL.Path == "/mcp" {
			misses.Add(1)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Mcp-Session-Id", "sess-cache")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": req.ID,
			"result": map[string]interface{}{
				"protocolVersion": "2025-06-18",
				"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
				"serverInfo":      map[string]interface{}{"name": "cache-fixture", "version": "1"},
			},
		})
	}))
	defer ts.Close()

	opts := attack.Options{TimeoutSeconds: 5, Discovery: attack.NewDiscoveryCache()}

	eps1, err := mcp.OpenSessionForTest(ts.URL, opts)
	if err != nil {
		t.Fatalf("first resolution: %v", err)
	}
	first := misses.Load()
	if first != 1 {
		t.Fatalf("first walk should have missed exactly once at /mcp, got %d", first)
	}

	eps2, err := mcp.OpenSessionForTest(ts.URL, opts)
	if err != nil {
		t.Fatalf("second resolution: %v", err)
	}
	if eps2[0] != eps1[0] {
		t.Errorf("second resolution should land on the same endpoint, got %q vs %q", eps2[0], eps1[0])
	}
	if after := misses.Load(); after != first {
		t.Errorf("cached walk must not repeat the dead-candidate probe: misses %d -> %d", first, after)
	}
}
