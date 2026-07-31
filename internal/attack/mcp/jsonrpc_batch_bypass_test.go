package mcp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

// batchServer builds a mock MCP server whose auth behavior depends on mode:
//   - "bypass-init":   single initialize is gated (401) but a batch [initialize]
//     is processed (the auth gate bypass at the handshake).
//   - "bypass-method": initialize is open, but single tools/list is gated (401)
//     while a batch [tools/list] is processed (the per-method gate bypass).
//   - "secure":        the auth gate applies to single AND batch requests alike.
//   - "open":          nothing is gated (no auth to bypass).
//   - "not-mcp":       every request 404s.
//
// The vulnerability is modeled by enforcing the gate only on non-batch requests
// in the two "bypass" modes, exactly the real-world bug where a gate inspects the
// top-level method and an array has none.
func batchServer(mode string) *httptest.Server {
	initResult := func(id interface{}) map[string]interface{} {
		return map[string]interface{}{
			"jsonrpc": "2.0", "id": id,
			"result": map[string]interface{}{
				"protocolVersion": "2025-03-26",
				"serverInfo":      map[string]interface{}{"name": "batch-srv", "version": "1.0"},
				"capabilities":    map[string]interface{}{"tools": map[string]interface{}{"listChanged": false}},
			},
		}
	}
	toolsResult := func(id interface{}) map[string]interface{} {
		return map[string]interface{}{
			"jsonrpc": "2.0", "id": id,
			"result": map[string]interface{}{"tools": []interface{}{map[string]interface{}{"name": "echo"}}},
		}
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mode == "not-mcp" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		isBatch := len(bytes.TrimSpace(raw)) > 0 && bytes.TrimSpace(raw)[0] == '['
		authed := r.Header.Get("Authorization") != ""
		w.Header().Set("Content-Type", "application/json")

		var objs []map[string]interface{}
		if isBatch {
			_ = json.Unmarshal(raw, &objs)
		} else {
			var one map[string]interface{}
			_ = json.Unmarshal(raw, &one)
			objs = []map[string]interface{}{one}
		}

		// enforce: is the auth gate active for this request shape?
		enforce := !isBatch
		if mode == "secure" {
			enforce = true
		}
		if mode == "open" {
			enforce = false
		}

		// respond returns the response object and HTTP status for one request.
		respond := func(req map[string]interface{}) (map[string]interface{}, int) {
			method, _ := req["method"].(string)
			id := req["id"]
			switch method {
			case "initialize":
				if (mode == "bypass-init" || mode == "secure") && enforce && !authed {
					return nil, http.StatusUnauthorized
				}
				return initResult(id), http.StatusOK
			case "notifications/initialized":
				return nil, http.StatusAccepted
			case "tools/list":
				if (mode == "bypass-method" || mode == "secure") && enforce && !authed {
					return nil, http.StatusUnauthorized
				}
				return toolsResult(id), http.StatusOK
			default:
				return map[string]interface{}{"jsonrpc": "2.0", "id": id,
					"error": map[string]interface{}{"code": -32601, "message": "method not found"}}, http.StatusOK
			}
		}

		if isBatch {
			var arr []interface{}
			for _, req := range objs {
				resp, st := respond(req)
				if st == http.StatusUnauthorized {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				if resp != nil {
					arr = append(arr, resp)
				}
			}
			_ = json.NewEncoder(w).Encode(arr)
			return
		}

		resp, st := respond(objs[0])
		if st != http.StatusOK {
			w.WriteHeader(st)
			return
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func runBatchBypass(t *testing.T, srv *httptest.Server) []attack.Finding {
	t.Helper()
	exec := mcpattack.NewBatchBypassExecutor(attack.RuleContext{
		ID:   "mcp-jsonrpc-batch-bypass-001",
		Name: "MCP JSON-RPC Batch Authentication Bypass",
	})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return findings
}

// TestBatchBypass_InitializeGate: initialize is gated for a single request but a
// batch [initialize] is processed => confirmed high finding.
func TestBatchBypass_InitializeGate(t *testing.T) {
	srv := batchServer("bypass-init")
	defer srv.Close()

	findings := runBatchBypass(t, srv)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Confidence != attack.ConfirmedExploit {
		t.Errorf("expected ConfirmedExploit, got %v", f.Confidence)
	}
	if f.Severity != "high" {
		t.Errorf("expected high severity, got %q", f.Severity)
	}
}

// TestBatchBypass_MethodGate: initialize is open but tools/list is gated for a
// single request while a batch [tools/list] is processed => confirmed finding.
func TestBatchBypass_MethodGate(t *testing.T) {
	srv := batchServer("bypass-method")
	defer srv.Close()

	if findings := runBatchBypass(t, srv); len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
}

// TestBatchBypass_SecureNoFinding: the gate applies to batches too => no finding.
func TestBatchBypass_SecureNoFinding(t *testing.T) {
	srv := batchServer("secure")
	defer srv.Close()

	if findings := runBatchBypass(t, srv); len(findings) != 0 {
		t.Errorf("expected 0 findings when batches are gated too, got %d: %+v", len(findings), findings)
	}
}

// TestBatchBypass_FullyOpenNoFinding: nothing is gated, so there is no auth to
// bypass (that posture belongs to mcp-tools-unauth-001) => no finding.
func TestBatchBypass_FullyOpenNoFinding(t *testing.T) {
	srv := batchServer("open")
	defer srv.Close()

	if findings := runBatchBypass(t, srv); len(findings) != 0 {
		t.Errorf("expected 0 findings when there is no auth gate, got %d: %+v", len(findings), findings)
	}
}

// TestBatchBypass_NotMCP: a non-MCP endpoint that 401s then is probed must not
// produce a finding (the bypassed batch must return a real MCP result).
func TestBatchBypass_NotMCP(t *testing.T) {
	srv := batchServer("not-mcp")
	defer srv.Close()

	assertInconclusive(t, mcpattack.NewBatchBypassExecutor(attack.RuleContext{ID: "mcp-jsonrpc-batch-bypass-001"}), srv.URL, testOpts())
}
