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

// batchServer models an auth gate that may mishandle batch requests.
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

		enforce := !isBatch
		if mode == "secure" {
			enforce = true
		}
		if mode == "open" {
			enforce = false
		}

		respond := func(req map[string]interface{}) (map[string]interface{}, int) {
			method, _ := req["method"].(string)
			id := req["id"]
			switch method {
			case "initialize":
				if (mode == "bypass-init" || mode == "unrelated-init" || mode == "malformed-init" || mode == "secure") && enforce && !authed {
					return nil, http.StatusUnauthorized
				}
				if isBatch && mode == "unrelated-init" {
					return initResult(999), http.StatusOK
				}
				if isBatch && mode == "malformed-init" {
					return map[string]interface{}{
						"jsonrpc": "2.0", "id": id,
						"result": map[string]interface{}{"protocolVersion": "2025-03-26"},
					}, http.StatusOK
				}
				return initResult(id), http.StatusOK
			case "notifications/initialized":
				return nil, http.StatusAccepted
			case "tools/list":
				if (mode == "bypass-method" || mode == "unrelated-method" || mode == "null-method" || mode == "malformed-method" || mode == "secure") && enforce && !authed {
					return nil, http.StatusUnauthorized
				}
				if isBatch && mode == "unrelated-method" {
					return toolsResult(999), http.StatusOK
				}
				if isBatch && mode == "null-method" {
					return toolsResult(nil), http.StatusOK
				}
				if isBatch && mode == "malformed-method" {
					return map[string]interface{}{"jsonrpc": "2.0", "id": id, "result": map[string]interface{}{}}, http.StatusOK
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

func TestBatchBypass_MethodGate(t *testing.T) {
	srv := batchServer("bypass-method")
	defer srv.Close()

	if findings := runBatchBypass(t, srv); len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
}

func TestBatchBypass_SecureNoFinding(t *testing.T) {
	srv := batchServer("secure")
	defer srv.Close()

	if findings := runBatchBypass(t, srv); len(findings) != 0 {
		t.Errorf("expected 0 findings when batches are gated too, got %d: %+v", len(findings), findings)
	}
}

func TestBatchBypass_FullyOpenNoFinding(t *testing.T) {
	srv := batchServer("open")
	defer srv.Close()

	if findings := runBatchBypass(t, srv); len(findings) != 0 {
		t.Errorf("expected 0 findings when there is no auth gate, got %d: %+v", len(findings), findings)
	}
}

func TestBatchBypass_NotMCP(t *testing.T) {
	srv := batchServer("not-mcp")
	defer srv.Close()

	assertInconclusive(t, mcpattack.NewBatchBypassExecutor(attack.RuleContext{ID: "mcp-jsonrpc-batch-bypass-001"}), srv.URL, testOpts())
}

func TestBatchBypass_RequiresCorrelatedResult(t *testing.T) {
	for _, mode := range []string{"unrelated-init", "unrelated-method", "null-method"} {
		t.Run(mode, func(t *testing.T) {
			srv := batchServer(mode)
			defer srv.Close()

			if findings := runBatchBypass(t, srv); len(findings) != 0 {
				t.Fatalf("expected no finding for an unrelated response, got %+v", findings)
			}
		})
	}
}

func TestBatchBypass_RequiresExpectedResultShape(t *testing.T) {
	for _, mode := range []string{"malformed-init", "malformed-method"} {
		t.Run(mode, func(t *testing.T) {
			srv := batchServer(mode)
			defer srv.Close()

			if findings := runBatchBypass(t, srv); len(findings) != 0 {
				t.Fatalf("expected no finding for a malformed result, got %+v", findings)
			}
		})
	}
}
