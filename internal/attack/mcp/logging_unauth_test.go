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

func loggingServer(mode string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mode == "not-mcp" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		method, _ := req["method"].(string)
		w.Header().Set("Content-Type", "application/json")
		enc := func(v map[string]interface{}) { _ = json.NewEncoder(w).Encode(v) }
		rpcErr := func(code int, msg string) {
			enc(map[string]interface{}{"jsonrpc": "2.0", "id": req["id"],
				"error": map[string]interface{}{"code": code, "message": msg}})
		}

		switch method {
		case "initialize":
			caps := map[string]interface{}{}
			if mode != "no-cap" {
				caps["logging"] = map[string]interface{}{}
			}
			enc(map[string]interface{}{
				"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]interface{}{
					"protocolVersion": "2025-03-26",
					"serverInfo":      map[string]interface{}{"name": "logging-srv", "version": "1.0"},
					"capabilities":    caps,
				},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "logging/setLevel":
			switch mode {
			case "auth-enforced":
				rpcErr(-32001, "Unauthorized")
			case "http-auth":
				w.WriteHeader(http.StatusUnauthorized)
			case "http-forbidden":
				w.WriteHeader(http.StatusForbidden)
			case "http-rpc-auth":
				w.WriteHeader(http.StatusInternalServerError)
				rpcErr(-32001, "Unauthorized")
			case "http-internal":
				w.WriteHeader(http.StatusInternalServerError)
				rpcErr(-32603, "Internal error")
			case "http-invalid":
				w.WriteHeader(http.StatusBadRequest)
				rpcErr(-32602, "Invalid params: unknown log level")
			case "method-missing":
				rpcErr(-32601, "Method not found")
			case "http-method-missing":
				w.WriteHeader(http.StatusNotFound)
				rpcErr(-32601, "Method not found")
			case "wrong-id":
				enc(map[string]interface{}{"jsonrpc": "2.0", "id": 999,
					"error": map[string]interface{}{"code": -32602, "message": "Invalid params"}})
			case "reachable-internal":
				// server-everything surfaces an invalid level as -32603 (internal).
				rpcErr(-32603, "invalid_value: unknown log level")
			default:
				// The scanner only ever sends an invalid level; a compliant server
				// answers -32602 and changes nothing.
				rpcErr(-32602, "Invalid params: unknown log level")
			}
		default:
			rpcErr(-32601, "Method not found")
		}
	}))
}

func runLoggingUnauth(t *testing.T, srv *httptest.Server) []attack.Finding {
	t.Helper()
	exec := mcpattack.NewLoggingUnauthExecutor(attack.RuleContext{ID: "mcp-logging-unauth-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return findings
}

func TestLoggingUnauth_Reachable(t *testing.T) {
	srv := loggingServer("reachable")
	defer srv.Close()

	findings := runLoggingUnauth(t, srv)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Confidence != attack.ConfirmedExploit || f.Severity != "medium" {
		t.Errorf("expected medium/confirmed, got %q/%v", f.Severity, f.Confidence)
	}
}

func TestLoggingUnauth_ReachableInternalError(t *testing.T) {
	srv := loggingServer("reachable-internal")
	defer srv.Close()

	findings := runLoggingUnauth(t, srv)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for a -32603 invalid-level response, got %d: %+v", len(findings), findings)
	}
}

func TestLoggingUnauth_AuthEnforced(t *testing.T) {
	srv := loggingServer("auth-enforced")
	defer srv.Close()

	if findings := runLoggingUnauth(t, srv); len(findings) != 0 {
		t.Errorf("expected 0 findings when auth is enforced, got %d: %+v", len(findings), findings)
	}
}

func TestLoggingUnauth_HTTPAuthDenial(t *testing.T) {
	for _, mode := range []string{"http-auth", "http-forbidden", "http-rpc-auth"} {
		t.Run(mode, func(t *testing.T) {
			srv := loggingServer(mode)
			defer srv.Close()
			if findings := runLoggingUnauth(t, srv); len(findings) != 0 {
				t.Fatalf("expected no finding after explicit auth denial, got %+v", findings)
			}
		})
	}
}

func TestLoggingUnauth_UnsupportedMethod(t *testing.T) {
	for _, mode := range []string{"method-missing", "http-method-missing"} {
		t.Run(mode, func(t *testing.T) {
			srv := loggingServer(mode)
			defer srv.Close()
			if findings := runLoggingUnauth(t, srv); len(findings) != 0 {
				t.Fatalf("expected no finding for an unavailable method, got %+v", findings)
			}
		})
	}
}

func TestLoggingUnauth_IncompleteProbe(t *testing.T) {
	for _, mode := range []string{"http-internal", "http-invalid", "wrong-id"} {
		t.Run(mode, func(t *testing.T) {
			srv := loggingServer(mode)
			defer srv.Close()
			assertInconclusive(t, mcpattack.NewLoggingUnauthExecutor(
				attack.RuleContext{ID: "mcp-logging-unauth-001"}), srv.URL, testOpts())
		})
	}
}

func TestLoggingUnauth_NoCapability(t *testing.T) {
	srv := loggingServer("no-cap")
	defer srv.Close()

	if findings := runLoggingUnauth(t, srv); len(findings) != 0 {
		t.Errorf("expected 0 findings without the logging capability, got %d: %+v", len(findings), findings)
	}
}

func TestLoggingUnauth_NotMCP(t *testing.T) {
	srv := loggingServer("not-mcp")
	defer srv.Close()

	assertInconclusive(t, mcpattack.NewLoggingUnauthExecutor(attack.RuleContext{ID: "mcp-logging-unauth-001"}), srv.URL, testOpts())
}
