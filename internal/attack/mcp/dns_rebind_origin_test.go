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

func dnsRebindRC() attack.RuleContext {
	return attack.RuleContext{
		ID:          "mcp-dns-rebind-origin-001",
		Name:        "MCP Origin Validation (DNS Rebinding)",
		Severity:    "high",
		Remediation: "Validate the Origin header and reject an invalid Origin with 403.",
	}
}

// dnsRebindServer models an MCP Streamable HTTP endpoint. mode selects Origin
// handling:
//   - "vulnerable": processes initialize regardless of Origin (no validation)
//   - "validates":  rejects a request carrying any Origin with HTTP 403
//   - "not-mcp":    not an MCP endpoint (no JSON-RPC result)
func dnsRebindServer(mode string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if mode == "validates" && r.Header.Get("Origin") != "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if mode == "not-mcp" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": 1,
			"result": map[string]interface{}{
				"protocolVersion": "2025-06-18",
				"serverInfo":      map[string]interface{}{"name": "rebind-fixture", "version": "1.0"},
				"capabilities":    map[string]interface{}{},
			},
		})
	}))
}

func runDNSRebind(t *testing.T, ts *httptest.Server) []attack.Finding {
	t.Helper()
	findings, err := mcpattack.NewDNSRebindOriginExecutor(dnsRebindRC()).Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return findings
}

// TestDNSRebind_Vulnerable: the server processes a foreign-Origin initialize.
// MUST fire confirmed/high.
func TestDNSRebind_Vulnerable(t *testing.T) {
	ts := dnsRebindServer("vulnerable")
	defer ts.Close()

	findings := runDNSRebind(t, ts)
	if len(findings) != 1 {
		t.Fatalf("expected exactly one finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Confidence != attack.ConfirmedExploit || f.Severity != "high" {
		t.Errorf("want high/ConfirmedExploit, got %q/%q", f.Severity, f.Confidence)
	}
}

// TestDNSRebind_ValidatesOrigin: the server rejects a foreign Origin with 403.
// The rule MUST stay silent.
func TestDNSRebind_ValidatesOrigin(t *testing.T) {
	ts := dnsRebindServer("validates")
	defer ts.Close()

	if findings := runDNSRebind(t, ts); len(findings) != 0 {
		t.Errorf("expected zero findings when the server validates Origin, got %d: %+v", len(findings), findings)
	}
}

// TestDNSRebind_NotMCP: not an MCP endpoint. The rule does not apply.
func TestDNSRebind_NotMCP(t *testing.T) {
	ts := dnsRebindServer("not-mcp")
	defer ts.Close()

	if findings := runDNSRebind(t, ts); len(findings) != 0 {
		t.Errorf("expected zero findings against a non-MCP server, got %d", len(findings))
	}
}
