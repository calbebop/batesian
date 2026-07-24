package mcp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

func hbsRuleCtx() attack.RuleContext {
	return attack.RuleContext{ID: "mcp-header-body-split-001", Name: "MCP Header/Body Split", Severity: "high", Remediation: "Validate Mcp-Method."}
}

// splitServer models a Streamable HTTP MCP server. mode selects header handling
// for tools/list (initialize always succeeds):
//   - "split":     requires Mcp-Method presence but ignores its VALUE (vulnerable)
//   - "strict":    rejects missing OR mismatched Mcp-Method with 400/-32020
//   - "unaware":   ignores Mcp-Method entirely (not SEP-2243-aware)
func splitServer(mode string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		method, _ := req["method"].(string)
		id := req["id"]
		hdr := r.Header.Get("Mcp-Method")
		w.Header().Set("Content-Type", "application/json")

		writeTools := func() {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{"tools": []interface{}{map[string]interface{}{"name": "echo"}}},
			})
		}
		reject := func() {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"error": map[string]interface{}{"code": -32020, "message": "HeaderMismatch"},
			})
		}

		switch method {
		case "initialize":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{
					"protocolVersion": "2025-06-18",
					"serverInfo":      map[string]interface{}{"name": "split-fixture", "version": "1.0"},
					"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
				},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			switch mode {
			case "unaware":
				writeTools() // ignores header entirely
			case "strict":
				if hdr != method { // missing or mismatched
					reject()
					return
				}
				writeTools()
			default: // split: enforce presence, ignore value
				if hdr == "" {
					reject()
					return
				}
				writeTools()
			}
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
}

func runSplit(t *testing.T, ts *httptest.Server) []attack.Finding {
	t.Helper()
	findings, err := mcpattack.NewHeaderBodySplitExecutor(hbsRuleCtx()).Execute(context.Background(), ts.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return findings
}

// TestSplit_Vulnerable: presence enforced, value ignored => confirmed.
func TestSplit_Vulnerable(t *testing.T) {
	ts := splitServer("split")
	defer ts.Close()

	findings := runSplit(t, ts)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Confidence != attack.ConfirmedExploit || findings[0].Severity != "high" {
		t.Errorf("want high/ConfirmedExploit, got %q/%q", findings[0].Severity, findings[0].Confidence)
	}
	if !strings.Contains(findings[0].Title, "SEP-2243") {
		t.Errorf("expected SEP-2243 in title, got %q", findings[0].Title)
	}
}

// TestSplit_Strict: rejects mismatch => secure, no finding.
func TestSplit_Strict(t *testing.T) {
	ts := splitServer("strict")
	defer ts.Close()

	if findings := runSplit(t, ts); len(findings) != 0 {
		t.Errorf("expected zero findings against a strict server, got %d: %+v", len(findings), findings)
	}
}

// TestSplit_Unaware: ignores Mcp-Method entirely => not SEP-2243-aware, no finding.
func TestSplit_Unaware(t *testing.T) {
	ts := splitServer("unaware")
	defer ts.Close()

	if findings := runSplit(t, ts); len(findings) != 0 {
		t.Errorf("expected zero findings against a header-unaware server, got %d: %+v", len(findings), findings)
	}
}

// TestSplit_NotMCP: non-MCP server => no finding.
func TestSplit_NotMCP(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	defer ts.Close()

	assertInconclusive(t, mcpattack.NewHeaderBodySplitExecutor(hbsRuleCtx()), ts.URL, attack.Options{TimeoutSeconds: 5})
}
