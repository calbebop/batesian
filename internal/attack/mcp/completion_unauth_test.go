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

// completionServer builds a mock MCP server whose completion/complete behavior
// is driven by mode:
//   - "oracle":          completions+prompts advertised; completion/complete
//     returns real suggestion values => medium reachability + high disclosure.
//   - "resource-oracle": completions+prompts+resources advertised; the prompt
//     arg returns empty but the resource-template variable discloses values =>
//     medium + high, with the high referencing the resource template.
//   - "reachable-empty": completions+prompts advertised; completion/complete
//     returns an empty completion result => medium only (no disclosure).
//   - "reachable-synth": only completions advertised; completion/complete answers
//     -32602 for the synthetic probe ref => medium only.
//   - "auth-enforced":   completion/complete answers -32001 Unauthorized => silent.
//   - "no-cap":          completions capability absent => silent.
//   - "not-mcp":         initialize 404s => silent.
func completionServer(mode string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mode == "not-mcp" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		method, _ := req["method"].(string)
		params, _ := req["params"].(map[string]interface{})
		w.Header().Set("Content-Type", "application/json")
		enc := func(v map[string]interface{}) { _ = json.NewEncoder(w).Encode(v) }
		rpcErr := func(code int, msg string) {
			enc(map[string]interface{}{"jsonrpc": "2.0", "id": req["id"],
				"error": map[string]interface{}{"code": code, "message": msg}})
		}
		completion := func(values []interface{}) {
			enc(map[string]interface{}{"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]interface{}{"completion": map[string]interface{}{
					"values": values, "total": len(values), "hasMore": false}}})
		}

		switch method {
		case "initialize":
			caps := map[string]interface{}{}
			if mode != "no-cap" {
				caps["completions"] = map[string]interface{}{}
			}
			if mode == "oracle" || mode == "reachable-empty" || mode == "resource-oracle" {
				caps["prompts"] = map[string]interface{}{}
			}
			if mode == "resource-oracle" {
				caps["resources"] = map[string]interface{}{}
			}
			enc(map[string]interface{}{
				"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]interface{}{
					"protocolVersion": "2025-03-26",
					"serverInfo":      map[string]interface{}{"name": "completion-srv", "version": "1.0"},
					"capabilities":    caps,
				},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "prompts/list":
			enc(map[string]interface{}{
				"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]interface{}{
					"prompts": []interface{}{
						map[string]interface{}{
							"name": "code_review",
							"arguments": []interface{}{
								map[string]interface{}{"name": "language"},
							},
						},
					},
				},
			})
		case "resources/templates/list":
			enc(map[string]interface{}{
				"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]interface{}{
					"resourceTemplates": []interface{}{
						map[string]interface{}{"uriTemplate": "file:///project/{path}", "name": "project-file"},
					},
				},
			})
		case "completion/complete":
			ref, _ := params["ref"].(map[string]interface{})
			refType, _ := ref["type"].(string)
			switch mode {
			case "auth-enforced":
				rpcErr(-32001, "Unauthorized")
			case "reachable-synth":
				rpcErr(-32602, "Invalid params: unknown prompt")
			case "reachable-empty":
				completion([]interface{}{})
			case "resource-oracle":
				// The prompt argument yields nothing; the resource template leaks.
				if refType == "ref/resource" {
					completion([]interface{}{"accounts/admin.py", "secrets/prod.env"})
				} else {
					completion([]interface{}{})
				}
			default: // oracle
				completion([]interface{}{"python", "pytorch", "pyside"})
			}
		default:
			rpcErr(-32601, "Method not found")
		}
	}))
}

func runCompletionUnauth(t *testing.T, srv *httptest.Server) []attack.Finding {
	t.Helper()
	exec := mcpattack.NewCompletionUnauthExecutor(attack.RuleContext{ID: "mcp-completion-unauth-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return findings
}

// TestCompletionUnauth_Oracle: real ref returns values => medium + high.
func TestCompletionUnauth_Oracle(t *testing.T) {
	srv := completionServer("oracle")
	defer srv.Close()

	findings := runCompletionUnauth(t, srv)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (reachability + disclosure), got %d: %+v", len(findings), findings)
	}
	hasMedium, hasHigh := false, false
	for _, f := range findings {
		if f.Confidence != attack.ConfirmedExploit {
			t.Errorf("expected ConfirmedExploit, got %v", f.Confidence)
		}
		switch f.Severity {
		case "medium":
			hasMedium = true
		case "high":
			hasHigh = true
		}
	}
	if !hasMedium || !hasHigh {
		t.Errorf("expected both medium and high findings, got medium=%v high=%v", hasMedium, hasHigh)
	}
}

// TestCompletionUnauth_ResourceOracle: the prompt arg discloses nothing but the
// resource-template variable leaks values => medium + high, high naming the
// resource template.
func TestCompletionUnauth_ResourceOracle(t *testing.T) {
	srv := completionServer("resource-oracle")
	defer srv.Close()

	findings := runCompletionUnauth(t, srv)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (reachability + disclosure), got %d: %+v", len(findings), findings)
	}
	var high *attack.Finding
	for i := range findings {
		if findings[i].Severity == "high" {
			high = &findings[i]
		}
	}
	if high == nil {
		t.Fatal("expected a high disclosure finding")
	}
	if !strings.Contains(high.Title, "resource template") {
		t.Errorf("expected high finding to name the resource template, got %q", high.Title)
	}
}

// TestCompletionUnauth_ReachableEmpty: reachable but no values => medium only.
func TestCompletionUnauth_ReachableEmpty(t *testing.T) {
	srv := completionServer("reachable-empty")
	defer srv.Close()

	findings := runCompletionUnauth(t, srv)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding (reachability only), got %d: %+v", len(findings), findings)
	}
	if findings[0].Severity != "medium" {
		t.Errorf("expected medium reachability finding, got %q", findings[0].Severity)
	}
}

// TestCompletionUnauth_ReachableSynthetic: no prompt/resource refs to discover,
// synthetic probe dispatches (-32602) => medium only.
func TestCompletionUnauth_ReachableSynthetic(t *testing.T) {
	srv := completionServer("reachable-synth")
	defer srv.Close()

	findings := runCompletionUnauth(t, srv)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding (synthetic reachability), got %d: %+v", len(findings), findings)
	}
	if findings[0].Severity != "medium" {
		t.Errorf("expected medium reachability finding, got %q", findings[0].Severity)
	}
}

// TestCompletionUnauth_AuthEnforced: completion/complete requires auth => silent.
func TestCompletionUnauth_AuthEnforced(t *testing.T) {
	srv := completionServer("auth-enforced")
	defer srv.Close()

	if findings := runCompletionUnauth(t, srv); len(findings) != 0 {
		t.Errorf("expected 0 findings when auth is enforced, got %d: %+v", len(findings), findings)
	}
}

// TestCompletionUnauth_NoCapability: server does not advertise completions => skip.
func TestCompletionUnauth_NoCapability(t *testing.T) {
	srv := completionServer("no-cap")
	defer srv.Close()

	if findings := runCompletionUnauth(t, srv); len(findings) != 0 {
		t.Errorf("expected 0 findings without the completions capability, got %d: %+v", len(findings), findings)
	}
}

// TestCompletionUnauth_NotMCP: initialize fails => silent.
func TestCompletionUnauth_NotMCP(t *testing.T) {
	srv := completionServer("not-mcp")
	defer srv.Close()

	if findings := runCompletionUnauth(t, srv); len(findings) != 0 {
		t.Errorf("expected 0 findings for a non-MCP server, got %d: %+v", len(findings), findings)
	}
}
