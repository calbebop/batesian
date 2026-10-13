package mcp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

// completionServer serves the completion rule fixtures.
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
			if mode == "oracle" || mode == "reachable-empty" || mode == "resource-oracle" ||
				mode == "prompt-list-fails" || mode == "prompt-list-malformed" || mode == "prompt-list-paged" ||
				mode == "prompt-paged" ||
				mode == "real-probe-fails" || mode == "completion-server-error" || mode == "reference-limit" ||
				mode == "partial-discovery-reachable" || mode == "partial-probe-reachable" ||
				mode == "prompt-entry-malformed" || mode == "prompt-list-wrong-id" ||
				mode == "prompt-list-rpc-auth" || mode == "prompt-list-non-auth-error" || mode == "prompt-list-unsupported" {
				caps["prompts"] = map[string]interface{}{}
			}
			if mode == "resource-oracle" || mode == "template-list-fails" || mode == "partial-discovery-reachable" ||
				mode == "template-entry-malformed" || mode == "template-list-unsupported" ||
				strings.HasPrefix(mode, "resource-paged") {
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
			if mode == "prompt-paged" {
				cursor, paged := params["cursor"].(string)
				if paged && cursor != "next" {
					rpcErr(-32602, "unexpected cursor")
					return
				}
				name, argument := "code_review", "language"
				result := map[string]interface{}{}
				if paged {
					name, argument = "secret_query", "path"
				} else {
					result["nextCursor"] = "next"
				}
				result["prompts"] = []interface{}{map[string]interface{}{
					"name": name, "arguments": []interface{}{map[string]interface{}{"name": argument}},
				}}
				enc(map[string]interface{}{"jsonrpc": "2.0", "id": req["id"], "result": result})
				return
			}
			if mode == "prompt-list-rpc-auth" {
				rpcErr(-32001, "Unauthorized")
				return
			}
			if mode == "prompt-list-non-auth-error" {
				rpcErr(-32002, "Resource not found")
				return
			}
			if mode == "prompt-list-unsupported" {
				rpcErr(-32601, "Method not found")
				return
			}
			if mode == "prompt-list-fails" || mode == "partial-discovery-reachable" {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			if mode == "prompt-list-malformed" {
				enc(map[string]interface{}{"jsonrpc": "2.0", "id": req["id"], "result": map[string]interface{}{}})
				return
			}
			if mode == "prompt-entry-malformed" {
				enc(map[string]interface{}{"jsonrpc": "2.0", "id": req["id"], "result": map[string]interface{}{
					"prompts": []interface{}{map[string]interface{}{"name": "code_review", "arguments": "not an array"}},
				}})
				return
			}
			arguments := []interface{}{map[string]interface{}{"name": "language"}}
			if mode == "partial-probe-reachable" {
				arguments = append(arguments, map[string]interface{}{"name": "framework"})
			}
			if mode == "reference-limit" {
				for i := 1; i < 9; i++ {
					arguments = append(arguments, map[string]interface{}{"name": fmt.Sprintf("argument-%d", i)})
				}
			}
			result := map[string]interface{}{
				"prompts": []interface{}{map[string]interface{}{"name": "code_review", "arguments": arguments}},
			}
			if mode == "prompt-list-paged" {
				result["nextCursor"] = "next"
			}
			id := req["id"]
			if mode == "prompt-list-wrong-id" {
				id = 99
			}
			enc(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"result": result,
			})
		case "resources/templates/list":
			if strings.HasPrefix(mode, "resource-paged") {
				cursor, paged := params["cursor"].(string)
				if paged && cursor != "next" {
					rpcErr(-32602, "unexpected cursor")
					return
				}
				if paged && (mode == "resource-paged-fails" || mode == "resource-paged-partial-leak") {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				template := "file:///project/{path}"
				result := map[string]interface{}{}
				if paged {
					template = "file:///secrets/{path}"
					if mode == "resource-paged-loop" {
						result["nextCursor"] = "next"
					}
				} else {
					result["nextCursor"] = "next"
					if mode == "resource-paged-badcursor" {
						result["nextCursor"] = 7
					}
				}
				result["resourceTemplates"] = []interface{}{map[string]interface{}{
					"uriTemplate": template, "name": "files",
				}}
				enc(map[string]interface{}{"jsonrpc": "2.0", "id": req["id"], "result": result})
				return
			}
			if mode == "template-list-unsupported" {
				rpcErr(-32601, "Method not found")
				return
			}
			if mode == "template-list-fails" {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			if mode == "template-entry-malformed" {
				enc(map[string]interface{}{"jsonrpc": "2.0", "id": req["id"], "result": map[string]interface{}{
					"resourceTemplates": []interface{}{map[string]interface{}{"name": "missing-uri"}},
				}})
				return
			}
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
			refName, _ := ref["name"].(string)
			switch mode {
			case "auth-enforced":
				rpcErr(-32001, "Unauthorized")
			case "reachable-synth":
				rpcErr(-32602, "Invalid params: unknown prompt")
			case "reachable-internal":
				// A non-(-32602) validation path: still proves dispatch without auth.
				rpcErr(-32603, "internal: unknown completion ref")
			case "reachable-empty":
				completion([]interface{}{})
			case "prompt-list-fails", "prompt-list-malformed", "prompt-list-paged", "template-list-fails",
				"reference-limit", "prompt-entry-malformed", "template-entry-malformed", "prompt-list-wrong-id",
				"prompt-list-rpc-auth", "prompt-list-non-auth-error", "prompt-list-unsupported", "template-list-unsupported":
				rpcErr(-32001, "Unauthorized")
			case "real-probe-fails", "completion-server-error":
				if refName == "code_review" {
					if mode == "completion-server-error" {
						w.WriteHeader(http.StatusInternalServerError)
						rpcErr(-32603, "Internal error")
					} else {
						w.WriteHeader(http.StatusServiceUnavailable)
					}
				} else {
					rpcErr(-32001, "Unauthorized")
				}
			case "partial-discovery-reachable":
				if refType == "ref/resource" {
					completion([]interface{}{"accounts/admin.py"})
				} else {
					rpcErr(-32001, "Unauthorized")
				}
			case "partial-probe-reachable":
				argument, _ := params["argument"].(map[string]interface{})
				if argument["name"] == "language" {
					w.WriteHeader(http.StatusServiceUnavailable)
				} else {
					completion([]interface{}{"flask"})
				}
			case "resource-oracle":
				// The prompt argument yields nothing; the resource template leaks.
				if refType == "ref/resource" {
					completion([]interface{}{"accounts/admin.py", "secrets/prod.env"})
				} else {
					completion([]interface{}{})
				}
			case "resource-paged":
				uri, _ := ref["uri"].(string)
				if uri == "file:///secrets/{path}" {
					completion([]interface{}{"prod.env"})
				} else {
					completion([]interface{}{})
				}
			case "resource-paged-partial-leak":
				completion([]interface{}{"observed.txt"})
			case "resource-paged-fails", "resource-paged-protected", "resource-paged-loop", "resource-paged-badcursor":
				rpcErr(-32001, "Unauthorized")
			case "prompt-paged":
				if refName == "secret_query" {
					completion([]interface{}{"prod.env"})
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

func TestCompletionUnauth_ResourceTemplatePagination(t *testing.T) {
	srv := completionServer("resource-paged")
	defer srv.Close()
	findings := runCompletionUnauth(t, srv)
	if len(findings) != 2 || !strings.Contains(findings[1].Title, "resource template") ||
		!strings.Contains(findings[1].Evidence, "prod.env") ||
		!strings.Contains(findings[0].Evidence, "resources/templates/list: complete") {
		t.Fatalf("second-page disclosure not reported: %+v", findings)
	}
}

func TestCompletionUnauth_ResourceTemplatePaginationProtected(t *testing.T) {
	srv := completionServer("resource-paged-protected")
	defer srv.Close()
	if findings := runCompletionUnauth(t, srv); len(findings) != 0 {
		t.Fatalf("protected completion reported a finding: %+v", findings)
	}
}

func TestCompletionUnauth_PromptPagination(t *testing.T) {
	srv := completionServer("prompt-paged")
	defer srv.Close()
	findings := runCompletionUnauth(t, srv)
	if len(findings) != 2 || !strings.Contains(findings[1].Title, "secret_query") ||
		!strings.Contains(findings[1].Evidence, "prod.env") ||
		!strings.Contains(findings[0].Evidence, "prompts/list: complete") {
		t.Fatalf("second-page prompt disclosure not reported: %+v", findings)
	}
}

func TestCompletionUnauth_PartialTemplateInventoryRetainsDisclosure(t *testing.T) {
	srv := completionServer("resource-paged-partial-leak")
	defer srv.Close()
	findings := runCompletionUnauth(t, srv)
	if len(findings) != 2 || !strings.Contains(findings[0].Evidence, "resources/templates/list: incomplete") ||
		!strings.Contains(findings[0].Evidence, "completion assessment incomplete") ||
		!strings.Contains(findings[1].Evidence, "observed.txt") {
		t.Fatalf("partial inventory lost observed disclosure: %+v", findings)
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
// synthetic probe returns -32602 => medium indicator only.
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
	if findings[0].Confidence != attack.RiskIndicator {
		t.Errorf("generic validation error must be an indicator, got %q", findings[0].Confidence)
	}
}

// An internal error is observable but does not prove handler dispatch.
func TestCompletionUnauth_ReachableViaInternalError(t *testing.T) {
	srv := completionServer("reachable-internal")
	defer srv.Close()

	findings := runCompletionUnauth(t, srv)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 reachability finding for the -32603 response, got %d: %+v", len(findings), findings)
	}
	if findings[0].Severity != "medium" {
		t.Errorf("expected medium reachability finding, got %q", findings[0].Severity)
	}
	if findings[0].Confidence != attack.RiskIndicator || strings.Contains(findings[0].Evidence, "was dispatched") {
		t.Errorf("generic error must not prove dispatch: %+v", findings[0])
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

func TestCompletionUnauth_AuthGatedDiscovery(t *testing.T) {
	srv := completionServer("prompt-list-rpc-auth")
	defer srv.Close()
	if findings := runCompletionUnauth(t, srv); len(findings) != 0 {
		t.Errorf("expected clean result, got %+v", findings)
	}
}

func TestCompletionUnauth_IncompletePrerequisites(t *testing.T) {
	for _, mode := range []string{
		"prompt-list-fails",
		"prompt-list-malformed",
		"prompt-entry-malformed",
		"prompt-list-wrong-id",
		"prompt-list-non-auth-error",
		"prompt-list-unsupported",
		"prompt-list-paged",
		"template-list-fails",
		"template-list-unsupported",
		"resource-paged-fails",
		"resource-paged-loop",
		"resource-paged-badcursor",
		"template-entry-malformed",
		"real-probe-fails",
		"completion-server-error",
		"reference-limit",
	} {
		t.Run(mode, func(t *testing.T) {
			srv := completionServer(mode)
			defer srv.Close()
			assertInconclusive(t, mcpattack.NewCompletionUnauthExecutor(attack.RuleContext{ID: "mcp-completion-unauth-001"}), srv.URL, testOpts())
		})
	}
}

func TestCompletionUnauth_PartialDiscoveryRetainsFinding(t *testing.T) {
	srv := completionServer("partial-discovery-reachable")
	defer srv.Close()

	findings := runCompletionUnauth(t, srv)
	if len(findings) != 2 {
		t.Fatalf("expected reachability and disclosure findings, got %+v", findings)
	}
	if !strings.Contains(findings[0].Evidence, "prompts/list: incomplete") ||
		!strings.Contains(findings[0].Evidence, "resources/templates/list: complete") ||
		!strings.Contains(findings[0].Evidence, "completion assessment incomplete") {
		t.Errorf("missing partial-discovery outcome: %s", findings[0].Evidence)
	}
}

func TestCompletionUnauth_PartialProbeRetainsFinding(t *testing.T) {
	srv := completionServer("partial-probe-reachable")
	defer srv.Close()

	findings := runCompletionUnauth(t, srv)
	if len(findings) != 2 {
		t.Fatalf("expected reachability and disclosure findings, got %+v", findings)
	}
	if !strings.Contains(findings[0].Evidence, "1: incomplete (no verdict)") ||
		!strings.Contains(findings[0].Evidence, "2: reachable") ||
		!strings.Contains(findings[0].Evidence, "completion assessment incomplete") {
		t.Errorf("missing partial-probe outcome: %s", findings[0].Evidence)
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

	assertInconclusive(t, mcpattack.NewCompletionUnauthExecutor(attack.RuleContext{ID: "mcp-completion-unauth-001"}), srv.URL, testOpts())
}
