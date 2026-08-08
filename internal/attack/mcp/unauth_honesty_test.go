package mcp_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

// listingServer is a wide-open MCP server whose listing methods answer according
// to mode. Nothing is ever authorization-checked, so what the unauth rules should
// report depends only on whether they could establish anything.
//
//	"open" every listing returns a result       => findings
//	"401"  every listing returns 401            => clean, auth is enforced
//	"502"  every listing returns a gateway 502  => inconclusive, nothing was established
//
// The 401 and 502 cases used to be indistinguishable: both gates were
// `if err != nil || !resp.IsSuccess() { return nil }`, so a scan claimed the
// surfaces were secure when it had merely failed to reach them.
func listingServer(t *testing.T, mode string) *httptest.Server {
	t.Helper()
	// completion/complete is included because it is completion-unauth's own probe.
	// With only the listings affected, that rule reaches completion/complete, gets a
	// -32601, and correctly concludes the surface is absent, so the mode would
	// never exercise what this test is about.
	listings := map[string]map[string]interface{}{
		"tools/list":          {"tools": []interface{}{map[string]interface{}{"name": "echo"}}},
		"prompts/list":        {"prompts": []interface{}{map[string]interface{}{"name": "greet"}}},
		"resources/list":      {"resources": []interface{}{map[string]interface{}{"uri": "config://db"}}},
		"completion/complete": {"completion": map[string]interface{}{"values": []interface{}{"alpha", "beta"}}},
		// logging/setLevel is included for the same reason: left to fall through it
		// answers -32601, which correctly reads as the method being absent, so the
		// mode would never reach logging-unauth's gate.
		"logging/setLevel": {},
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mcp" {
			http.NotFound(w, r)
			return
		}
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		method, _ := body["method"].(string)
		id := body["id"]
		w.Header().Set("Content-Type", "application/json")

		result := func(v map[string]interface{}) {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": id, "result": v})
		}

		switch method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "listing-session")
			result(map[string]interface{}{
				"protocolVersion": "2025-06-18",
				"serverInfo":      map[string]interface{}{"name": "listing", "version": "1"},
				"capabilities": map[string]interface{}{
					"tools": map[string]interface{}{}, "prompts": map[string]interface{}{},
					"resources": map[string]interface{}{}, "logging": map[string]interface{}{},
					"completions": map[string]interface{}{},
				},
			})
			return
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
			return
		}

		if listing, isListing := listings[method]; isListing {
			switch mode {
			case "502":
				// A gateway failure. It says nothing about authorization.
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusBadGateway)
				_, _ = w.Write([]byte("Bad Gateway"))
			case "401":
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0", "id": id,
					"error": map[string]interface{}{"code": -32001, "message": "Unauthorized"},
				})
			default:
				result(listing)
			}
			return
		}

		switch method {
		case "resources/read":
			result(map[string]interface{}{"contents": []interface{}{
				map[string]interface{}{"uri": "config://db", "text": "plain content"}}})
		case "prompts/get":
			result(map[string]interface{}{"messages": []interface{}{
				map[string]interface{}{"role": "user", "content": map[string]interface{}{"type": "text", "text": "Hello"}}}})
		case "tools/call":
			result(map[string]interface{}{"content": []interface{}{
				map[string]interface{}{"type": "text", "text": "ok"}}})
		default:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"error": map[string]interface{}{"code": -32601, "message": "Method not found"},
			})
		}
	}))
}

// unauthFamily is the set converted in this increment. Each is driven through the
// same three server postures, because the defect and the fix are shared.
func unauthFamily() map[string]func(attack.RuleContext) attack.Executor {
	return map[string]func(attack.RuleContext) attack.Executor{
		"mcp-tools-unauth-001":      func(rc attack.RuleContext) attack.Executor { return mcpattack.NewToolsUnauthExecutor(rc) },
		"mcp-prompt-unauth-001":     func(rc attack.RuleContext) attack.Executor { return mcpattack.NewPromptUnauthExecutor(rc) },
		"mcp-resources-unauth-001":  func(rc attack.RuleContext) attack.Executor { return mcpattack.NewResourcesUnauthExecutor(rc) },
		"mcp-completion-unauth-001": func(rc attack.RuleContext) attack.Executor { return mcpattack.NewCompletionUnauthExecutor(rc) },
		"mcp-logging-unauth-001":    func(rc attack.RuleContext) attack.Executor { return mcpattack.NewLoggingUnauthExecutor(rc) },
	}
}

// A gateway failure on the listing is not evidence of a closed surface, so the
// rule must report that it could not test rather than that the server is secure.
func TestUnauthFamily_GatewayFailureIsInconclusive(t *testing.T) {
	srv := listingServer(t, "502")
	defer srv.Close()

	for id, mk := range unauthFamily() {
		t.Run(id, func(t *testing.T) {
			exec := mk(attack.RuleContext{ID: id, Name: id, Severity: "high"})
			findings, err := exec.Execute(context.Background(), srv.URL, testOpts())
			if len(findings) != 0 {
				t.Fatalf("expected no findings against a 502, got %d", len(findings))
			}
			if !errors.Is(err, attack.ErrInconclusive) {
				t.Errorf("a 502 established nothing, so this must be inconclusive, got err=%v", err)
			}
			// The handshake succeeded here, so the reason must say what actually
			// happened. Reported as bare unreachability, this sends the operator
			// looking for a network fault when the server is answering fine.
			if !strings.Contains(err.Error(), "handshake succeeded") {
				t.Errorf("inconclusive reason should record that the handshake succeeded and the "+
					"probe returned no verdict, got: %v", err)
			}
		})
	}
}

// Auth genuinely enforced. A clean report is correct here, and must not be
// collateral damage from the fix.
func TestUnauthFamily_AuthEnforcedStaysClean(t *testing.T) {
	srv := listingServer(t, "401")
	defer srv.Close()

	for id, mk := range unauthFamily() {
		t.Run(id, func(t *testing.T) {
			exec := mk(attack.RuleContext{ID: id, Name: id, Severity: "high"})
			findings, err := exec.Execute(context.Background(), srv.URL, testOpts())
			if err != nil {
				t.Fatalf("auth enforced is a tested, clean result, not an error: %v", err)
			}
			if len(findings) != 0 {
				t.Errorf("expected no findings when auth is enforced, got %d", len(findings))
			}
		})
	}
}

// The positive direction, so the conversion is not silently suppressing findings.
func TestUnauthFamily_OpenServerStillFires(t *testing.T) {
	srv := listingServer(t, "open")
	defer srv.Close()

	for _, id := range []string{"mcp-tools-unauth-001", "mcp-prompt-unauth-001",
		"mcp-resources-unauth-001", "mcp-logging-unauth-001"} {
		t.Run(id, func(t *testing.T) {
			exec := unauthFamily()[id](attack.RuleContext{ID: id, Name: id, Severity: "high"})
			findings, err := exec.Execute(context.Background(), srv.URL, testOpts())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(findings) == 0 {
				t.Error("an open server must still produce findings")
			}
		})
	}
}
