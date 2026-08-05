package mcp_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

// Endpoint discovery tries /mcp, /, /api and /rpc. Several rules used to keep
// walking that list after a candidate had already answered as an MCP server,
// which buys nothing: the rest of the list is the same server at paths it does
// not serve. Measured against @modelcontextprotocol/server-everything it was 30%
// of a scan's requests, and 75% of one rule's.
//
// The server below answers at /mcp only and counts every request that lands
// anywhere else, so a rule that keeps walking fails.

// mountedMCPServer serves a working MCP endpoint at /mcp and 404s every other
// path, counting the strays.
func mountedMCPServer(t *testing.T) (*httptest.Server, *int64) {
	t.Helper()

	var strays int64
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mcp" {
			// Only the other candidate paths count. A rule may legitimately fetch
			// well-known OAuth metadata, which is discovery of a different kind.
			switch r.URL.Path {
			case "/", "/api", "/rpc":
				atomic.AddInt64(&strays, 1)
			}
			http.NotFound(w, r)
			return
		}

		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		method, _ := req["method"].(string)
		id := req["id"]
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Mcp-Session-Id", "srv-session-1")

		write := func(result interface{}) {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id, "result": result,
			})
		}

		switch method {
		case "initialize":
			write(map[string]interface{}{
				"protocolVersion": "2025-06-18",
				"serverInfo":      map[string]interface{}{"name": "walk-fixture", "version": "1.0"},
				"capabilities": map[string]interface{}{
					"tools": map[string]interface{}{}, "resources": map[string]interface{}{},
					"prompts": map[string]interface{}{}, "logging": map[string]interface{}{},
				},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			write(map[string]interface{}{"tools": []interface{}{
				map[string]interface{}{"name": "echo", "description": "echo"},
			}})
		case "resources/list":
			write(map[string]interface{}{"resources": []interface{}{
				map[string]interface{}{"uri": "file://a", "name": "a"},
			}})
		case "prompts/list":
			write(map[string]interface{}{"prompts": []interface{}{
				map[string]interface{}{"name": "p"},
			}})
		case "tools/call":
			write(map[string]interface{}{"content": []interface{}{
				map[string]string{"type": "text", "text": "ok"},
			}})
		default:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"error": map[string]interface{}{"code": -32601, "message": "Method not found"},
			})
		}
	})

	return httptest.NewServer(mux), &strays
}

func walkExecutors() map[string]attack.Executor {
	rc := attack.RuleContext{ID: "mcp-test-001", Name: "Test", Severity: "high", Remediation: "Fix"}
	return map[string]attack.Executor{
		"secret-canary":        mcpattack.NewSecretCanaryExecutor(rc),
		"init-downgrade":       mcpattack.NewInitDowngradeExecutor(rc),
		"sse-resume-replay":    mcpattack.NewSSEResumeReplayExecutor(rc),
		"header-body-split":    mcpattack.NewHeaderBodySplitExecutor(rc),
		"jsonrpc-batch-bypass": mcpattack.NewBatchBypassExecutor(rc),
		"oauth-audience":       mcpattack.NewOAuthAudienceExecutor(rc),
	}
}

func TestCandidateWalk_StopsOnceAnEndpointAnswers(t *testing.T) {
	for name, exec := range walkExecutors() {
		t.Run(name, func(t *testing.T) {
			ts, strays := mountedMCPServer(t)
			defer ts.Close()

			_, _ = exec.Execute(context.Background(), ts.URL, testOpts())

			if n := atomic.LoadInt64(strays); n != 0 {
				t.Errorf("kept walking after /mcp answered: %d request(s) to other candidate paths", n)
			}
		})
	}
}

// The boundary the change must not cross: when nothing answers, every candidate
// is still tried and the rule reports that it could not test, rather than a clean
// pass.
//
// oauth-audience is excluded. It reports a clean pass rather than inconclusive
// when no OAuth surface is reachable, which predates this change and is a
// separate question from the candidate walk.
func TestCandidateWalk_NothingAnswersIsStillInconclusive(t *testing.T) {
	for name, exec := range walkExecutors() {
		if name == "oauth-audience" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			var hits int64
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt64(&hits, 1)
				http.NotFound(w, r)
			}))
			defer ts.Close()

			_, err := exec.Execute(context.Background(), ts.URL, testOpts())
			if !errors.Is(err, attack.ErrInconclusive) {
				t.Errorf("expected ErrInconclusive against a 404-everything server, got err=%v", err)
			}
			if atomic.LoadInt64(&hits) == 0 {
				t.Error("no candidate was tried at all")
			}
		})
	}
}
