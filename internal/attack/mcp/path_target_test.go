package mcp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

// An operator scanning an MCP server usually has its published URL, and that URL
// carries the path the handler is mounted at: https://host/mcp is the
// convention. Endpoint discovery used to only ever append to the target, so it
// probed /mcp/mcp, /mcp/, /mcp/api and /mcp/rpc and never /mcp itself. Every MCP
// rule then reported that it could not reach a testable endpoint, and a real
// exposure went unreported.
//
// The servers below answer at one path and 404 everywhere else, which is what
// makes them a regression test: a handler that replies on any path (as the other
// harnesses in this package do) is satisfied by the first appended candidate and
// cannot catch this.

// mountedResourcesServer serves the unauthenticated resources handler at
// mountPath only.
func mountedResourcesServer(t *testing.T, mountPath string) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc(mountPath, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != mountPath {
			http.NotFound(w, r)
			return
		}
		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		method, _ := req["method"].(string)
		id := req["id"]
		w.Header().Set("Content-Type", "application/json")

		switch method {
		case "initialize":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      id,
				"result": map[string]interface{}{
					"protocolVersion": "2025-03-26",
					"serverInfo":      map[string]interface{}{"name": "mounted", "version": "1.0"},
					"capabilities":    map[string]interface{}{"resources": map[string]interface{}{}},
				},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusOK)
		case "resources/list":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      id,
				"result": map[string]interface{}{
					"resources": []map[string]interface{}{
						{"uri": "config://database", "name": "DB Config", "mimeType": "text/plain"},
					},
				},
			})
		case "resources/read":
			params, _ := req["params"].(map[string]interface{})
			uri, _ := params["uri"].(string)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      id,
				"result": map[string]interface{}{
					"contents": []interface{}{
						map[string]interface{}{
							"uri":      uri,
							"mimeType": "text/plain",
							"text":     "Welcome to the public configuration overview page.",
						},
					},
				},
			})
		default:
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      id,
				"error":   map[string]interface{}{"code": -32601, "message": "Method not found"},
			})
		}
	})

	return httptest.NewServer(mux)
}

func TestResourcesUnauth_TargetNamesTheEndpointPath(t *testing.T) {
	ts := mountedResourcesServer(t, "/mcp")
	defer ts.Close()

	exec := mcpattack.NewResourcesUnauthExecutor(resourcesRC())

	for _, target := range []string{ts.URL + "/mcp", ts.URL + "/mcp/"} {
		t.Run(target, func(t *testing.T) {
			findings, err := exec.Execute(context.Background(), target, testOpts())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(findings) < 2 {
				t.Fatalf("expected at least 2 findings (list + read), got %d", len(findings))
			}
		})
	}
}

// A handler mounted somewhere other than a conventional path is only reachable
// when the target itself is probed, so this pins that the fix is not just
// "/mcp works now".
func TestResourcesUnauth_TargetNamesAnUnconventionalPath(t *testing.T) {
	ts := mountedResourcesServer(t, "/services/agent/jsonrpc")
	defer ts.Close()

	exec := mcpattack.NewResourcesUnauthExecutor(resourcesRC())
	findings, err := exec.Execute(context.Background(), ts.URL+"/services/agent/jsonrpc", testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) < 2 {
		t.Fatalf("expected at least 2 findings (list + read), got %d", len(findings))
	}
}

// The origin form must keep working unchanged: a server mounted at /mcp is
// still found when the operator passes only the origin.
func TestResourcesUnauth_OriginTargetStillReachesMountedHandler(t *testing.T) {
	ts := mountedResourcesServer(t, "/mcp")
	defer ts.Close()

	exec := mcpattack.NewResourcesUnauthExecutor(resourcesRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) < 2 {
		t.Fatalf("expected at least 2 findings (list + read), got %d", len(findings))
	}
}

// A target naming a path that has no handler must still report that it could not
// test, rather than being rescued into a clean pass by the appended candidates.
func TestResourcesUnauth_WrongPathTargetIsStillInconclusive(t *testing.T) {
	ts := mountedResourcesServer(t, "/mcp")
	defer ts.Close()

	exec := mcpattack.NewResourcesUnauthExecutor(resourcesRC())
	assertInconclusive(t, exec, ts.URL+"/not-the-handler", testOpts())
}
