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

func resourcesRC() attack.RuleContext {
	return attack.RuleContext{
		ID:          "mcp-resources-unauth-001",
		Name:        "MCP Resources Unauthenticated Read",
		Severity:    "critical",
		Remediation: "Require authentication on all MCP endpoints.",
	}
}

// mcpResourcesServer builds a test server that serves resources/list and
// resources/read without any authentication.
func mcpResourcesServer(t *testing.T, resources []map[string]interface{}, readContent string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}

		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", 400)
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
					"serverInfo":      map[string]interface{}{"name": "test", "version": "1.0"},
					"capabilities":    map[string]interface{}{"resources": map[string]interface{}{}},
				},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusOK)
		case "resources/list":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      id,
				"result":  map[string]interface{}{"resources": resources},
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
							"text":     readContent,
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
	}))
}

// mcpResourcesRequireAuthServer returns 401 for all resource requests.
func mcpResourcesRequireAuthServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		json.NewDecoder(r.Body).Decode(&req)
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
					"serverInfo":      map[string]interface{}{"name": "secure", "version": "1.0"},
					"capabilities":    map[string]interface{}{"resources": map[string]interface{}{}},
				},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusOK)
		default:
			// Reject with JSON-RPC auth error
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      id,
				"error":   map[string]interface{}{"code": -32000, "message": "Authentication required"},
			})
		}
	}))
}

func TestResourcesUnauth_Vulnerable(t *testing.T) {
	resources := []map[string]interface{}{
		{"uri": "config://database", "name": "DB Config", "mimeType": "text/plain"},
		{"uri": "config://app", "name": "App Config", "mimeType": "text/plain"},
	}
	content := "postgresql://admin:password123@db.internal:5432/prod"

	ts := mcpResourcesServer(t, resources, content)
	defer ts.Close()

	exec := mcpattack.NewResourcesUnauthExecutor(resourcesRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) < 2 {
		t.Fatalf("expected at least 2 findings (list + read), got %d", len(findings))
	}

	// Should have a critical finding for the read
	hasCritical := false
	for _, f := range findings {
		if f.Severity == "critical" {
			hasCritical = true
		}
	}
	if !hasCritical {
		t.Errorf("expected a critical finding for readable resource content, got: %v", findings)
	}
	for _, f := range findings {
		if f.Confidence != attack.ConfirmedExploit {
			t.Errorf("finding %q: want ConfirmedExploit, got %q", f.Title, f.Confidence)
		}
	}
}

func TestResourcesUnauth_CredentialInContent(t *testing.T) {
	resources := []map[string]interface{}{
		{"uri": "secrets://api", "name": "API Keys", "mimeType": "text/plain"},
	}
	// Contains an AWS access key — should trigger credential detection
	content := "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI"

	ts := mcpResourcesServer(t, resources, content)
	defer ts.Close()

	exec := mcpattack.NewResourcesUnauthExecutor(resourcesRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Credential detection should escalate to critical
	for _, f := range findings {
		if strings.Contains(f.Evidence, "AKIA") || f.Severity == "critical" {
			return // passed
		}
	}
	t.Errorf("expected credential detection in findings, got: %v", findings)
}

func TestResourcesUnauth_AuthRequired(t *testing.T) {
	ts := mcpResourcesRequireAuthServer(t)
	defer ts.Close()

	exec := mcpattack.NewResourcesUnauthExecutor(resourcesRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings when auth required, got %d", len(findings))
	}
}

func TestResourcesUnauth_NoResources(t *testing.T) {
	// Server returns empty resources list — nothing to read, no finding expected.
	ts := mcpResourcesServer(t, []map[string]interface{}{}, "")
	defer ts.Close()

	exec := mcpattack.NewResourcesUnauthExecutor(resourcesRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings with empty resource list, got %d", len(findings))
	}
}

func TestResourcesUnauth_NotMCPServer(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	defer ts.Close()

	exec := mcpattack.NewResourcesUnauthExecutor(resourcesRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings on non-MCP server, got %d", len(findings))
	}
}
