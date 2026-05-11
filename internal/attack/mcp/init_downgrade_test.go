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

func TestInitDowngrade_VulnerableServer(t *testing.T) {
	// Server accepts ANY protocol version including the legacy pre-auth one
	// and returns resources without auth.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		method, _ := req["method"].(string)
		w.Header().Set("Content-Type", "application/json")
		switch method {
		case "initialize":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]interface{}{
					"protocolVersion": "2024-11-05",
					"serverInfo":      map[string]interface{}{"name": "vuln-server", "version": "0.1"},
					"capabilities":    map[string]interface{}{"resources": map[string]interface{}{}},
				},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "resources/list":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]interface{}{
					"resources": []interface{}{
						map[string]interface{}{"uri": "file:///secret.txt", "name": "secret"},
					},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	exec := mcpattack.NewInitDowngradeExecutor(attack.RuleContext{ID: "mcp-init-downgrade-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) < 2 {
		t.Fatalf("expected at least 2 findings, got %d", len(findings))
	}
	hasCritical := false
	for _, f := range findings {
		if f.Severity == "critical" {
			hasCritical = true
		}
	}
	if !hasCritical {
		t.Error("expected a critical finding for resources after downgrade")
	}
}

func TestInitDowngrade_VersionRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": req["id"],
			"error": map[string]interface{}{"code": -32600, "message": "Unsupported protocol version"},
		})
	}))
	defer srv.Close()

	exec := mcpattack.NewInitDowngradeExecutor(attack.RuleContext{ID: "mcp-init-downgrade-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for server that rejects legacy version, got %d", len(findings))
	}
}

func TestInitDowngrade_VersionAcceptedNoResources(t *testing.T) {
	// Server accepts the legacy version but enforces auth on resources.
	// Only the indicator finding should fire.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		method, _ := req["method"].(string)
		w.Header().Set("Content-Type", "application/json")
		switch method {
		case "initialize":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]interface{}{
					"protocolVersion": "2024-11-05",
					"serverInfo":      map[string]interface{}{"name": "partial-vuln", "version": "1.0"},
					"capabilities":    map[string]interface{}{"resources": map[string]interface{}{}},
				},
			})
		default:
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req["id"],
				"error": map[string]interface{}{"code": -32001, "message": "Unauthorized"},
			})
		}
	}))
	defer srv.Close()

	exec := mcpattack.NewInitDowngradeExecutor(attack.RuleContext{ID: "mcp-init-downgrade-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 indicator finding, got %d", len(findings))
	}
	if findings[0].Confidence != attack.RiskIndicator {
		t.Errorf("expected RiskIndicator, got %v", findings[0].Confidence)
	}
}
