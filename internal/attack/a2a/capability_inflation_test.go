package a2a_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	a2aattack "github.com/calbebop/batesian/internal/attack/a2a"
)

func TestCapabilityInflation_AcceptsElevatedConfig(t *testing.T) {
	// Server accepts any tasks/send regardless of configuration content.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var req map[string]interface{}
		json.NewDecoder(r.Body).Decode(&req)
		method, _ := req["method"].(string)
		if method == "tasks/send" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]interface{}{
					"id": "task-1", "status": map[string]interface{}{"state": "completed"},
				},
			})
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	exec := a2aattack.NewCapabilityInflationExecutor(attack.RuleContext{ID: "a2a-capability-inflation-001", Remediation: "validate config"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings when server accepts elevated configuration without validation error")
	}
	for _, f := range findings {
		if f.Confidence != attack.RiskIndicator {
			t.Errorf("expected RiskIndicator confidence, got %v", f.Confidence)
		}
	}
}

func TestCapabilityInflation_RejectsElevatedConfig(t *testing.T) {
	// Server validates configuration and rejects unknown fields.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var req map[string]interface{}
		json.NewDecoder(r.Body).Decode(&req)
		method, _ := req["method"].(string)
		if method == "tasks/send" {
			params, _ := req["params"].(map[string]interface{})
			if _, hasConfig := params["configuration"]; hasConfig {
				// Reject requests with any configuration block.
				json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0", "id": req["id"],
					"error": map[string]interface{}{
						"code":    -32602,
						"message": "Unknown configuration fields: permissions, scope, runAs",
					},
				})
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]interface{}{"id": "task-1", "status": map[string]interface{}{"state": "completed"}},
			})
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	exec := a2aattack.NewCapabilityInflationExecutor(attack.RuleContext{ID: "a2a-capability-inflation-001", Remediation: "validate config"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when server rejects elevated config, got %d", len(findings))
	}
}

func TestCapabilityInflation_EchoesPrivilegeClaim(t *testing.T) {
	// Server reflects the "admin" keyword in its response.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var req map[string]interface{}
		json.NewDecoder(r.Body).Decode(&req)
		method, _ := req["method"].(string)
		if method == "tasks/send" {
			params, _ := req["params"].(map[string]interface{})
			body := map[string]interface{}{
				"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]interface{}{"id": "task-1", "status": "completed"},
			}
			if cfg, _ := params["configuration"].(map[string]interface{}); cfg != nil {
				if perms, ok := cfg["permissions"]; ok {
					// Echo the permissions back (vulnerable behavior).
					body["result"].(map[string]interface{})["grantedPermissions"] = perms
					body["result"].(map[string]interface{})["note"] = "admin access acknowledged"
				}
			}
			json.NewEncoder(w).Encode(body)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	exec := a2aattack.NewCapabilityInflationExecutor(attack.RuleContext{ID: "a2a-capability-inflation-001", Remediation: "validate config"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings when server echoes privilege claim keywords")
	}
	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "reflects") || strings.Contains(f.Title, "accepted") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a reflection or acceptance finding, got: %v", findings[0].Title)
	}
}
