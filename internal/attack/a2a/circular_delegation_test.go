package a2a_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	a2aattack "github.com/calbebop/batesian/internal/attack/a2a"
)

func a2aRPCBase(w http.ResponseWriter, req map[string]interface{}, handler func(http.ResponseWriter, map[string]interface{})) {
	method, _ := req["method"].(string)
	w.Header().Set("Content-Type", "application/json")
	if method == "tasks/send" {
		handler(w, req)
	} else {
		http.NotFound(w, nil)
	}
}

func TestCircularDelegation_AcceptsDeepChain(t *testing.T) {
	// Server accepts tasks/send with any configuration, including deep delegation chains.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		json.NewDecoder(r.Body).Decode(&req)
		a2aRPCBase(w, req, func(w http.ResponseWriter, req map[string]interface{}) {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]interface{}{
					"id":     "task-1",
					"status": map[string]interface{}{"state": "completed"},
				},
			})
		})
	}))
	defer srv.Close()

	exec := a2aattack.NewCircularDelegationExecutor(attack.RuleContext{ID: "a2a-circular-delegation-001", Remediation: "add depth limit"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding when server accepts deep delegation chain without depth limit error")
	}
	if findings[0].Confidence != attack.RiskIndicator {
		t.Errorf("expected RiskIndicator confidence, got %v", findings[0].Confidence)
	}
}

func TestCircularDelegation_EnforcesDepthLimit(t *testing.T) {
	// Server returns a JSON-RPC error when delegation depth exceeds limit.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		method, _ := req["method"].(string)
		if method == "tasks/send" {
			params, _ := req["params"].(map[string]interface{})
			cfg, _ := params["configuration"].(map[string]interface{})
			if hopCount, _ := cfg["hopCount"].(float64); hopCount >= 5 {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0", "id": req["id"],
					"error": map[string]interface{}{
						"code":    -32600,
						"message": "delegation depth limit exceeded (max 5 hops)",
					},
				})
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]interface{}{"id": "task-1", "status": map[string]interface{}{"state": "completed"}},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	exec := a2aattack.NewCircularDelegationExecutor(attack.RuleContext{ID: "a2a-circular-delegation-001", Remediation: "add depth limit"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when server enforces delegation depth limit, got %d", len(findings))
	}
}
