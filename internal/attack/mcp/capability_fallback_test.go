package mcp_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

func modernUnadvertisedLists(expose bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		result := map[string]interface{}{}
		switch req.Method {
		case "server/discover":
			result = map[string]interface{}{
				"resultType": "complete", "supportedVersions": []string{"2026-07-28"},
				"capabilities": map[string]interface{}{},
			}
		case "tools/list":
			if expose {
				result = map[string]interface{}{"resultType": "complete", "tools": []map[string]string{{"name": "public_tool"}}}
			}
		case "prompts/list":
			if expose {
				result = map[string]interface{}{"resultType": "complete", "prompts": []map[string]string{{"name": "public_prompt"}}}
			}
		case "prompts/get":
			result = map[string]interface{}{"resultType": "complete", "messages": []map[string]interface{}{{
				"role": "user", "content": map[string]string{"type": "text", "text": "fixture content"},
			}}}
		}
		response := map[string]interface{}{"jsonrpc": "2.0", "id": req.ID}
		if len(result) == 0 {
			response["error"] = map[string]interface{}{"code": -32601, "message": "Method not found"}
		} else {
			response["result"] = result
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
}

func TestModernUnadvertisedListFallback(t *testing.T) {
	for _, tc := range []struct {
		name string
		exec attack.Executor
	}{
		{"tools", mcpattack.NewToolsUnauthExecutor(attack.RuleContext{ID: "mcp-tools-unauth-001"})},
		{"prompts", mcpattack.NewPromptUnauthExecutor(attack.RuleContext{ID: "mcp-prompt-unauth-001"})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := modernUnadvertisedLists(true)
			defer server.Close()
			findings, err := tc.exec.Execute(t.Context(), server.URL, testOpts())
			if len(findings) == 0 || err != nil {
				t.Fatalf("unadvertised list was missed: findings=%+v err=%v", findings, err)
			}
		})
		t.Run(tc.name+" absent", func(t *testing.T) {
			server := modernUnadvertisedLists(false)
			defer server.Close()
			findings, err := tc.exec.Execute(t.Context(), server.URL, testOpts())
			if len(findings) != 0 || err != nil {
				t.Fatalf("absent method should be clean: findings=%+v err=%v", findings, err)
			}
		})
	}
}
