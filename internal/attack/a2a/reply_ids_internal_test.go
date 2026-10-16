package a2a

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
)

func replayFirstReply(t *testing.T, result map[string]interface{}) (*httptest.Server, *[]string) {
	t.Helper()
	var firstID string
	ids := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID string `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		ids = append(ids, req.ID)
		w.Header().Set("Content-Type", "application/json")
		if firstID == "" {
			firstID = req.ID
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": firstID,
				"error": map[string]interface{}{"code": -32601, "message": "Method not found"},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": firstID, "result": result,
		})
	}))
	return server, &ids
}

func assertDistinctReplayIDs(t *testing.T, ids []string) {
	t.Helper()
	if len(ids) != 2 || ids[0] == ids[1] {
		t.Fatalf("request IDs = %q, want two distinct IDs", ids)
	}
}

func replayClient(url string) *attack.HTTPClient {
	return attack.NewHTTPClient(attack.Options{TimeoutSeconds: 2}, attack.NewVars(url, ""))
}

func TestContextFixationRejectsReplayedFallbackReply(t *testing.T) {
	server, ids := replayFirstReply(t, map[string]interface{}{"id": "task-1", "contextId": "ctx-1"})
	defer server.Close()
	result := NewContextFixationExecutor(attack.RuleContext{}).sendUnderContext(
		context.Background(), replayClient(server.URL), server.URL, nil, "ctx-1", "probe", "rand", "sending")
	if result.accepted || result.taskID != "" {
		t.Fatalf("replayed send reply accepted: %+v", result)
	}
	assertDistinctReplayIDs(t, *ids)
}

func TestDelegationRejectsReplayedTaskCreation(t *testing.T) {
	server, ids := replayFirstReply(t, map[string]interface{}{"id": "task-1", "contextId": "ctx-1"})
	defer server.Close()
	taskID, _, accepted, _ := NewDelegationIntegrityExecutor(attack.RuleContext{}).createTask(
		context.Background(), replayClient(server.URL), server.URL, attack.Principal{Name: "owner"}, "rand")
	if accepted || taskID != "" {
		t.Fatalf("replayed task creation accepted: task=%q accepted=%v", taskID, accepted)
	}
	assertDistinctReplayIDs(t, *ids)
}

func TestDelegationRejectsReplayedContinuation(t *testing.T) {
	server, ids := replayFirstReply(t, map[string]interface{}{"id": "task-1"})
	defer server.Close()
	outcome := NewDelegationIntegrityExecutor(attack.RuleContext{}).continueTask(
		context.Background(), replayClient(server.URL), server.URL, nil, "task-1", "ctx-1", "marker")
	if outcome != continuationUnobserved {
		t.Fatalf("replayed continuation outcome = %v, want unobserved", outcome)
	}
	assertDistinctReplayIDs(t, *ids)
}

func TestPushBindingRejectsReplayedFallbackReply(t *testing.T) {
	server, ids := replayFirstReply(t, map[string]interface{}{"taskId": "task-1", "id": "config-1", "url": "https://example.test/cb"})
	defer server.Close()
	set := NewPushBindingExecutor(attack.RuleContext{}).setPush(
		context.Background(), replayClient(server.URL), server.URL, nil, "setting a push config",
		"task-1", "https://example.test/cb", "token", "config-1", "rand")
	if set.accepted {
		t.Fatalf("replayed push-config reply accepted: %+v", set)
	}
	assertDistinctReplayIDs(t, *ids)
}

func TestPushBindingSetIDsSeparateConfigs(t *testing.T) {
	ids := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     string `json:"id"`
			Params struct {
				ID string `json:"id"`
			} `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		ids = append(ids, req.ID)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": req.ID,
			"result": map[string]string{"taskId": "task-1", "id": req.Params.ID, "url": "https://example.test/cb"},
		})
	}))
	defer server.Close()
	e := NewPushBindingExecutor(attack.RuleContext{})
	client := replayClient(server.URL)
	for _, configID := range []string{"owner", "attacker"} {
		set := e.setPush(context.Background(), client, server.URL, nil, "setting a push config",
			"task-1", "https://example.test/cb", "token", configID, "rand")
		if !set.accepted {
			t.Fatalf("config %q was not accepted: %+v", configID, set)
		}
	}
	assertDistinctReplayIDs(t, ids)
}
