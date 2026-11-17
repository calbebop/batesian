package a2a_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/attack/a2a"
)

func subscriptionRESTServer(version, mode string) *httptest.Server {
	tasks := map[string]string{}
	nextTask := 0
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/agent-card.json" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"supportedInterfaces": []any{
				map[string]string{"url": server.URL + "/agent", "protocolBinding": "HTTP+JSON", "protocolVersion": version},
			}})
			return
		}
		prefix := "/agent"
		if version != "1.0" {
			prefix += "/v1"
		}
		path := strings.TrimPrefix(r.URL.Path, prefix)
		if !strings.HasPrefix(r.URL.Path, prefix) {
			http.NotFound(w, r)
			return
		}
		who := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		state := "TASK_STATE_WORKING"
		if version != "1.0" {
			state = "working"
		}
		if mode == "terminal" {
			state = "TASK_STATE_COMPLETED"
		}
		taskID := strings.TrimSuffix(strings.TrimPrefix(path, "/tasks/"), ":subscribe")
		task := func(id string) map[string]any {
			return map[string]any{"id": id, "contextId": "rest-private-context-" + id,
				"status": map[string]string{"state": state}}
		}
		switch {
		case r.Method == http.MethodPost && path == "/message:send":
			if who != "tok-a" && who != "tok-b" || mode == "reverse-setup-fails" && who == "tok-b" ||
				mode == "first-setup-fails-reverse-open" && who == "tok-a" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			nextTask++
			id := fmt.Sprintf("rest-private-task-%d", nextTask)
			if mode == "same-task-id" {
				id = "rest-private-task"
			}
			tasks[id] = who
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"task": task(id)})
		case r.Method == http.MethodGet && strings.HasPrefix(path, "/tasks/") && tasks[taskID] != "":
			if who != tasks[taskID] && mode != "shared" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(task(taskID))
		case r.Method == http.MethodPost && strings.HasPrefix(path, "/tasks/") &&
			strings.HasSuffix(path, ":subscribe") && tasks[taskID] != "":
			if mode == "unsupported" {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			if mode == "unsupported-status" {
				w.Header().Set("Content-Type", "application/a2a+json")
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": 400,
					"details": []any{map[string]string{"@type": "type.googleapis.com/google.rpc.ErrorInfo",
						"reason": "UNSUPPORTED_OPERATION", "domain": "a2a-protocol.org"}}}})
				return
			}
			if who != tasks[taskID] && (mode == "bound" || mode == "reverse-setup-fails" ||
				mode == "same-task-id" || strings.Contains(mode, "reverse-open") && tasks[taskID] == "tok-a") {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if mode == "not-stream" {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"task": task(taskID)})
				return
			}
			eventTask := task(taskID)
			if mode == "wrong-task" && who != tasks[taskID] {
				eventTask["id"] = "another-task"
			}
			if mode == "wrong-context" && who != tasks[taskID] {
				eventTask["contextId"] = "another-context"
			}
			event := map[string]any{"task": eventTask}
			if version != "1.0" && mode == "legacy-update" {
				event = map[string]any{"statusUpdate": map[string]any{"taskId": taskID,
					"contextId": eventTask["contextId"], "status": map[string]string{"state": state}}}
			}
			if version != "1.0" && mode == "legacy-artifact" {
				event = map[string]any{"artifactUpdate": map[string]any{"taskId": taskID,
					"contextId": eventTask["contextId"], "artifact": map[string]any{
						"artifactId": "private-artifact", "parts": []any{map[string]string{"text": "private"}}}}}
			}
			payload, _ := json.Marshal(event)
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write(append([]byte(": keepalive\n\ndata: "), append(payload, []byte("\n\n")...)...))
		default:
			http.NotFound(w, r)
		}
	}))
	return server
}

func TestSubscriptionScopeREST(t *testing.T) {
	for _, tc := range []struct {
		version, mode string
		findings      int
		inconclusive  bool
	}{
		{"1.0", "bound", 0, false},
		{"1.0", "open", 1, false},
		{"1.0", "reverse-open", 1, false},
		{"1.0", "first-setup-fails-reverse-open", 1, true},
		{"1.0", "reverse-setup-fails", 0, true},
		{"1.0", "same-task-id", 0, true},
		{"1.0", "unsupported", 0, false},
		{"1.0", "unsupported-status", 0, false},
		{"1.0", "shared", 0, true},
		{"1.0", "wrong-task", 0, true},
		{"1.0", "wrong-context", 0, true},
		{"1.0", "not-stream", 0, true},
		{"1.0", "terminal", 0, true},
		{"0.3.0", "open", 1, false},
		{"0.3.0", "reverse-open", 1, false},
		{"0.3.0", "legacy-update", 1, false},
		{"0.3.0", "legacy-artifact", 1, false},
	} {
		t.Run(tc.version+"-"+tc.mode, func(t *testing.T) {
			server := subscriptionRESTServer(tc.version, tc.mode)
			defer server.Close()
			rule := attack.RuleContext{ID: "a2a-subscription-scope-001", Name: "A2A Subscription and Task-Read Scope Mismatch",
				Severity: "high", Remediation: "Authorize subscription requests."}
			findings, err := a2a.NewSubscriptionScopeExecutor(rule).Execute(t.Context(), server.URL,
				attack.Options{TimeoutSeconds: 3, Principals: pushPrincipals()})
			if len(findings) != tc.findings || errors.Is(err, attack.ErrInconclusive) != tc.inconclusive ||
				(err != nil && !tc.inconclusive) {
				t.Fatalf("findings=%+v err=%v", findings, err)
			}
			for _, finding := range findings {
				if finding.Confidence != attack.RiskIndicator || !strings.Contains(finding.Evidence, "GET /") ||
					strings.Contains(finding.Evidence+finding.Description+finding.TargetURL, "rest-private-task") {
					t.Fatalf("finding=%+v", finding)
				}
			}
			if strings.Contains(tc.mode, "reverse-open") && !strings.Contains(findings[0].Description,
				"Principal \"tenant-a\" could not read principal \"tenant-b\"'s task") {
				t.Fatalf("reverse finding=%+v", findings[0])
			}
		})
	}
}
