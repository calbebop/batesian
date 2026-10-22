package a2a_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/attack/a2a"
)

func subscriptionServer(mode string) *httptest.Server {
	tasks := map[string]string{}
	nextTask := 0
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			ID     string `json:"id"`
			Method string `json:"method"`
			Params struct {
				ID string `json:"id"`
			} `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&request)
		who := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		result := func(value any) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": value})
		}
		rpcError := func(code int, message string) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID,
				"error": map[string]any{"code": code, "message": message}})
		}
		if strings.HasPrefix(mode, "legacy-") && !strings.Contains(request.Method, "/") {
			rpcError(-32601, "Method not found")
			return
		}
		if mode == "v1-update" && strings.Contains(request.Method, "/") {
			rpcError(-32601, "Method not found")
			return
		}
		state := "working"
		if mode == "terminal" {
			state = "completed"
		}
		snapshot := func(id string) map[string]any {
			return map[string]any{"id": id, "contextId": "private-context", "status": map[string]string{"state": state}}
		}
		switch request.Method {
		case "SendMessage", "message/send":
			if who != "tok-a" {
				rpcError(-32001, "Task not found")
				return
			}
			nextTask++
			id := "task-subscription-" + strconv.Itoa(nextTask)
			tasks[id] = who
			result(snapshot(id))
		case "GetTask", "tasks/get":
			owner := tasks[request.Params.ID]
			if owner == "" || (who != owner && mode != "shared") {
				rpcError(-32001, "Task not found")
				return
			}
			result(snapshot(request.Params.ID))
		case "SubscribeToTask", "tasks/resubscribe":
			owner := tasks[request.Params.ID]
			if mode == "unsupported" {
				rpcError(-32601, "Method not found")
				return
			}
			if owner == "" || (who != owner && mode == "bound") {
				rpcError(-32001, "Task not found")
				return
			}
			if mode == "empty-stream" {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = w.Write([]byte(": no task event\n\n"))
				return
			}
			id := request.Params.ID
			if mode == "wrong-task" && who == "tok-b" {
				id = "unrelated-task"
			}
			if mode == "wrong-context" && who == "tok-b" {
				payload, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": request.ID,
					"result": map[string]any{"id": id, "contextId": "unrelated-context",
						"status": map[string]string{"state": state}}})
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = w.Write(append(append([]byte("data: "), payload...), []byte("\n\n")...))
				return
			}
			replyID := request.ID
			if mode == "wrong-reply-id" && who == "tok-b" {
				replyID = "unrelated-request"
			}
			var event any = snapshot(id)
			if mode == "legacy-update-open" || mode == "v1-update" {
				event = map[string]any{"taskId": id, "contextId": "private-context", "kind": "status-update",
					"status": map[string]string{"state": state}}
			}
			if mode == "legacy-artifact-open" {
				event = map[string]any{"taskId": id, "contextId": "private-context", "kind": "artifact-update",
					"artifact": map[string]any{"artifactId": "private-artifact", "parts": []any{map[string]string{"text": "private"}}}}
			}
			if mode == "missing-context" && who == "tok-b" {
				event = map[string]any{"id": id, "status": map[string]string{"state": state}}
			}
			payload, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": replyID, "result": event})
			if mode == "json-not-stream" {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(payload)
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write(append(append([]byte("data: "), payload...), []byte("\n\n")...))
		default:
			rpcError(-32601, "Method not found")
		}
	}))
}

func TestSubscriptionScope(t *testing.T) {
	for _, tc := range []struct {
		mode         string
		findings     int
		inconclusive bool
	}{
		{mode: "bound"},
		{mode: "open", findings: 1},
		{mode: "legacy-open", findings: 1},
		{mode: "legacy-update-open", findings: 1},
		{mode: "legacy-artifact-open", findings: 1},
		{mode: "unsupported"},
		{mode: "shared", inconclusive: true},
		{mode: "wrong-task", inconclusive: true},
		{mode: "wrong-context", inconclusive: true},
		{mode: "wrong-reply-id", inconclusive: true},
		{mode: "missing-context", inconclusive: true},
		{mode: "empty-stream", inconclusive: true},
		{mode: "v1-update", inconclusive: true},
		{mode: "json-not-stream", inconclusive: true},
		{mode: "terminal", inconclusive: true},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			srv := subscriptionServer(tc.mode)
			defer srv.Close()
			rule := attack.RuleContext{ID: "a2a-subscription-scope-001", Name: "A2A Subscription and Task-Read Scope Mismatch",
				Severity: "high", Remediation: "Authorize subscription requests."}
			findings, err := a2a.NewSubscriptionScopeExecutor(rule).Execute(t.Context(), srv.URL,
				attack.Options{TimeoutSeconds: 3, Principals: pushPrincipals()})
			if len(findings) != tc.findings || errors.Is(err, attack.ErrInconclusive) != tc.inconclusive ||
				(err != nil && !tc.inconclusive) {
				t.Fatalf("findings=%+v err=%v", findings, err)
			}
			for _, finding := range findings {
				if finding.Confidence != attack.RiskIndicator || finding.Severity != "high" ||
					strings.Contains(finding.Evidence, "task-subscription-") ||
					!strings.Contains(finding.Evidence, "denied") {
					t.Fatalf("finding=%+v", finding)
				}
			}
		})
	}
}

func TestSubscriptionScopeNeedsDistinctPrincipals(t *testing.T) {
	findings, err := a2a.NewSubscriptionScopeExecutor(attack.RuleContext{}).Execute(t.Context(),
		"https://example.com", attack.Options{Principals: []attack.Principal{
			{Name: "owner", Token: "same"}, {Name: "other", Token: "same"},
		}})
	if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("findings=%+v err=%v", findings, err)
	}
}
