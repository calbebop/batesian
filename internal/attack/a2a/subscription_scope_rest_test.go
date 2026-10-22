package a2a_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/attack/a2a"
)

func subscriptionRESTServer(version, mode string) *httptest.Server {
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
		task := map[string]any{"id": "rest-private-task", "contextId": "rest-private-context",
			"status": map[string]string{"state": state}}
		switch {
		case r.Method == http.MethodPost && path == "/message:send":
			if who != "tok-a" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"task": task})
		case r.Method == http.MethodGet && path == "/tasks/rest-private-task":
			if who != "tok-a" && mode != "shared" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(task)
		case r.Method == http.MethodPost && path == "/tasks/rest-private-task:subscribe":
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
			if who != "tok-a" && mode == "bound" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if mode == "not-stream" {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"task": task})
				return
			}
			if mode == "wrong-task" && who == "tok-b" {
				task["id"] = "another-task"
			}
			if mode == "wrong-context" && who == "tok-b" {
				task["contextId"] = "another-context"
			}
			event := map[string]any{"task": task}
			if version != "1.0" && mode == "legacy-update" {
				event = map[string]any{"statusUpdate": map[string]any{"taskId": "rest-private-task",
					"contextId": "rest-private-context", "status": map[string]string{"state": state}}}
			}
			if version != "1.0" && mode == "legacy-artifact" {
				event = map[string]any{"artifactUpdate": map[string]any{"taskId": "rest-private-task",
					"contextId": "rest-private-context", "artifact": map[string]any{
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
		{"1.0", "unsupported", 0, false},
		{"1.0", "unsupported-status", 0, false},
		{"1.0", "shared", 0, true},
		{"1.0", "wrong-task", 0, true},
		{"1.0", "wrong-context", 0, true},
		{"1.0", "not-stream", 0, true},
		{"1.0", "terminal", 0, true},
		{"0.3.0", "open", 1, false},
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
		})
	}
}
