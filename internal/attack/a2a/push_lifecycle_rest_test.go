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

func pushLifecycleRESTServer(version, mode string) *httptest.Server {
	var server *httptest.Server
	var configID, markerURL string
	present := false
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
		if !strings.HasPrefix(r.URL.Path, prefix+"/") {
			http.NotFound(w, r)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, prefix)
		who := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		writeJSON := func(value any) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(value)
		}
		config := func(id, callback string) any {
			if version == "1.0" {
				return map[string]string{"taskId": "rest-task", "id": id, "url": callback}
			}
			if mode == "legacy-optional-id" {
				return map[string]any{"name": "tasks/rest-task/pushNotificationConfigs/" + id,
					"pushNotificationConfig": map[string]string{"url": callback}}
			}
			return map[string]any{"name": "tasks/rest-task/pushNotificationConfigs/" + id,
				"pushNotificationConfig": map[string]string{"id": id, "url": callback}}
		}
		itemPath := "/tasks/rest-task/pushNotificationConfigs/" + configID
		switch {
		case r.Method == http.MethodPost && path == "/message:send":
			if who != "tok-a" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			writeJSON(map[string]any{"task": map[string]any{"id": "rest-task", "contextId": "rest-context",
				"status": map[string]string{"state": "TASK_STATE_WORKING"}}})
		case r.Method == http.MethodPost && path == "/tasks/rest-task/pushNotificationConfigs":
			if who != "tok-a" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			var body map[string]json.RawMessage
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if version == "1.0" {
				var request struct{ ID, URL string }
				_ = json.Unmarshal(body["id"], &request.ID)
				_ = json.Unmarshal(body["url"], &request.URL)
				configID, markerURL = request.ID, request.URL
			} else {
				var config struct {
					Name string                   `json:"name"`
					Push struct{ ID, URL string } `json:"pushNotificationConfig"`
				}
				_ = json.Unmarshal(body["config"], &config)
				configID, markerURL = config.Push.ID, config.Push.URL
			}
			present = true
			writeJSON(config(configID, markerURL))
		case r.Method == http.MethodGet && path == "/tasks/rest-task":
			if who != "tok-a" && mode != "shared" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			writeJSON(map[string]any{"id": "rest-task", "contextId": "rest-context",
				"status": map[string]string{"state": "TASK_STATE_WORKING"}})
		case r.Method == http.MethodGet && path == itemPath:
			if !present || who != "tok-a" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			writeJSON(config(configID, markerURL))
		case r.Method == http.MethodGet && path == "/tasks/rest-task/pushNotificationConfigs":
			if mode == "unsupported-list" {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			if mode == "list-loop" && who == "tok-a" {
				writeJSON(map[string]any{"configs": []any{}, "nextPageToken": "loop"})
				return
			}
			if mode == "list-malformed" && who == "tok-b" {
				writeJSON(map[string]any{"configs": "not an array"})
				return
			}
			allowed := who == "tok-a" || mode == "open" || mode == "list-open" || mode == "paged-open" || mode == "list-wrong-id"
			if !allowed {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			items := []any{}
			if present {
				id := configID
				if mode == "list-wrong-id" && who == "tok-b" {
					id = "different"
				}
				items = append(items, config(id, markerURL))
			}
			if version == "1.0" {
				if mode == "paged-open" && r.URL.Query().Get("pageToken") == "" {
					writeJSON(map[string]any{"configs": []any{}, "nextPageToken": "second"})
					return
				}
				writeJSON(map[string]any{"configs": items})
			} else {
				writeJSON(items)
			}
		case r.Method == http.MethodDelete && path == itemPath:
			if who == "tok-b" && mode == "unsupported-delete" {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			if who != "tok-a" && mode != "open" && mode != "delete-open" && mode != "delete-noop" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			if mode != "delete-noop" || who != "tok-b" {
				present = false
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	return server
}

func TestPushLifecycleREST(t *testing.T) {
	for _, tc := range []struct {
		version, mode string
		findings      int
		inconclusive  bool
	}{
		{"1.0", "bound", 0, false},
		{"1.0", "list-open", 1, false},
		{"1.0", "paged-open", 1, false},
		{"1.0", "delete-open", 1, false},
		{"1.0", "open", 2, false},
		{"1.0", "shared", 0, true},
		{"1.0", "list-loop", 0, true},
		{"1.0", "list-malformed", 0, true},
		{"1.0", "list-wrong-id", 0, false},
		{"1.0", "delete-noop", 0, true},
		{"1.0", "unsupported-list", 0, false},
		{"1.0", "unsupported-delete", 0, false},
		{"0.3.0", "bound", 0, false},
		{"0.3.0", "list-open", 1, false},
		{"0.3.0", "delete-open", 1, false},
		{"0.3.0", "open", 2, false},
		{"0.3.0", "shared", 0, true},
		{"0.3.0", "list-malformed", 0, true},
		{"0.3.0", "list-wrong-id", 0, false},
		{"0.3.0", "delete-noop", 0, true},
		{"0.3.0", "legacy-optional-id", 0, false},
	} {
		t.Run(tc.version+"-"+tc.mode, func(t *testing.T) {
			server := pushLifecycleRESTServer(tc.version, tc.mode)
			defer server.Close()
			state := &attack.TargetState{}
			findings, err := a2a.NewPushLifecycleExecutor(testRuleCtx()).Execute(t.Context(), server.URL,
				attack.Options{TimeoutSeconds: 3, Principals: pushPrincipals(), TargetState: state})
			if len(findings) != tc.findings || errors.Is(err, attack.ErrInconclusive) != tc.inconclusive ||
				(err != nil && !tc.inconclusive) {
				t.Fatalf("findings=%+v err=%v", findings, err)
			}
			objects := pushConfigObjects(state.Snapshot())
			if len(objects) != 1 || objects[0].Cleanup != attack.CleanupCompleted {
				t.Fatalf("cleanup=%+v", objects)
			}
			for _, finding := range findings {
				if finding.Confidence != attack.ConfirmedExploit || !strings.Contains(finding.Evidence, "GET task control: denied") ||
					!strings.Contains(finding.Evidence, "deleted") || !strings.Contains(finding.TargetURL, "/agent/") {
					t.Fatalf("finding=%+v", finding)
				}
			}
		})
	}
}
