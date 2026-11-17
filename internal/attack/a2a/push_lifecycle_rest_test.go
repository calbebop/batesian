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

func pushLifecycleRESTServer(version, mode string) *httptest.Server {
	var server *httptest.Server
	var configID, markerURL, taskID, taskOwner string
	nextTask := 0
	present := false
	reverseOpen := func(operation string) bool {
		return mode == "reverse-open" || mode == "first-setup-fails-reverse-open" || mode == "reverse-open-"+operation
	}
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
				return map[string]string{"taskId": taskID, "id": id, "url": callback}
			}
			if mode == "legacy-optional-id" {
				return map[string]any{"name": "tasks/" + taskID + "/pushNotificationConfigs/" + id,
					"pushNotificationConfig": map[string]string{"url": callback}}
			}
			return map[string]any{"name": "tasks/" + taskID + "/pushNotificationConfigs/" + id,
				"pushNotificationConfig": map[string]string{"id": id, "url": callback}}
		}
		configPath := "/tasks/" + taskID + "/pushNotificationConfigs"
		itemPath := configPath + "/" + configID
		switch {
		case r.Method == http.MethodPost && path == "/message:send":
			if who != "tok-a" && who != "tok-b" || mode == "first-setup-fails-reverse-open" && who == "tok-a" ||
				mode == "reverse-setup-fails" && who == "tok-b" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			nextTask++
			taskID = fmt.Sprintf("rest-task-%d", nextTask)
			if mode == "same-task-id" {
				taskID = "rest-task"
			}
			taskOwner = who
			configID, markerURL, present = "", "", false
			writeJSON(map[string]any{"task": map[string]any{"id": taskID, "contextId": "rest-context-" + taskID,
				"status": map[string]string{"state": "TASK_STATE_WORKING"}}})
		case r.Method == http.MethodPost && path == configPath && taskID != "":
			if who != taskOwner {
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
		case r.Method == http.MethodGet && path == "/tasks/"+taskID && taskID != "":
			if who != taskOwner && mode != "shared" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			writeJSON(map[string]any{"id": taskID, "contextId": "rest-context-" + taskID,
				"status": map[string]string{"state": "TASK_STATE_WORKING"}})
		case r.Method == http.MethodGet && path == itemPath && taskID != "":
			if !present || who != taskOwner {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			writeJSON(config(configID, markerURL))
		case r.Method == http.MethodGet && path == configPath && taskID != "":
			if mode == "unsupported-list" {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			if mode == "list-loop" && who == taskOwner {
				writeJSON(map[string]any{"configs": []any{}, "nextPageToken": "loop"})
				return
			}
			if mode == "list-malformed" && who != taskOwner {
				writeJSON(map[string]any{"configs": "not an array"})
				return
			}
			allowed := who == taskOwner || mode == "open" || mode == "list-open" || mode == "paged-open" ||
				mode == "list-wrong-id" || reverseOpen("list") && taskOwner == "tok-b"
			if !allowed {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			items := []any{}
			if present {
				id := configID
				if mode == "list-wrong-id" && who != taskOwner {
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
		case r.Method == http.MethodDelete && path == itemPath && taskID != "":
			if who != taskOwner && mode == "unsupported-delete" {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			if who != taskOwner && mode != "open" && mode != "delete-open" && mode != "delete-noop" &&
				(!reverseOpen("delete") || taskOwner != "tok-b") {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			if mode != "delete-noop" || who == taskOwner {
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
		{"1.0", "list-open", 2, false},
		{"1.0", "paged-open", 2, false},
		{"1.0", "delete-open", 2, false},
		{"1.0", "open", 4, false},
		{"1.0", "reverse-open-list", 1, false},
		{"1.0", "reverse-open-delete", 1, false},
		{"1.0", "reverse-open", 2, false},
		{"1.0", "first-setup-fails-reverse-open", 2, true},
		{"1.0", "reverse-setup-fails", 0, true},
		{"1.0", "same-task-id", 0, true},
		{"1.0", "shared", 0, true},
		{"1.0", "list-loop", 0, true},
		{"1.0", "list-malformed", 0, true},
		{"1.0", "list-wrong-id", 0, false},
		{"1.0", "delete-noop", 0, true},
		{"1.0", "unsupported-list", 0, false},
		{"1.0", "unsupported-delete", 0, false},
		{"0.3.0", "bound", 0, false},
		{"0.3.0", "list-open", 2, false},
		{"0.3.0", "delete-open", 2, false},
		{"0.3.0", "open", 4, false},
		{"0.3.0", "reverse-open-list", 1, false},
		{"0.3.0", "reverse-open-delete", 1, false},
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
			assertPushFindingsOmitObjectIDs(t, findings, objects)
			wantObjects := 2
			if tc.mode == "first-setup-fails-reverse-open" || tc.mode == "reverse-setup-fails" ||
				tc.mode == "same-task-id" {
				wantObjects = 1
			}
			if len(objects) != wantObjects {
				t.Fatalf("cleanup=%+v", objects)
			}
			for _, object := range objects {
				if object.Cleanup != attack.CleanupCompleted {
					t.Fatalf("cleanup=%+v", objects)
				}
			}
			for _, finding := range findings {
				if finding.Confidence != attack.RiskIndicator || !strings.Contains(finding.Evidence, "GET task control: denied") ||
					!strings.Contains(finding.Evidence, "deleted") || !strings.Contains(finding.TargetURL, "/agent/") {
					t.Fatalf("finding=%+v", finding)
				}
			}
			if strings.Contains(tc.mode, "reverse-open") && len(findings) > 0 {
				reverseFound := false
				for _, finding := range findings {
					reverseFound = reverseFound || strings.Contains(finding.Description,
						"Principal \"tenant-a\" could not read principal \"tenant-b\"'s task")
				}
				if !reverseFound {
					t.Fatalf("reverse finding missing: %+v", findings)
				}
			}
		})
	}
}
