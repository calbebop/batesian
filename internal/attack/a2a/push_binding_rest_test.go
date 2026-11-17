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

func pushBindingRESTServer(version, mode string) *httptest.Server {
	var server *httptest.Server
	tasks := map[string]string{}
	configs := map[string]map[string]string{}
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
		taskID, configID := "", ""
		if strings.HasPrefix(path, "/tasks/") {
			parts := strings.Split(strings.TrimPrefix(path, "/tasks/"), "/")
			taskID = parts[0]
			if len(parts) == 3 && parts[1] == "pushNotificationConfigs" {
				configID = parts[2]
			}
		}
		owner := tasks[taskID]
		writeJSON := func(value any) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(value)
		}
		config := func(id, callback string) any {
			if version == "1.0" {
				return map[string]string{"taskId": taskID, "id": id, "url": callback}
			}
			return map[string]any{"name": "tasks/" + taskID + "/pushNotificationConfigs/" + id,
				"pushNotificationConfig": map[string]string{"id": id, "url": callback}}
		}
		switch {
		case r.Method == http.MethodPost && path == "/message:send":
			if mode == "reverse-route-unavailable" && who == "tok-b" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if (who != "tok-a" && who != "tok-b") || mode == "reverse-setup-fails" && who == "tok-b" ||
				mode == "first-setup-fails-reverse-cross-read" && who == "tok-a" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			taskID = "rest-task-" + who
			if mode == "same-task-id" {
				taskID = "rest-task-shared"
			}
			tasks[taskID] = who
			writeJSON(map[string]any{"task": map[string]any{"id": taskID, "contextId": "rest-context-" + who,
				"status": map[string]string{"state": "TASK_STATE_WORKING"}}})
		case r.Method == http.MethodGet && taskID != "" && path == "/tasks/"+taskID:
			allowed := owner != "" && (who == owner || who != owner && mode == "shared") ||
				who == "" && mode == "public-task"
			if !allowed {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			writeJSON(map[string]any{"id": taskID, "contextId": "rest-context-" + owner,
				"status": map[string]string{"state": "TASK_STATE_WORKING"}})
		case r.Method == http.MethodPost && taskID != "" && path == "/tasks/"+taskID+"/pushNotificationConfigs":
			allowed := owner != "" && (who == owner || who != "" && who != owner &&
				(mode == "cross-write" || mode == "cross-write-noop" || mode == "reverse-cross-write" && owner == "tok-b")) ||
				who == "" && mode == "anonymous-write"
			if !allowed {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			var body map[string]json.RawMessage
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			id, callback := "", ""
			if version == "1.0" {
				_ = json.Unmarshal(body["id"], &id)
				_ = json.Unmarshal(body["url"], &callback)
			} else {
				var request struct {
					Config struct {
						Push struct {
							ID  string `json:"id"`
							URL string `json:"url"`
						} `json:"pushNotificationConfig"`
					} `json:"config"`
				}
				_ = json.Unmarshal(body["config"], &request.Config)
				id, callback = request.Config.Push.ID, request.Config.Push.URL
			}
			if id == "" || callback == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if mode != "cross-write-noop" || who == owner {
				if configs[taskID] == nil {
					configs[taskID] = map[string]string{}
				}
				configs[taskID][id] = callback
			}
			writeJSON(config(id, callback))
		case r.Method == http.MethodGet && configID != "":
			callback, ok := configs[taskID][configID]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			allowed := who == owner || who != "" && who != owner &&
				(mode == "cross-read" || mode == "cross-read-wrong-url" ||
					(mode == "reverse-cross-read" || mode == "first-setup-fails-reverse-cross-read") && owner == "tok-b")
			if !allowed {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			if who != owner && mode == "cross-read-wrong-url" {
				callback = "https://redacted.example/cb"
			}
			writeJSON(config(configID, callback))
		case r.Method == http.MethodDelete && configID != "":
			if who != owner {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			delete(configs[taskID], configID)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	return server
}

func TestPushBindingREST(t *testing.T) {
	for _, tc := range []struct {
		version, mode, title string
		count                int
		inconclusive         bool
	}{
		{"1.0", "bound", "", 0, false},
		{"1.0", "anonymous-write", "writable without authentication", 2, false},
		{"1.0", "cross-read", "readable across principals", 2, false},
		{"1.0", "cross-write", "writable across principals", 2, false},
		{"1.0", "reverse-cross-read", "readable across principals", 1, false},
		{"1.0", "reverse-cross-write", "writable across principals", 1, false},
		{"1.0", "cross-write-noop", "", 0, true},
		{"1.0", "cross-read-wrong-url", "", 0, true},
		{"1.0", "shared", "", 0, true},
		{"1.0", "public-task", "", 0, true},
		{"1.0", "same-task-id", "", 0, true},
		{"1.0", "reverse-setup-fails", "", 0, true},
		{"1.0", "reverse-route-unavailable", "", 0, true},
		{"1.0", "first-setup-fails-reverse-cross-read", "readable across principals", 1, true},
		{"0.3.0", "bound", "", 0, false},
		{"0.3.0", "anonymous-write", "writable without authentication", 2, false},
		{"0.3.0", "cross-read", "readable across principals", 2, false},
		{"0.3.0", "cross-write", "writable across principals", 2, false},
		{"0.3.0", "reverse-cross-read", "readable across principals", 1, false},
		{"0.3.0", "reverse-cross-write", "writable across principals", 1, false},
		{"0.3.0", "cross-write-noop", "", 0, true},
	} {
		t.Run(tc.version+"-"+tc.mode, func(t *testing.T) {
			server := pushBindingRESTServer(tc.version, tc.mode)
			defer server.Close()
			state := &attack.TargetState{}
			findings, err := a2a.NewPushBindingExecutor(testRuleCtx()).Execute(t.Context(), server.URL,
				attack.Options{TimeoutSeconds: 3, Principals: pushPrincipals(), TargetState: state})
			if len(findings) != tc.count ||
				errors.Is(err, attack.ErrInconclusive) != tc.inconclusive || err != nil && !tc.inconclusive {
				t.Fatalf("findings=%+v err=%v", findings, err)
			}
			if tc.title != "" && (!strings.Contains(findings[0].Title, tc.title) ||
				findings[0].Confidence != attack.RiskIndicator ||
				!strings.Contains(findings[0].Evidence, "binding: HTTP+JSON/"+tc.version) ||
				!strings.Contains(findings[0].Evidence, "deleted after probe")) {
				t.Fatalf("finding=%+v", findings[0])
			}
			objects := pushConfigObjects(state.Snapshot())
			assertPushFindingsOmitObjectIDs(t, findings, objects)
			want := 2
			switch tc.mode {
			case "anonymous-write", "cross-write", "cross-write-noop":
				want = 4
			case "reverse-cross-write":
				want = 3
			case "same-task-id", "reverse-setup-fails", "reverse-route-unavailable",
				"first-setup-fails-reverse-cross-read":
				want = 1
			}
			if len(objects) != want {
				t.Fatalf("cleanup objects=%+v", objects)
			}
			for _, object := range objects {
				if object.Cleanup != attack.CleanupCompleted && tc.mode != "cross-write-noop" {
					t.Fatalf("cleanup object=%+v", object)
				}
			}
			if strings.Contains(tc.mode, "reverse-cross") && len(findings) > 0 {
				if findings[0].Access == nil || findings[0].Access.Owner != "tenant-b" ||
					findings[0].Access.Caller != "tenant-a" {
					t.Fatalf("reverse access misattributed: %+v", findings[0])
				}
			}
		})
	}
}

func TestPushBindingRESTAnonymousWriteWithOnePrincipal(t *testing.T) {
	server := pushBindingRESTServer("1.0", "anonymous-write")
	defer server.Close()
	findings, err := a2a.NewPushBindingExecutor(testRuleCtx()).Execute(t.Context(), server.URL,
		attack.Options{TimeoutSeconds: 3, Principals: pushPrincipals()[:1]})
	if err != nil || len(findings) != 1 || !strings.Contains(findings[0].Title, "writable without authentication") {
		t.Fatalf("findings=%+v err=%v", findings, err)
	}
}

func TestPushBindingRESTNeedsSecondPrincipalForCrossChecks(t *testing.T) {
	server := pushBindingRESTServer("1.0", "bound")
	defer server.Close()
	findings, err := a2a.NewPushBindingExecutor(testRuleCtx()).Execute(t.Context(), server.URL,
		attack.Options{TimeoutSeconds: 3, Principals: pushPrincipals()[:1]})
	if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("findings=%+v err=%v", findings, err)
	}
}

func TestPushBindingRESTAdvertisedTaskRouteUnavailable(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/agent-card.json" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"supportedInterfaces": []any{
				map[string]string{"url": server.URL + "/agent", "protocolBinding": "HTTP+JSON", "protocolVersion": "1.0"},
			}})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	findings, err := a2a.NewPushBindingExecutor(testRuleCtx()).Execute(t.Context(), server.URL,
		attack.Options{TimeoutSeconds: 3, Principals: pushPrincipals()})
	if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) ||
		!strings.Contains(err.Error(), "advertised HTTP+JSON task routes") {
		t.Fatalf("findings=%+v err=%v", findings, err)
	}
}
