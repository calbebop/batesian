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
	configs := map[string]string{}
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
			return map[string]any{"name": "tasks/rest-task/pushNotificationConfigs/" + id,
				"pushNotificationConfig": map[string]string{"id": id, "url": callback}}
		}
		switch {
		case r.Method == http.MethodPost && path == "/message:send":
			if who != "tok-a" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			writeJSON(map[string]any{"task": map[string]any{"id": "rest-task", "contextId": "rest-context",
				"status": map[string]string{"state": "TASK_STATE_WORKING"}}})
		case r.Method == http.MethodGet && path == "/tasks/rest-task":
			allowed := who == "tok-a" || who == "tok-b" && mode == "shared" ||
				who == "" && mode == "public-task"
			if !allowed {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			writeJSON(map[string]any{"id": "rest-task", "contextId": "rest-context",
				"status": map[string]string{"state": "TASK_STATE_WORKING"}})
		case r.Method == http.MethodPost && path == "/tasks/rest-task/pushNotificationConfigs":
			allowed := who == "tok-a" || who == "tok-b" && (mode == "cross-write" || mode == "cross-write-noop") ||
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
			if who != "tok-b" || mode != "cross-write-noop" {
				configs[id] = callback
			}
			writeJSON(config(id, callback))
		case r.Method == http.MethodGet && strings.HasPrefix(path, "/tasks/rest-task/pushNotificationConfigs/"):
			id := strings.TrimPrefix(path, "/tasks/rest-task/pushNotificationConfigs/")
			callback, ok := configs[id]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			allowed := who == "tok-a" || who == "tok-b" && (mode == "cross-read" || mode == "cross-read-wrong-url")
			if !allowed {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			if who == "tok-b" && mode == "cross-read-wrong-url" {
				callback = "https://redacted.example/cb"
			}
			writeJSON(config(id, callback))
		case r.Method == http.MethodDelete && strings.HasPrefix(path, "/tasks/rest-task/pushNotificationConfigs/"):
			if who != "tok-a" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			id := strings.TrimPrefix(path, "/tasks/rest-task/pushNotificationConfigs/")
			delete(configs, id)
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
		inconclusive         bool
	}{
		{"1.0", "bound", "", false},
		{"1.0", "anonymous-write", "writable without authentication", false},
		{"1.0", "cross-read", "readable across principals", false},
		{"1.0", "cross-write", "writable across principals", false},
		{"1.0", "cross-write-noop", "", true},
		{"1.0", "cross-read-wrong-url", "", true},
		{"1.0", "shared", "", true},
		{"1.0", "public-task", "", true},
		{"0.3.0", "bound", "", false},
		{"0.3.0", "anonymous-write", "writable without authentication", false},
		{"0.3.0", "cross-read", "readable across principals", false},
		{"0.3.0", "cross-write", "writable across principals", false},
		{"0.3.0", "cross-write-noop", "", true},
	} {
		t.Run(tc.version+"-"+tc.mode, func(t *testing.T) {
			server := pushBindingRESTServer(tc.version, tc.mode)
			defer server.Close()
			state := &attack.TargetState{}
			findings, err := a2a.NewPushBindingExecutor(testRuleCtx()).Execute(t.Context(), server.URL,
				attack.Options{TimeoutSeconds: 3, Principals: pushPrincipals(), TargetState: state})
			if len(findings) != 0 && tc.title == "" || len(findings) != 1 && tc.title != "" ||
				errors.Is(err, attack.ErrInconclusive) != tc.inconclusive || err != nil && !tc.inconclusive {
				t.Fatalf("findings=%+v err=%v", findings, err)
			}
			if tc.title != "" && (!strings.Contains(findings[0].Title, tc.title) ||
				findings[0].Confidence != attack.ConfirmedExploit ||
				!strings.Contains(findings[0].Evidence, "binding: HTTP+JSON/"+tc.version) ||
				!strings.Contains(findings[0].Evidence, "deleted after probe")) {
				t.Fatalf("finding=%+v", findings[0])
			}
			objects := pushConfigObjects(state.Snapshot())
			want := 1
			if tc.mode == "anonymous-write" || tc.mode == "cross-write" || tc.mode == "cross-write-noop" {
				want = 2
			}
			if len(objects) != want {
				t.Fatalf("cleanup objects=%+v", objects)
			}
			for _, object := range objects {
				if object.Cleanup != attack.CleanupCompleted && tc.mode != "cross-write-noop" {
					t.Fatalf("cleanup object=%+v", object)
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
