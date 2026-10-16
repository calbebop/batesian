package a2a

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
)

func TestPushRegistrationReplyAccepted(t *testing.T) {
	const taskID = "task-1"
	const callbackURL = "https://oob.example/cb"
	for _, tc := range []struct {
		name   string
		method string
		body   string
		want   bool
	}{
		{"v1", "CreateTaskPushNotificationConfig", `{"jsonrpc":"2.0","id":"probe","result":{"taskId":"task-1","url":"https://oob.example/cb"}}`, true},
		{"v0.3", "tasks/pushNotificationConfig/set", `{"jsonrpc":"2.0","id":"probe","result":{"taskId":"task-1","pushNotificationConfig":{"url":"https://oob.example/cb"}}}`, true},
		{"null", "CreateTaskPushNotificationConfig", `{"jsonrpc":"2.0","id":"probe","result":null}`, false},
		{"empty", "CreateTaskPushNotificationConfig", `{"jsonrpc":"2.0","id":"probe","result":{}}`, false},
		{"generic", "CreateTaskPushNotificationConfig", `{"jsonrpc":"2.0","id":"probe","result":{"ok":true}}`, false},
		{"wrong task", "CreateTaskPushNotificationConfig", `{"jsonrpc":"2.0","id":"probe","result":{"taskId":"other","url":"https://oob.example/cb"}}`, false},
		{"wrong URL", "CreateTaskPushNotificationConfig", `{"jsonrpc":"2.0","id":"probe","result":{"taskId":"task-1","url":"https://other.example/cb"}}`, false},
		{"wrong shape", "tasks/pushNotificationConfig/set", `{"jsonrpc":"2.0","id":"probe","result":{"taskId":"task-1","url":"https://oob.example/cb"}}`, false},
		{"wrong ID", "CreateTaskPushNotificationConfig", `{"jsonrpc":"2.0","id":"other","result":{"taskId":"task-1","url":"https://oob.example/cb"}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := &attack.Response{StatusCode: 200, Body: []byte(tc.body)}
			if got := pushRegistrationReplyAccepted(resp, "probe", tc.method, taskID, callbackURL); got != tc.want {
				t.Fatalf("accepted = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestRESTPushRegistrationReplyAccepted(t *testing.T) {
	const taskID = "task-1"
	const callbackURL = "https://oob.example/cb"
	for _, tc := range []struct {
		name    string
		version string
		body    string
		want    bool
	}{
		{"v1", "1.0", `{"taskId":"task-1","url":"https://oob.example/cb"}`, true},
		{"v1 no task ID", "1.0", `{"url":"https://oob.example/cb"}`, true},
		{"v0.3", "0.3.0", `{"name":"tasks/task-1/pushNotificationConfigs/config-1","pushNotificationConfig":{"url":"https://oob.example/cb"}}`, true},
		{"empty", "1.0", `{}`, false},
		{"wrong task", "1.0", `{"taskId":"other","url":"https://oob.example/cb"}`, false},
		{"wrong URL", "1.0", `{"taskId":"task-1","url":"https://other.example/cb"}`, false},
		{"v0.3 wrong task", "0.3.0", `{"name":"tasks/other/pushNotificationConfigs/config-1","pushNotificationConfig":{"url":"https://oob.example/cb"}}`, false},
		{"v0.3 missing config ID", "0.3.0", `{"name":"tasks/task-1/pushNotificationConfigs/","pushNotificationConfig":{"url":"https://oob.example/cb"}}`, false},
		{"v0.3 wrong URL", "0.3.0", `{"name":"tasks/task-1/pushNotificationConfigs/config-1","pushNotificationConfig":{"url":"https://other.example/cb"}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := &attack.Response{StatusCode: 200, Body: []byte(tc.body)}
			if got := restPushRegistrationReplyAccepted(resp, taskID, callbackURL, tc.version); got != tc.want {
				t.Fatalf("accepted = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestPushBindingSetNeedsMatchingConfig(t *testing.T) {
	const callbackURL = "https://oob.example/cb"
	for _, tc := range []struct {
		name      string
		v1Result  any
		v03Result any
		accepted  bool
	}{
		{"empty replies", map[string]any{}, map[string]any{}, false},
		{"null replies", nil, nil, false},
		{"v0.3 fallback", map[string]any{"taskId": "task-1", "url": "https://other.example/cb"},
			map[string]any{"taskId": "task-1", "pushNotificationConfig": map[string]string{"id": "config-1", "url": callbackURL}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var request struct {
					ID     string `json:"id"`
					Method string `json:"method"`
				}
				if json.NewDecoder(r.Body).Decode(&request) != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				result := tc.v1Result
				if request.Method == "tasks/pushNotificationConfig/set" {
					result = tc.v03Result
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": result})
			}))
			defer server.Close()

			set := NewPushBindingExecutor(attack.RuleContext{}).setPush(t.Context(), replayClient(server.URL),
				server.URL, nil, "setting a push config", "task-1", callbackURL, "token", "config-1", "probe")
			if set.accepted != tc.accepted || set.judged != tc.accepted {
				t.Fatalf("set = %+v, want accepted %t", set, tc.accepted)
			}
			if tc.accepted && (set.v1 || !set.partial) {
				t.Fatalf("fallback must retain the unjudged v1 reply: %+v", set)
			}
		})
	}
}
