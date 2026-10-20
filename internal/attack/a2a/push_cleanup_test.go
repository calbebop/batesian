package a2a

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
)

func TestPushCleanupJSONRPC(t *testing.T) {
	for _, tc := range []struct {
		name, version, getMethod, deleteMethod string
	}{
		{"v1", "1.0", "GetTaskPushNotificationConfig", "DeleteTaskPushNotificationConfig"},
		{"v0.3", "0.3.0", "tasks/pushNotificationConfig/get", "tasks/pushNotificationConfig/delete"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				call := calls.Add(1)
				var request struct {
					ID     string            `json:"id"`
					Method string            `json:"method"`
					Params map[string]string `json:"params"`
				}
				if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&request) != nil {
					t.Errorf("cleanup request = %+v, method %s", request, r.Method)
				}
				wantMethod := tc.getMethod
				if call == 2 {
					wantMethod = tc.deleteMethod
				}
				if request.Method != wantMethod {
					t.Errorf("method = %q, want %q", request.Method, wantMethod)
				}
				if tc.version == "1.0" {
					if request.Params["taskId"] != "task-1" || request.Params["id"] != "config-1" || r.Header.Get("A2A-Version") != "1.0" {
						t.Errorf("v1 delete params = %+v", request.Params)
					}
				} else if request.Params["id"] != "task-1" || request.Params["pushNotificationConfigId"] != "config-1" || r.Header.Get("A2A-Version") != "" {
					t.Errorf("v0.3 delete params = %+v", request.Params)
				}
				result := map[string]any{}
				if call == 1 {
					result = map[string]any{"id": "config-1", "url": "https://callback.example/probe"}
					if tc.version == "0.3.0" {
						result = map[string]any{"taskId": "task-1", "pushNotificationConfig": map[string]string{"id": "config-1", "url": "https://callback.example/probe"}}
					}
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": result})
			}))
			defer srv.Close()
			response := &attack.Response{Body: []byte(`{"id":"config-1"}`)}
			if tc.version == "0.3.0" {
				response.Body = []byte(`{"pushNotificationConfig":{"id":"config-1"}}`)
			}
			registration := newPushRegistration(srv.URL, "task-1", tc.version, "https://callback.example/probe", response, false)
			state := &attack.TargetState{}
			client := attack.NewHTTPClient(attack.Options{}, attack.NewVars(srv.URL, ""))
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			line := registration.finish(ctx, client, state, false)
			objects := state.Snapshot()
			if calls.Load() != 2 || len(objects) != 1 || objects[0].Cleanup != attack.CleanupCompleted || !strings.Contains(line, "deleted after probe") {
				t.Fatalf("calls=%d objects=%+v line=%q", calls.Load(), objects, line)
			}
		})
	}
}

func TestPushCleanupREST(t *testing.T) {
	for _, tc := range []struct {
		name, version, body string
	}{
		{"v1", "1.0", `{"id":"config-1"}`},
		{"v0.3", "0.3.0", `{"name":"tasks/task-1/pushNotificationConfigs/config-1"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				call := calls.Add(1)
				if !strings.HasSuffix(r.URL.Path, "/tasks/task-1/pushNotificationConfigs/config-1") {
					t.Errorf("cleanup target = %s %s", r.Method, r.URL.Path)
				}
				if call == 1 && r.Method == http.MethodGet {
					if tc.version == "1.0" {
						_, _ = w.Write([]byte(`{"taskId":"task-1","id":"config-1","url":"https://callback.example/probe"}`))
					} else {
						_, _ = w.Write([]byte(`{"name":"tasks/task-1/pushNotificationConfigs/config-1","pushNotificationConfig":{"url":"https://callback.example/probe"}}`))
					}
					return
				}
				if call != 2 || r.Method != http.MethodDelete {
					t.Errorf("unexpected cleanup request = %s %s", r.Method, r.URL.Path)
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			defer srv.Close()
			endpoint := srv.URL + "/api/tasks/task-1/pushNotificationConfigs"
			registration := newPushRegistration(endpoint, "task-1", tc.version, "https://callback.example/probe", &attack.Response{Body: []byte(tc.body)}, true)
			state := &attack.TargetState{}
			client := attack.NewHTTPClient(attack.Options{}, attack.NewVars(srv.URL, ""))
			registration.finish(t.Context(), client, state, false)
			objects := state.Snapshot()
			if calls.Load() != 2 || len(objects) != 1 || objects[0].Cleanup != attack.CleanupCompleted {
				t.Fatalf("calls=%d objects=%+v", calls.Load(), objects)
			}
		})
	}
}

func TestPushCleanupSkipsUnknownOrUnsafeID(t *testing.T) {
	for _, tc := range []struct {
		name, body string
	}{
		{"unknown", `{}`},
		{"unsafe", `{"id":"../other"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
			}))
			defer srv.Close()
			registration := newPushRegistration(srv.URL+"/tasks/task-1/pushNotificationConfigs", "task-1", "1.0", "https://callback.example/probe",
				&attack.Response{Body: []byte(tc.body)}, true)
			state := &attack.TargetState{}
			client := attack.NewHTTPClient(attack.Options{}, attack.NewVars(srv.URL, ""))
			line := registration.finish(t.Context(), client, state, false)
			objects := state.Snapshot()
			if calls.Load() != 0 || len(objects) != 1 || objects[0].Cleanup != attack.CleanupUnavailable || !strings.Contains(line, "verify on target") {
				t.Fatalf("calls=%d objects=%+v line=%q", calls.Load(), objects, line)
			}
		})
	}
}

func TestPushCleanupReportsRefusedDelete(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"taskId":"task-1","id":"config-1","url":"https://callback.example/probe"}`))
			return
		}
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()
	registration := newPushRegistration(srv.URL+"/tasks/task-1/pushNotificationConfigs", "task-1", "1.0", "https://callback.example/probe",
		&attack.Response{Body: []byte(`{"id":"config-1"}`)}, true)
	state := &attack.TargetState{}
	client := attack.NewHTTPClient(attack.Options{}, attack.NewVars(srv.URL, ""))
	line := registration.finish(t.Context(), client, state, false)
	objects := state.Snapshot()
	if len(objects) != 1 || objects[0].Cleanup != attack.CleanupAttempted || !strings.Contains(line, "HTTP 403") {
		t.Fatalf("objects=%+v line=%q", objects, line)
	}
}

func TestPushCleanupSkipsMismatchedReadback(t *testing.T) {
	var deletes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deletes.Add(1)
		}
		_, _ = w.Write([]byte(`{"taskId":"task-1","id":"config-1","url":"https://unrelated.example/"}`))
	}))
	defer srv.Close()
	registration := newPushRegistration(srv.URL+"/tasks/task-1/pushNotificationConfigs", "task-1", "1.0", "https://callback.example/probe",
		&attack.Response{Body: []byte(`{"id":"config-1"}`)}, true)
	state := &attack.TargetState{}
	client := attack.NewHTTPClient(attack.Options{}, attack.NewVars(srv.URL, ""))
	line := registration.finish(t.Context(), client, state, false)
	objects := state.Snapshot()
	if deletes.Load() != 0 || len(objects) != 1 || objects[0].Cleanup != attack.CleanupUnavailable ||
		!strings.Contains(line, "readback did not confirm") {
		t.Fatalf("deletes=%d objects=%+v line=%q", deletes.Load(), objects, line)
	}
}

func TestPushCleanupRetainsExternalOOBRegistration(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
	}))
	defer srv.Close()
	registration := newPushRegistration(srv.URL, "task-1", "1.0", "https://collector.example/probe",
		&attack.Response{Body: []byte(`{"id":"config-1"}`)}, false)
	state := &attack.TargetState{}
	client := attack.NewHTTPClient(attack.Options{}, attack.NewVars(srv.URL, ""))
	line := registration.finish(t.Context(), client, state, true)
	objects := state.Snapshot()
	if calls.Load() != 0 || len(objects) != 1 || objects[0].Cleanup != attack.CleanupNotAttempted ||
		!strings.Contains(line, "remove after manual verification") {
		t.Fatalf("calls=%d objects=%+v line=%q", calls.Load(), objects, line)
	}
}

func TestPushCleanupSkipsUnconfirmedJSONRPCReadback(t *testing.T) {
	var deletes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			ID     string `json:"id"`
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&request)
		if request.Method == "DeleteTaskPushNotificationConfig" {
			deletes.Add(1)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID,
			"result": map[string]string{"id": "config-1", "url": "https://unrelated.example/"}})
	}))
	defer srv.Close()
	registration := newPushRegistration(srv.URL, "task-1", "1.0", "https://callback.example/probe",
		&attack.Response{Body: []byte(`{"result":{"id":"config-1"}}`)}, false)
	state := &attack.TargetState{}
	client := attack.NewHTTPClient(attack.Options{}, attack.NewVars(srv.URL, ""))
	registration.finish(t.Context(), client, state, false)
	objects := state.Snapshot()
	if deletes.Load() != 0 || len(objects) != 1 || objects[0].Cleanup != attack.CleanupUnavailable {
		t.Fatalf("deletes=%d objects=%+v", deletes.Load(), objects)
	}
}
