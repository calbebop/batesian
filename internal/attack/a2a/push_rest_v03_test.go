package a2a_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/attack/a2a"
)

func v03RESTPushServer(t *testing.T, auth, signed, messageOnly bool) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var origin string
	var registrations atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/agent.json", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]interface{}{
			"name": "Legacy REST Agent", "url": origin + "/agent",
			"additionalInterfaces": []map[string]string{{
				"url": origin + "/agent", "transport": "HTTP+JSON", "protocolVersion": "0.3.0",
			}},
		})
	})
	mux.HandleFunc("/agent/v1/message:send", func(w http.ResponseWriter, r *http.Request) {
		body := readBody(r)
		message, _ := body["message"].(map[string]interface{})
		content, _ := message["content"].([]interface{})
		if r.Method != http.MethodPost || r.Header.Get("A2A-Version") != "" ||
			message["role"] != "ROLE_USER" || len(content) != 1 || message["parts"] != nil {
			http.Error(w, "invalid v0.3 send request", http.StatusBadRequest)
			return
		}
		if messageOnly {
			writeJSON(w, map[string]interface{}{"message": map[string]string{"messageId": "reply"}})
			return
		}
		writeJSON(w, map[string]interface{}{"task": map[string]string{"id": "task-legacy", "contextId": "ctx-legacy"}})
	})
	mux.HandleFunc("/agent/v1/tasks/task-legacy/pushNotificationConfigs", func(w http.ResponseWriter, r *http.Request) {
		body := readBody(r)
		config, _ := body["config"].(map[string]interface{})
		push, _ := config["pushNotificationConfig"].(map[string]interface{})
		callbackURL, _ := push["url"].(string)
		token, _ := push["token"].(string)
		name, _ := config["name"].(string)
		configID, _ := body["configId"].(string)
		if r.Method != http.MethodPost || r.Header.Get("A2A-Version") != "" ||
			body["parent"] != "tasks/task-legacy" || configID == "" ||
			name != "tasks/task-legacy/pushNotificationConfigs/"+configID ||
			callbackURL == "" || token == "" || body["url"] != nil {
			http.Error(w, "invalid v0.3 push config", http.StatusBadRequest)
			return
		}
		credential := ""
		if auth {
			info, _ := push["authentication"].(map[string]interface{})
			schemes, _ := info["schemes"].([]interface{})
			credential, _ = info["credentials"].(string)
			if len(schemes) != 1 || schemes[0] != "Bearer" || len(credential) != 64 || credential == token {
				http.Error(w, "invalid v0.3 authentication", http.StatusBadRequest)
				return
			}
		} else if push["authentication"] != nil {
			http.Error(w, "unexpected authentication", http.StatusBadRequest)
			return
		}
		registrations.Add(1)
		payload := []byte(`{"statusUpdate":{"taskId":"task-legacy","status":{"state":"TASK_STATE_COMPLETED"}}}`)
		callback, err := http.NewRequest(http.MethodPost, callbackURL, strings.NewReader(string(payload)))
		if err != nil {
			t.Error(err)
		} else {
			callback.Header.Set("Content-Type", "application/json")
			callback.Header.Set("X-A2A-Notification-Token", token)
			if signed {
				callback.Header.Set("Authorization", "Bearer "+credential)
			}
			resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(callback)
			if err != nil {
				t.Error(err)
			} else {
				_ = resp.Body.Close()
			}
		}
		writeJSON(w, config)
	})
	server := httptest.NewServer(mux)
	origin = server.URL
	return server, &registrations
}

func TestPushSSRF_V03RESTBindingConfirmed(t *testing.T) {
	server, registrations := v03RESTPushServer(t, false, false, false)
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	findings, err := a2a.NewPushSSRFExecutor(testRuleCtx()).Execute(ctx, server.URL, testOpts())
	if err != nil || len(findings) != 1 || findings[0].Confidence != attack.ConfirmedExploit || registrations.Load() != 1 {
		t.Fatalf("v0.3 REST push was not confirmed: findings=%+v registrations=%d err=%v", findings, registrations.Load(), err)
	}
}

func TestPushSSRF_V03RESTMessageIsNotRegistration(t *testing.T) {
	server, registrations := v03RESTPushServer(t, false, false, true)
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	findings, _ := a2a.NewPushSSRFExecutor(testRuleCtx()).Execute(ctx, server.URL, testOpts())
	if len(findings) != 0 || registrations.Load() != 0 {
		t.Fatalf("message response registered a push config: findings=%+v registrations=%d", findings, registrations.Load())
	}
}

func TestCbAuth_V03RESTBinding(t *testing.T) {
	for _, tc := range []struct {
		name   string
		signed bool
		want   int
	}{
		{name: "signed", signed: true, want: 0},
		{name: "unsigned", signed: false, want: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, registrations := v03RESTPushServer(t, true, tc.signed, false)
			defer server.Close()
			findings, err := runCbAuth(t, server.URL, "")
			if err != nil || len(findings) != tc.want || registrations.Load() != 1 {
				t.Fatalf("v0.3 REST auth result: findings=%+v registrations=%d err=%v", findings, registrations.Load(), err)
			}
			if tc.want == 1 && findings[0].Confidence != attack.ConfirmedExploit {
				t.Fatalf("unsigned callback was not confirmed: %+v", findings[0])
			}
		})
	}
}
