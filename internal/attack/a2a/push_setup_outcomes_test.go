package a2a_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/calbebop/batesian/internal/attack"
	a2aattack "github.com/calbebop/batesian/internal/attack/a2a"
)

func pushSetupServer(mode string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/.well-known/agent-card.json" {
			binding, path := "JSONRPC", "/"
			if mode == "rest-config-gateway" {
				binding, path = "HTTP+JSON", "/api"
			}
			writeJSON(w, map[string]any{
				"name": "Push setup test agent",
				"supportedInterfaces": []map[string]string{{
					"url": "http://" + r.Host + path, "protocolBinding": binding, "protocolVersion": "1.0",
				}},
			})
			return
		}
		if r.URL.Path == "/api/message:send" {
			writeJSON(w, map[string]any{"task": map[string]string{"id": "task-setup"}})
			return
		}
		if r.URL.Path == "/api/tasks/task-setup/pushNotificationConfigs" {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		if r.URL.Path != "/" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		req := readBody(r)
		method, _ := req["method"].(string)
		id := req["id"]
		switch method {
		case "GetTask", "tasks/get":
			rpcErr(w, id, -32001, "Task not found")
		case "SendMessage":
			if mode == "task-drop" {
				conn, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					_ = conn.Close()
				}
				return
			}
			if mode == "v03-set-gateway" || mode == "v03-inline-callback" || mode == "rest-config-gateway" {
				rpcErr(w, id, -32601, "Method not found")
				return
			}
			writeJSON(w, map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]string{"id": "task-setup"}})
		case "CreateTaskPushNotificationConfig":
			if mode == "v1-config-unsupported" {
				rpcErr(w, id, -32003, "Push notifications not supported")
				return
			}
			if mode == "v1-config-auth" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusBadGateway)
		case "message/send":
			if mode == "v03-set-gateway" || mode == "v03-inline-callback" {
				if mode == "v03-inline-callback" {
					params, _ := req["params"].(map[string]any)
					config, _ := params["configuration"].(map[string]any)
					push, _ := config["pushNotificationConfig"].(map[string]any)
					callbackURL, _ := push["url"].(string)
					token, _ := push["token"].(string)
					if callback, err := http.NewRequest(http.MethodPost, callbackURL, strings.NewReader(`{"statusUpdate":{"taskId":"task-setup","status":{"state":"TASK_STATE_COMPLETED"}}}`)); err == nil {
						callback.Header.Set("X-A2A-Notification-Token", token)
						if resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(callback); err == nil {
							_ = resp.Body.Close()
						}
					}
				}
				writeJSON(w, map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]string{"id": "task-setup"}})
				return
			}
			rpcErr(w, id, -32601, "Method not found")
		case "tasks/pushNotificationConfig/set":
			w.WriteHeader(http.StatusBadGateway)
		default:
			rpcErr(w, id, -32601, "Method not found")
		}
	}))
}

func pushSetupRules() []struct {
	name string
	exec attack.Executor
} {
	return []struct {
		name string
		exec attack.Executor
	}{
		{"SSRF", a2aattack.NewPushSSRFExecutor(testRuleCtx())},
		{"callback auth", a2aattack.NewPushCallbackAuthExecutor(cbAuthRC())},
	}
}

func TestPushSetup_UnjudgedAttemptsAreIncomplete(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want string
	}{
		{"task-drop", "creating a task"},
		{"v1-config-auth", "CreateTaskPushNotificationConfig"},
		{"v1-config-gateway", "CreateTaskPushNotificationConfig"},
		{"v03-set-gateway", "registration was not confirmed"},
		{"rest-config-gateway", "pushNotificationConfigs"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			srv := pushSetupServer(tc.mode)
			defer srv.Close()
			for _, rule := range pushSetupRules() {
				t.Run(rule.name, func(t *testing.T) {
					findings, err := rule.exec.Execute(t.Context(), srv.URL, attack.Options{
						TimeoutSeconds: 5, OOBListenerURL: "http://oob.batesian.invalid",
					})
					if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) || !strings.Contains(err.Error(), tc.want) {
						t.Fatalf("unjudged push setup must be incomplete: findings=%+v err=%v", findings, err)
					}
				})
			}
		})
	}
}

func TestPushSetup_ExplicitlyUnsupportedIsNotApplicable(t *testing.T) {
	srv := pushSetupServer("v1-config-unsupported")
	defer srv.Close()
	for _, rule := range pushSetupRules() {
		t.Run(rule.name, func(t *testing.T) {
			findings, err := rule.exec.Execute(t.Context(), srv.URL, attack.Options{
				TimeoutSeconds: 5, OOBListenerURL: "http://oob.batesian.invalid",
			})
			if len(findings) != 0 || err != nil {
				t.Fatalf("unsupported push should be not applicable: findings=%+v err=%v", findings, err)
			}
		})
	}
}

func TestPushSetup_InlineCallbackConfirmsFinding(t *testing.T) {
	srv := pushSetupServer("v03-inline-callback")
	defer srv.Close()
	for _, rule := range pushSetupRules() {
		t.Run(rule.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			findings, err := rule.exec.Execute(ctx, srv.URL, attack.Options{TimeoutSeconds: 5})
			if len(findings) != 1 || err != nil || findings[0].Confidence != attack.ConfirmedExploit {
				t.Fatalf("observed inline callback must retain the finding: findings=%+v err=%v", findings, err)
			}
		})
	}
}
