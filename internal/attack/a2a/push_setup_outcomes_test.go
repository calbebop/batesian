package a2a_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/calbebop/batesian/internal/attack"
	a2aattack "github.com/calbebop/batesian/internal/attack/a2a"
)

func pushSetupServer(mode string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/.well-known/agent-card.json" {
			binding, path := "JSONRPC", "/"
			if mode == "rest-config-gateway" || mode == "rest-config-invalid" {
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
			writeJSON(w, map[string]any{"task": map[string]any{"id": "task-setup", "status": map[string]string{"state": "TASK_STATE_SUBMITTED"}}})
			return
		}
		if r.URL.Path == "/api/tasks/task-setup/pushNotificationConfigs" {
			if mode == "rest-config-invalid" {
				writeJSON(w, map[string]any{})
				return
			}
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
			if mode == "v1-send-gateway-v03-confirm" {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			if mode == "v1-message-v03-confirm" {
				writeJSON(w, map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]any{
					"kind": "message", "messageId": "reply", "role": "agent", "parts": []any{map[string]string{"text": "pong"}},
				}})
				return
			}
			if mode == "v03-set-gateway" || mode == "v03-inline-callback" || mode == "rest-config-gateway" ||
				mode == "rest-config-invalid" ||
				mode == "v03-send-wrong-id" || mode == "v03-set-wrong-id" || strings.HasPrefix(mode, "v03-invalid-") {
				rpcErr(w, id, -32601, "Method not found")
				return
			}
			if mode == "v1-send-wrong-id-v03-confirm" {
				id = "other-request"
			}
			writeJSON(w, map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]any{"id": "task-setup", "status": map[string]string{"state": "TASK_STATE_SUBMITTED"}}})
		case "CreateTaskPushNotificationConfig":
			if strings.HasPrefix(mode, "v1-config-invalid-") {
				params, _ := req["params"].(map[string]any)
				var result any
				switch mode {
				case "v1-config-invalid-empty":
					result = map[string]any{}
				case "v1-config-invalid-task":
					result = map[string]any{"taskId": "other", "url": params["url"]}
				case "v1-config-invalid-url":
					result = map[string]any{"taskId": "task-setup", "url": "https://other.example/cb"}
				}
				writeJSON(w, map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
				return
			}
			if mode == "v1-config-unsupported" || mode == "v1-unsupported-v03-confirm" {
				rpcErr(w, id, -32003, "Push notifications not supported")
				return
			}
			if mode == "v1-config-auth" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if mode == "v1-send-wrong-id-v03-confirm" || mode == "v1-config-wrong-id-v03-confirm" {
				if mode == "v1-config-wrong-id-v03-confirm" {
					id = "other-request"
				}
				params, _ := req["params"].(map[string]any)
				writeJSON(w, map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]any{
					"taskId": "task-setup", "url": params["url"],
				}})
				return
			}
			w.WriteHeader(http.StatusBadGateway)
		case "message/send":
			if mode == "v03-set-gateway" || mode == "v03-inline-callback" ||
				mode == "v1-send-gateway-v03-confirm" || mode == "v1-config-gateway-v03-confirm" ||
				strings.HasPrefix(mode, "v1-config-invalid-") || strings.HasPrefix(mode, "v03-invalid-") ||
				mode == "v1-message-v03-confirm" || mode == "v1-unsupported-v03-confirm" ||
				mode == "v1-send-wrong-id-v03-confirm" || mode == "v1-config-wrong-id-v03-confirm" ||
				mode == "v03-send-wrong-id" || mode == "v03-set-wrong-id" {
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
				if mode == "v03-send-wrong-id" {
					id = "other-request"
				}
				writeJSON(w, map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]any{"id": "task-setup", "status": map[string]string{"state": "submitted"}}})
				return
			}
			rpcErr(w, id, -32601, "Method not found")
		case "tasks/pushNotificationConfig/set":
			if strings.HasPrefix(mode, "v03-invalid-") {
				params, _ := req["params"].(map[string]any)
				var result any
				switch mode {
				case "v03-invalid-empty":
					result = map[string]any{}
				case "v03-invalid-task":
					result = map[string]any{"taskId": "other", "pushNotificationConfig": params["pushNotificationConfig"]}
				case "v03-invalid-url":
					result = map[string]any{"taskId": "task-setup", "pushNotificationConfig": map[string]string{"url": "https://other.example/cb"}}
				}
				writeJSON(w, map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
				return
			}
			if mode == "v1-send-gateway-v03-confirm" || mode == "v1-config-gateway-v03-confirm" ||
				strings.HasPrefix(mode, "v1-config-invalid-") ||
				mode == "v1-message-v03-confirm" || mode == "v1-unsupported-v03-confirm" ||
				mode == "v1-send-wrong-id-v03-confirm" || mode == "v1-config-wrong-id-v03-confirm" ||
				mode == "v03-send-wrong-id" || mode == "v03-set-wrong-id" {
				if mode == "v03-set-wrong-id" {
					id = "other-request"
				}
				params, _ := req["params"].(map[string]any)
				writeJSON(w, map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]any{
					"taskId": "task-setup", "pushNotificationConfig": params["pushNotificationConfig"],
				}})
				return
			}
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

func TestPushSetup_MalformedTaskDoesNotRegister(t *testing.T) {
	for _, wire := range []string{"v1", "v0.3", "rest"} {
		t.Run(wire, func(t *testing.T) {
			var registrations atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet && r.URL.Path == "/.well-known/agent-card.json" {
					binding, path := "JSONRPC", "/"
					if wire == "rest" {
						binding, path = "HTTP+JSON", "/api"
					}
					writeJSON(w, map[string]any{"name": "Push task test agent", "supportedInterfaces": []map[string]string{{
						"url": "http://" + r.Host + path, "protocolBinding": binding, "protocolVersion": "1.0",
					}}})
					return
				}
				if r.URL.Path == "/api/message:send" && wire == "rest" {
					writeJSON(w, map[string]any{"task": map[string]string{"id": "task-1"}})
					return
				}
				if r.URL.Path == "/api/tasks/task-1/pushNotificationConfigs" {
					registrations.Add(1)
					writeJSON(w, map[string]string{"taskId": "task-1", "url": "http://oob.batesian.invalid/cb"})
					return
				}
				if r.URL.Path != "/" || r.Method != http.MethodPost {
					http.NotFound(w, r)
					return
				}
				req := readBody(r)
				method, _ := req["method"].(string)
				switch method {
				case "SendMessage":
					if wire == "v1" {
						writeJSON(w, map[string]any{"jsonrpc": "2.0", "id": req["id"], "result": map[string]string{"id": "task-1"}})
						return
					}
				case "message/send":
					if wire == "v0.3" {
						writeJSON(w, map[string]any{"jsonrpc": "2.0", "id": req["id"], "result": map[string]string{"id": "task-1"}})
						return
					}
				case "CreateTaskPushNotificationConfig", "tasks/pushNotificationConfig/set":
					registrations.Add(1)
					writeJSON(w, map[string]any{"jsonrpc": "2.0", "id": req["id"], "result": map[string]string{"taskId": "task-1"}})
					return
				}
				rpcErr(w, req["id"], -32601, "Method not found")
			}))
			defer srv.Close()
			for _, rule := range pushSetupRules() {
				t.Run(rule.name, func(t *testing.T) {
					findings, err := rule.exec.Execute(t.Context(), srv.URL, attack.Options{
						TimeoutSeconds: 5, OOBListenerURL: "http://oob.batesian.invalid",
					})
					if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) || registrations.Load() != 0 {
						t.Fatalf("malformed task triggered push registration: findings=%+v registrations=%d err=%v", findings, registrations.Load(), err)
					}
				})
			}
		})
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
			confidence := attack.ConfirmedExploit
			if rule.name == "SSRF" {
				confidence = attack.RiskIndicator
			}
			if len(findings) != 1 || !errors.Is(err, attack.ErrInconclusive) || findings[0].Confidence != confidence {
				t.Fatalf("observed callback must retain the finding and failed set attempt: findings=%+v err=%v", findings, err)
			}
		})
	}
}

func TestPushSetup_FallbackRetainsUnjudgedAttempts(t *testing.T) {
	for _, mode := range []string{
		"v1-send-gateway-v03-confirm", "v1-config-gateway-v03-confirm",
	} {
		t.Run(mode, func(t *testing.T) {
			srv := pushSetupServer(mode)
			defer srv.Close()
			for _, rule := range pushSetupRules() {
				t.Run(rule.name, func(t *testing.T) {
					findings, err := rule.exec.Execute(t.Context(), srv.URL, attack.Options{
						TimeoutSeconds: 5, OOBListenerURL: "http://oob.batesian.invalid",
					})
					if len(findings) != 1 || findings[0].Confidence != attack.RiskIndicator ||
						!errors.Is(err, attack.ErrInconclusive) {
						t.Fatalf("fallback must retain the indicator and incomplete setup: findings=%+v err=%v", findings, err)
					}
				})
			}
		})
	}
}

func TestPushSetup_InvalidV1RegistrationFallsBack(t *testing.T) {
	for _, mode := range []string{
		"v1-config-invalid-null", "v1-config-invalid-empty", "v1-config-invalid-task", "v1-config-invalid-url",
	} {
		t.Run(mode, func(t *testing.T) {
			srv := pushSetupServer(mode)
			defer srv.Close()
			for _, rule := range pushSetupRules() {
				t.Run(rule.name, func(t *testing.T) {
					findings, err := rule.exec.Execute(t.Context(), srv.URL, attack.Options{
						TimeoutSeconds: 5, OOBListenerURL: "http://oob.batesian.invalid",
					})
					if len(findings) != 1 || findings[0].Confidence != attack.RiskIndicator ||
						!errors.Is(err, attack.ErrInconclusive) || !strings.Contains(err.Error(), "did not confirm the task and callback URL") {
						t.Fatalf("fallback must retain the unconfirmed v1 registration: findings=%+v err=%v", findings, err)
					}
				})
			}
		})
	}
}

func TestPushSetup_InvalidLegacyRegistrationIsIncomplete(t *testing.T) {
	for _, mode := range []string{"v03-invalid-null", "v03-invalid-empty", "v03-invalid-task", "v03-invalid-url"} {
		t.Run(mode, func(t *testing.T) {
			srv := pushSetupServer(mode)
			defer srv.Close()
			for _, rule := range pushSetupRules() {
				t.Run(rule.name, func(t *testing.T) {
					findings, err := rule.exec.Execute(t.Context(), srv.URL, attack.Options{
						TimeoutSeconds: 5, OOBListenerURL: "http://oob.batesian.invalid",
					})
					if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) ||
						!strings.Contains(err.Error(), "did not confirm the task and callback URL") {
						t.Fatalf("invalid legacy registration must be incomplete: findings=%+v err=%v", findings, err)
					}
				})
			}
		})
	}
}

func TestPushSetup_InvalidRESTRegistrationIsIncomplete(t *testing.T) {
	srv := pushSetupServer("rest-config-invalid")
	defer srv.Close()
	for _, rule := range pushSetupRules() {
		t.Run(rule.name, func(t *testing.T) {
			findings, err := rule.exec.Execute(t.Context(), srv.URL, attack.Options{
				TimeoutSeconds: 5, OOBListenerURL: "http://oob.batesian.invalid",
			})
			if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) ||
				!strings.Contains(err.Error(), "did not confirm the task and callback URL") {
				t.Fatalf("empty REST config must be incomplete: findings=%+v err=%v", findings, err)
			}
		})
	}
}

func TestPushSetup_WrongReplyIDRetainsFallback(t *testing.T) {
	for _, mode := range []string{"v1-send-wrong-id-v03-confirm", "v1-config-wrong-id-v03-confirm"} {
		t.Run(mode, func(t *testing.T) {
			srv := pushSetupServer(mode)
			defer srv.Close()
			for _, rule := range pushSetupRules() {
				t.Run(rule.name, func(t *testing.T) {
					findings, err := rule.exec.Execute(t.Context(), srv.URL, attack.Options{
						TimeoutSeconds: 5, OOBListenerURL: "http://oob.batesian.invalid",
					})
					if len(findings) != 1 || findings[0].Confidence != attack.RiskIndicator ||
						!errors.Is(err, attack.ErrInconclusive) || !strings.Contains(err.Error(), "request ID") {
						t.Fatalf("fallback must retain the indicator and unmatched reply: findings=%+v err=%v", findings, err)
					}
				})
			}
		})
	}
}

func TestPushSetup_WrongLegacyReplyIDIsIncomplete(t *testing.T) {
	for _, mode := range []string{"v03-send-wrong-id", "v03-set-wrong-id"} {
		t.Run(mode, func(t *testing.T) {
			srv := pushSetupServer(mode)
			defer srv.Close()
			for _, rule := range pushSetupRules() {
				t.Run(rule.name, func(t *testing.T) {
					findings, err := rule.exec.Execute(t.Context(), srv.URL, attack.Options{
						TimeoutSeconds: 5, OOBListenerURL: "http://oob.batesian.invalid",
					})
					if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) ||
						!strings.Contains(err.Error(), "request ID") {
						t.Fatalf("unmatched legacy reply must not confirm push setup: findings=%+v err=%v", findings, err)
					}
				})
			}
		})
	}
}

func TestPushSetup_UnsupportedFallbackStaysConclusive(t *testing.T) {
	for _, mode := range []string{"v1-unsupported-v03-confirm", "v1-message-v03-confirm"} {
		t.Run(mode, func(t *testing.T) {
			srv := pushSetupServer(mode)
			defer srv.Close()
			for _, rule := range pushSetupRules() {
				t.Run(rule.name, func(t *testing.T) {
					findings, err := rule.exec.Execute(t.Context(), srv.URL, attack.Options{
						TimeoutSeconds: 5, OOBListenerURL: "http://oob.batesian.invalid",
					})
					if len(findings) != 1 || err != nil || findings[0].Confidence != attack.RiskIndicator {
						t.Fatalf("unsupported v1 push setup must not make v0.3 incomplete: findings=%+v err=%v", findings, err)
					}
				})
			}
		})
	}
}

func TestPushSetup_RESTFallbackRetainsUnjudgedAttempts(t *testing.T) {
	for _, failedStep := range []string{"send", "config"} {
		t.Run(failedStep, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/.well-known/agent-card.json":
					writeJSON(w, map[string]any{
						"name": "REST fallback agent",
						"supportedInterfaces": []map[string]string{
							{"url": "http://" + r.Host + "/old", "protocolBinding": "HTTP+JSON", "protocolVersion": "1.0"},
							{"url": "http://" + r.Host + "/api", "protocolBinding": "HTTP+JSON", "protocolVersion": "1.0"},
						},
					})
				case "/old/message:send":
					if failedStep == "send" {
						w.WriteHeader(http.StatusBadGateway)
						return
					}
					writeJSON(w, map[string]any{"task": map[string]any{"id": "task-setup", "status": map[string]string{"state": "TASK_STATE_SUBMITTED"}}})
				case "/old/tasks/task-setup/pushNotificationConfigs":
					w.WriteHeader(http.StatusBadGateway)
				case "/api/message:send":
					writeJSON(w, map[string]any{"task": map[string]any{"id": "task-setup", "status": map[string]string{"state": "TASK_STATE_SUBMITTED"}}})
				case "/api/tasks/task-setup/pushNotificationConfigs":
					config := readBody(r)
					writeJSON(w, map[string]any{"taskId": "task-setup", "url": config["url"]})
				case "/":
					req := readBody(r)
					rpcErr(w, req["id"], -32601, "Method not found")
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()
			for _, rule := range pushSetupRules() {
				t.Run(rule.name, func(t *testing.T) {
					findings, err := rule.exec.Execute(t.Context(), srv.URL, attack.Options{
						TimeoutSeconds: 5, OOBListenerURL: "http://oob.batesian.invalid",
					})
					if len(findings) != 1 || findings[0].Confidence != attack.RiskIndicator ||
						!errors.Is(err, attack.ErrInconclusive) {
						t.Fatalf("REST fallback must retain the indicator and failed setup: findings=%+v err=%v", findings, err)
					}
				})
			}
		})
	}
}
