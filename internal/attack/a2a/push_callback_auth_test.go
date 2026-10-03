package a2a_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/calbebop/batesian/internal/attack"
	a2a "github.com/calbebop/batesian/internal/attack/a2a"
)

func cbAuthRC() attack.RuleContext {
	return attack.RuleContext{
		ID:          "a2a-push-callback-auth-001",
		Name:        "A2A Push Callback Authentication",
		Severity:    "high",
		Remediation: "Present the configured Bearer credential on every push callback.",
	}
}

// cbAuthServer models a v1.0 agent sending a task notification.
type cbAuthServer struct {
	signed          bool
	wrongCredential bool
	tokenOnly       bool
	preflight       bool
	wrongTaskFirst  bool
	callOut         bool
}

func (s *cbAuthServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
			ID     string `json:"id"`
			Params struct {
				TaskID         string `json:"taskId"`
				URL            string `json:"url"`
				Token          string `json:"token"`
				Authentication struct {
					Scheme      string `json:"scheme"`
					Credentials string `json:"credentials"`
				} `json:"authentication"`
			} `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)

		switch req.Method {
		case "SendMessage":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID,
				"result": map[string]interface{}{
					"id":        "task-cbauth-1",
					"contextId": "ctx-cbauth",
					"status":    map[string]interface{}{"state": "TASK_STATE_WORKING"},
				},
			})
		case "CreateTaskPushNotificationConfig":
			url, token := req.Params.URL, req.Params.Token
			if req.Params.Authentication.Scheme != "Bearer" || len(req.Params.Authentication.Credentials) != 64 ||
				strings.Contains(url, req.Params.Authentication.Credentials) || req.Params.Authentication.Credentials == token {
				http.Error(w, "missing independent Bearer credential", http.StatusBadRequest)
				return
			}
			if s.callOut || s.preflight {
				go func() {
					time.Sleep(150 * time.Millisecond)
					client := &http.Client{Timeout: 5 * time.Second}
					if s.preflight {
						if probe, err := http.NewRequest(http.MethodGet, url, nil); err == nil {
							if resp, err := client.Do(probe); err == nil {
								_ = resp.Body.Close()
							}
						}
					}
					if !s.callOut {
						return
					}
					ids := []string{req.Params.TaskID}
					if s.wrongTaskFirst {
						ids = append([]string{"other-task"}, ids...)
					}
					for _, taskID := range ids {
						body := map[string]interface{}{
							"statusUpdate": map[string]interface{}{
								"taskId": taskID,
								"status": map[string]string{"state": "TASK_STATE_COMPLETED"},
							},
						}
						b, _ := json.Marshal(body)
						callback, err := http.NewRequest(http.MethodPost, url, strings.NewReader(string(b)))
						if err != nil {
							return
						}
						callback.Header.Set("Content-Type", "application/json")
						if s.signed {
							callback.Header.Set("Authorization", "Bearer "+req.Params.Authentication.Credentials)
						} else if s.wrongCredential {
							callback.Header.Set("Authorization", "Bearer wrong-credential")
						}
						if s.tokenOnly {
							callback.Header.Set("X-A2A-Notification-Token", token)
						}
						if resp, err := client.Do(callback); err == nil {
							_ = resp.Body.Close()
						}
					}
				}()
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID,
				"result": map[string]interface{}{
					"taskId": req.Params.TaskID, "url": url, "token": token,
					"authentication": map[string]string{
						"scheme": "Bearer", "credentials": req.Params.Authentication.Credentials,
					},
				},
			})
		default:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID,
				"error": map[string]interface{}{"code": -32601, "message": "Method not found"},
			})
		}
	}
}

func runCbAuth(t *testing.T, target string, oobURL string) ([]attack.Finding, error) {
	t.Helper()
	opts := attack.Options{TimeoutSeconds: 10}
	if oobURL != "" {
		opts.OOBListenerURL = oobURL
	}
	return a2a.NewPushCallbackAuthExecutor(cbAuthRC()).Execute(context.Background(), target, opts)
}

// TestCbAuth_UnsignedCallbackFires checks a missing Bearer credential.
func TestCbAuth_UnsignedCallbackFires(t *testing.T) {
	target := httptest.NewServer((&cbAuthServer{signed: false, callOut: true}).handler())
	defer target.Close()

	findings, err := runCbAuth(t, target.URL, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != "high" || f.Confidence != attack.ConfirmedExploit {
		t.Errorf("want high/ConfirmedExploit, got %q/%q", f.Severity, f.Confidence)
	}
	if !strings.Contains(f.Evidence, "configured Bearer credential matched: no") {
		t.Errorf("evidence should record the missing credential, got: %q", f.Evidence)
	}
}

func TestCbAuth_TokenOnlyCallbackFires(t *testing.T) {
	target := httptest.NewServer((&cbAuthServer{tokenOnly: true, callOut: true}).handler())
	defer target.Close()

	findings, err := runCbAuth(t, target.URL, "")
	if err != nil || len(findings) != 1 || findings[0].Severity != "high" {
		t.Fatalf("want high finding when only the optional token is echoed, got findings=%+v err=%v", findings, err)
	}
}

func TestCbAuth_WrongBearerCredentialFires(t *testing.T) {
	target := httptest.NewServer((&cbAuthServer{wrongCredential: true, callOut: true}).handler())
	defer target.Close()

	findings, err := runCbAuth(t, target.URL, "")
	if err != nil || len(findings) != 1 || findings[0].Severity != "high" {
		t.Fatalf("want high finding for incorrect Bearer credential, got findings=%+v err=%v", findings, err)
	}
}

// TestCbAuth_SignedCallbackSilent checks the configured Bearer credential.
func TestCbAuth_SignedCallbackSilent(t *testing.T) {
	target := httptest.NewServer((&cbAuthServer{signed: true, callOut: true}).handler())
	defer target.Close()

	findings, err := runCbAuth(t, target.URL, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings with configured Bearer authentication, got %d: %+v", len(findings), findings)
	}
}

func TestCbAuth_PreflightAndOtherTaskIgnored(t *testing.T) {
	target := httptest.NewServer((&cbAuthServer{signed: true, preflight: true, wrongTaskFirst: true, callOut: true}).handler())
	defer target.Close()

	findings, err := runCbAuth(t, target.URL, "")
	if err != nil || len(findings) != 0 {
		t.Fatalf("preflight or unrelated task raised a finding: %+v (err=%v)", findings, err)
	}
}

func TestCbAuth_PreflightOnlyNotTested(t *testing.T) {
	target := httptest.NewServer((&cbAuthServer{preflight: true}).handler())
	defer target.Close()

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	findings, err := a2a.NewPushCallbackAuthExecutor(cbAuthRC()).Execute(ctx, target.URL, testOpts())
	if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("preflight-only callback must be inconclusive, got findings=%+v err=%v", findings, err)
	}
}

func sendAuthenticatedNotification(t *testing.T, callbackURL, taskID, credential string) {
	t.Helper()
	body, err := json.Marshal(map[string]interface{}{
		"statusUpdate": map[string]interface{}{
			"taskId": taskID, "status": map[string]string{"state": "TASK_STATE_COMPLETED"},
		},
	})
	if err != nil {
		t.Error(err)
		return
	}
	request, err := http.NewRequest(http.MethodPost, callbackURL, strings.NewReader(string(body)))
	if err != nil {
		t.Error(err)
		return
	}
	request.Header.Set("Authorization", "Bearer "+credential)
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(request)
	if err != nil {
		t.Error(err)
		return
	}
	_ = resp.Body.Close()
}

func TestCbAuth_V03AuthenticationShape(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request := readBody(r)
		method, _ := request["method"].(string)
		params, _ := request["params"].(map[string]interface{})
		switch method {
		case "message/send":
			config, _ := params["configuration"].(map[string]interface{})
			push, _ := config["pushNotificationConfig"].(map[string]interface{})
			auth, _ := push["authentication"].(map[string]interface{})
			schemes, _ := auth["schemes"].([]interface{})
			if len(schemes) != 1 || schemes[0] != "Bearer" || auth["credentials"] == "" {
				t.Errorf("v0.3 inline config missing Bearer authentication: %+v", push)
			}
			writeJSON(w, map[string]interface{}{"jsonrpc": "2.0", "id": request["id"], "result": map[string]string{"id": "task-v03-auth", "contextId": "ctx"}})
		case "tasks/pushNotificationConfig/set":
			push, _ := params["pushNotificationConfig"].(map[string]interface{})
			auth, _ := push["authentication"].(map[string]interface{})
			schemes, _ := auth["schemes"].([]interface{})
			credential, _ := auth["credentials"].(string)
			if len(schemes) != 1 || schemes[0] != "Bearer" || credential == "" {
				t.Errorf("v0.3 set config missing Bearer authentication: %+v", push)
			}
			callbackURL, _ := push["url"].(string)
			sendAuthenticatedNotification(t, callbackURL, "task-v03-auth", credential)
			writeJSON(w, map[string]interface{}{"jsonrpc": "2.0", "id": request["id"], "result": push})
		default:
			rpcErr(w, request["id"], -32601, "method not found")
		}
	}))
	defer target.Close()

	findings, err := runCbAuth(t, target.URL, "")
	if err != nil || len(findings) != 0 {
		t.Fatalf("configured v0.3 callback was not accepted: findings=%+v err=%v", findings, err)
	}
}

func TestCbAuth_RESTAuthenticationShape(t *testing.T) {
	var origin string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/agent-card.json", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]interface{}{
			"name": "REST Agent", "supportedInterfaces": []map[string]string{{
				"url": origin + "/v1", "protocolBinding": "HTTP+JSON", "protocolVersion": "1.0",
			}},
		})
	})
	mux.HandleFunc("/v1/message:send", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]interface{}{"task": map[string]string{"id": "task-rest-auth", "contextId": "ctx"}})
	})
	mux.HandleFunc("/v1/tasks/task-rest-auth/pushNotificationConfigs", func(w http.ResponseWriter, r *http.Request) {
		config := readBody(r)
		auth, _ := config["authentication"].(map[string]interface{})
		credential, _ := auth["credentials"].(string)
		if auth["scheme"] != "Bearer" || credential == "" {
			t.Errorf("REST config missing Bearer authentication: %+v", config)
		}
		callbackURL, _ := config["url"].(string)
		sendAuthenticatedNotification(t, callbackURL, "task-rest-auth", credential)
		writeJSON(w, config)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	origin = server.URL

	findings, err := runCbAuth(t, server.URL, "")
	if err != nil || len(findings) != 0 {
		t.Fatalf("configured REST callback was not accepted: findings=%+v err=%v", findings, err)
	}
}

// TestCbAuth_NoCallbackNotTested: registration accepted, webhook never hit.
// The oracle never ran, so the rule reports not tested rather than clean.
func TestCbAuth_NoCallbackNotTested(t *testing.T) {
	target := httptest.NewServer((&cbAuthServer{callOut: false}).handler())
	defer target.Close()

	findings, err := runCbAuth(t, target.URL, "")
	if err == nil {
		t.Fatalf("expected an inconclusive error when no callback arrived")
	}
	if !strings.Contains(err.Error(), "no task notification") {
		t.Errorf("expected the reason to name the missing notification, got: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings alongside the inconclusive result, got %d", len(findings))
	}
}

// TestCbAuth_ExternalOOBInfoIndicator: with an external collector the scanner
// cannot see the callback itself; an info indicator names the token to check
// for instead.
func TestCbAuth_ExternalOOBInfoIndicator(t *testing.T) {
	target := httptest.NewServer((&cbAuthServer{signed: false, callOut: true}).handler())
	defer target.Close()

	findings, err := runCbAuth(t, target.URL, "http://127.0.0.1:9/oob")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Severity != "info" || findings[0].Confidence != attack.RiskIndicator {
		t.Errorf("want info/RiskIndicator for external OOB, got %q/%q",
			findings[0].Severity, findings[0].Confidence)
	}
	if !strings.Contains(findings[0].Evidence, "expected bearer credential:") {
		t.Errorf("external OOB evidence omitted the credential to verify: %q", findings[0].Evidence)
	}
}

// TestCbAuth_AnonymousRefusedNotTested: a secured agent refuses the task
// creation from an anonymous scan. Not tested, naming the refusal - never a
// clean claim about callbacks nobody agreed to send.
func TestCbAuth_AnonymousRefusedNotTested(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string      `json:"method"`
			ID     json.Number `json:"id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Method == "SendMessage" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID,
				"error": map[string]interface{}{"code": -32000, "message": "unauthorized"},
			})
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer ts.Close()

	findings, err := a2a.NewPushCallbackAuthExecutor(cbAuthRC()).
		Execute(context.Background(), ts.URL, attack.Options{TimeoutSeconds: 5})
	if err == nil {
		t.Fatalf("expected an inconclusive error against a secured anonymous scan")
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings alongside the inconclusive result, got %d", len(findings))
	}
}
