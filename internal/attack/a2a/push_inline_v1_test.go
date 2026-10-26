package a2a_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/attack/a2a"
)

func inlineV1PushServer(t *testing.T, sendCallback, sendCredential bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		req := readBody(r)
		method, _ := req["method"].(string)
		if method != "SendMessage" {
			rpcErr(w, req["id"], -32601, "Method not found")
			return
		}
		params, _ := req["params"].(map[string]interface{})
		configuration, _ := params["configuration"].(map[string]interface{})
		push, hasInline := configuration["taskPushNotificationConfig"].(map[string]interface{})
		if hasInline && sendCallback {
			callbackURL, _ := push["url"].(string)
			token, _ := push["token"].(string)
			if callbackURL == "" || token == "" {
				t.Errorf("inline push configuration missing URL or token: %+v", push)
			} else {
				body, _ := json.Marshal(map[string]interface{}{"statusUpdate": map[string]string{"taskId": "inline-task-1"}})
				cbReq, err := http.NewRequest(http.MethodPost, callbackURL, bytes.NewReader(body))
				if err == nil {
					cbReq.Header.Set("X-A2A-Notification-Token", token)
					if sendCredential {
						auth, _ := push["authentication"].(map[string]interface{})
						credential, _ := auth["credentials"].(string)
						cbReq.Header.Set("Authorization", "Bearer "+credential)
					}
					client := &http.Client{Timeout: 3 * time.Second}
					if resp, err := client.Do(cbReq); err == nil {
						_ = resp.Body.Close()
					}
				}
			}
		}
		writeJSON(w, map[string]interface{}{"jsonrpc": "2.0", "id": req["id"],
			"result": map[string]interface{}{"task": map[string]interface{}{
				"id": "inline-task-1", "contextId": "inline-context-1",
				"status": map[string]string{"state": "TASK_STATE_COMPLETED"}}}})
	}))
}

func TestPushSSRF_V1InlineFastTask(t *testing.T) {
	srv := inlineV1PushServer(t, true, false)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	findings, err := a2a.NewPushSSRFExecutor(testRuleCtx()).Execute(ctx, srv.URL, testOpts())
	if err != nil || len(findings) != 1 || findings[0].Confidence != attack.RiskIndicator {
		t.Fatalf("inline push finding = %+v, error = %v", findings, err)
	}
	if !strings.Contains(findings[0].Evidence, "SendMessage-inline") {
		t.Fatalf("inline binding missing from evidence: %s", findings[0].Evidence)
	}
}

func TestPushCallbackAuth_V1InlineFastTask(t *testing.T) {
	for _, tc := range []struct {
		name           string
		sendCredential bool
		wantFinding    bool
	}{
		{"missing credential", false, true},
		{"credential present", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := inlineV1PushServer(t, true, tc.sendCredential)
			defer srv.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			findings, err := a2a.NewPushCallbackAuthExecutor(testRuleCtx()).Execute(ctx, srv.URL, testOpts())
			if err != nil || (len(findings) == 1) != tc.wantFinding {
				t.Fatalf("inline push findings = %+v, error = %v", findings, err)
			}
		})
	}
}

func TestPushSSRF_V1InlineNoDelivery(t *testing.T) {
	srv := inlineV1PushServer(t, false, false)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	findings, err := a2a.NewPushSSRFExecutor(testRuleCtx()).Execute(ctx, srv.URL, testOpts())
	if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) ||
		!strings.Contains(err.Error(), "no push callback observed") {
		t.Fatalf("unobserved inline push findings = %+v, error = %v", findings, err)
	}
}
