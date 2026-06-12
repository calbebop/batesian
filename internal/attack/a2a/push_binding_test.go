package a2a_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/attack/a2a"
)

// pushServer models an A2A server with a push-config control plane.
// mode controls cross-principal binding on set/get:
//   - "unbound": any authenticated principal may set/get any task's push config.
//   - "bound": only the task owner may set/get (secure).
//   - "open": even unauthenticated set succeeds (no-auth control plane).
func pushServer(mode string) *httptest.Server {
	type cfg struct{ url, owner string }
	pushCfg := map[string]cfg{} // taskId -> config
	taskOwner := map[string]string{}

	tenant := func(r *http.Request) string {
		auth := r.Header.Get("Authorization")
		switch auth {
		case "Bearer tok-a":
			return "tenant-a"
		case "Bearer tok-b":
			return "tenant-b"
		default:
			return ""
		}
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]interface{}
		_ = json.Unmarshal(raw, &body)
		method, _ := body["method"].(string)
		reqID := body["id"]
		params, _ := body["params"].(map[string]interface{})
		who := tenant(r)

		result := func(res interface{}) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": reqID, "result": res})
		}
		rpcErr := func(msg string) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": reqID,
				"error": map[string]interface{}{"code": -32600, "message": msg}})
		}

		switch method {
		case "SendMessage", "message/send":
			if who == "" {
				rpcErr("auth required")
				return
			}
			tid := "task-" + who
			taskOwner[tid] = who
			result(map[string]interface{}{"id": tid, "contextId": "ctx-" + who, "status": "working"})
		case "CreateTaskPushNotificationConfig", "tasks/pushNotificationConfig/set":
			tid, _ := params["taskId"].(string)
			url := pushURL(params)
			if mode != "open" && who == "" {
				rpcErr("auth required")
				return
			}
			if mode == "bound" && who != "" && taskOwner[tid] != who {
				rpcErr("not task owner")
				return
			}
			pushCfg[tid] = cfg{url: url, owner: who}
			result(map[string]interface{}{"taskId": tid, "pushNotificationConfig": map[string]string{"url": url}})
		case "GetTaskPushNotificationConfig", "tasks/pushNotificationConfig/get":
			tid, _ := params["taskId"].(string)
			if who == "" {
				rpcErr("auth required")
				return
			}
			if mode == "bound" && taskOwner[tid] != who {
				rpcErr("not task owner")
				return
			}
			c := pushCfg[tid]
			result(map[string]interface{}{"taskId": tid, "pushNotificationConfig": map[string]string{"url": c.url}})
		default:
			rpcErr("method not found")
		}
	}))
}

func pushURL(params map[string]interface{}) string {
	if c, ok := params["pushNotificationConfig"].(map[string]interface{}); ok {
		if u, ok := c["url"].(string); ok {
			return u
		}
	}
	if u, ok := params["pushNotificationUrl"].(string); ok {
		return u
	}
	return ""
}

func pushPrincipals() []attack.Principal {
	return []attack.Principal{
		{Name: "tenant-a", Token: "tok-a", Tenant: "A"},
		{Name: "tenant-b", Token: "tok-b", Tenant: "B"},
	}
}

func runPushBinding(t *testing.T, ts *httptest.Server, principals []attack.Principal) []attack.Finding {
	t.Helper()
	findings, err := a2a.NewPushBindingExecutor(testRuleCtx()).Execute(context.Background(), ts.URL,
		attack.Options{TimeoutSeconds: 5, Principals: principals})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return findings
}

// TestPushBinding_Unbound: B can both set and read A's push config => two
// confirmed findings (write hijack + read leak).
func TestPushBinding_Unbound(t *testing.T) {
	ts := pushServer("unbound")
	defer ts.Close()

	findings := runPushBinding(t, ts, pushPrincipals())
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (write + read), got %d: %+v", len(findings), findings)
	}
	for _, f := range findings {
		if f.Confidence != attack.ConfirmedExploit || f.Severity != "high" {
			t.Errorf("want high/ConfirmedExploit, got %q/%q", f.Severity, f.Confidence)
		}
	}
	titles := findings[0].Title + "|" + findings[1].Title
	if !strings.Contains(titles, "writable") || !strings.Contains(titles, "readable") {
		t.Errorf("expected one write and one read finding, got: %s", titles)
	}
}

// TestPushBinding_Bound: only the owner may set/get => secure, no finding.
func TestPushBinding_Bound(t *testing.T) {
	ts := pushServer("bound")
	defer ts.Close()

	if findings := runPushBinding(t, ts, pushPrincipals()); len(findings) != 0 {
		t.Errorf("expected zero findings against an owner-bound server, got %d: %+v", len(findings), findings)
	}
}

// TestPushBinding_Open: unauthenticated set succeeds => no-auth control plane,
// suppressed (not this rule's territory).
func TestPushBinding_Open(t *testing.T) {
	ts := pushServer("open")
	defer ts.Close()

	if findings := runPushBinding(t, ts, pushPrincipals()); len(findings) != 0 {
		t.Errorf("expected zero findings against an open control plane, got %d: %+v", len(findings), findings)
	}
}

// TestPushBinding_InsufficientPrincipals: <2 principals => clean skip.
func TestPushBinding_InsufficientPrincipals(t *testing.T) {
	ts := pushServer("unbound")
	defer ts.Close()

	if findings := runPushBinding(t, ts, pushPrincipals()[:1]); len(findings) != 0 {
		t.Errorf("expected zero findings with <2 principals, got %d", len(findings))
	}
}
