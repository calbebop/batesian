package a2a_test

import (
	"context"
	"encoding/json"
	"errors"
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
//
// v1Only makes the server refuse the v0.3 slash methods, which is what a
// deployment without the compatibility layer looks like. It matters because the
// v0.3 fallback otherwise masks a wrong v1.0 request shape.
func pushServer(mode string) *httptest.Server { return pushServerVersioned(mode, false) }

func pushServerVersioned(mode string, v1Only bool) *httptest.Server {
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

		if v1Only && strings.Contains(method, "/") {
			rpcErr("method not found")
			return
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
			// Strict per method, as a2a-sdk is: on the v1.0 PascalCase call the
			// params ARE a TaskPushNotificationConfig, so the callback is flat
			// and a nested pushNotificationConfig is an unknown field. v0.3 is
			// the shape that nests it. A harness that accepted either on either
			// method would pass while a real agent answered -32602.
			url := pushURL(params, method)
			if url == "" {
				rpcErr("invalid params")
				return
			}
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

// pushURL reads the callback from the two shapes the protocol defines: nested
// under pushNotificationConfig on v0.3, and flat on params for v1.0, where the
// params ARE a TaskPushNotificationConfig.
//
// It used to also accept a flat pushNotificationUrl, which is the field the rule
// happened to send and which no SDK defines. Accepting it here let the harness
// pass while a2a-sdk answered the same request -32602, so only shapes the
// protocol defines are read now.
func pushURL(params map[string]interface{}, method string) string {
	if method == "CreateTaskPushNotificationConfig" {
		u, _ := params["url"].(string)
		return u
	}
	if c, ok := params["pushNotificationConfig"].(map[string]interface{}); ok {
		u, _ := c["url"].(string)
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

// A deployment that speaks only v1.0 has no v0.3 fallback to hide behind, so the
// rule's v1.0 request shape has to be right. It was not: the params to
// CreateTaskPushNotificationConfig ARE a TaskPushNotificationConfig, and the rule
// sent a nested pushNotificationConfig plus an invented pushNotificationUrl,
// which a2a-sdk rejects with -32602.
func TestPushBinding_UnboundV1Only(t *testing.T) {
	ts := pushServerVersioned("unbound", true)
	defer ts.Close()

	findings := runPushBinding(t, ts, pushPrincipals())
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings against a v1.0-only server, got %d: %+v", len(findings), findings)
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

	// Not via runPushBinding: that helper fatals on any error, and the point here is
	// which error comes back.
	findings, err := a2a.NewPushBindingExecutor(testRuleCtx()).Execute(context.Background(), ts.URL,
		attack.Options{TimeoutSeconds: 5, Principals: pushPrincipals()[:1]})
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("one principal cannot exercise a cross-principal rule; want ErrInconclusive, got %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings, got %d", len(findings))
	}
}
