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

// pushServer models owner-bound, open, and unbound push-config access.
func pushServer(mode string) *httptest.Server { return pushServerVersioned(mode, false) }

func pushServerVersioned(mode string, v1Only bool) *httptest.Server {
	type cfg struct{ url, owner, id string }
	pushCfg := map[string]map[string]cfg{}
	taskOwner := map[string]string{}
	var lastSetID, ownerGetID interface{}
	var lastSetResult, ownerGetResult map[string]interface{}

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
		if (mode == "legacy-only" || mode == "legacy-version-strict") && !strings.Contains(method, "/") {
			rpcErr("method not found")
			return
		}
		if mode == "legacy-version-strict" && strings.Contains(method, "/") && r.Header.Get("A2A-Version") != "" {
			rpcErr("version not supported")
			return
		}
		if v1Only && (method == "CreateTaskPushNotificationConfig" || method == "GetTaskPushNotificationConfig") &&
			r.Header.Get("A2A-Version") != "1.0" {
			rpcErr("version not supported")
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
			if mode == "push-gated" {
				// Push access can be gated separately from task creation.
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": reqID,
					"error": map[string]interface{}{"code": -32600, "message": "push:write scope required"}})
				return
			}
			// Match each version's request shape.
			url := pushURL(params, method)
			if url == "" {
				rpcErr("invalid params")
				return
			}
			if mode != "open" && mode != "noop-anon" && who == "" {
				rpcErr("auth required")
				return
			}
			if mode == "bound" && who != "" && taskOwner[tid] != who {
				rpcErr("not task owner")
				return
			}
			configID, _ := params["id"].(string)
			if method != "CreateTaskPushNotificationConfig" {
				config, _ := params["pushNotificationConfig"].(map[string]interface{})
				configID, _ = config["id"].(string)
			}
			if pushCfg[tid] == nil {
				pushCfg[tid] = map[string]cfg{}
			}
			noop := ((mode == "noop-write" || mode == "noop-write-blind") && who == "tenant-b") ||
				(mode == "noop-anon" && who == "") ||
				(mode == "noop-owner" && who == "tenant-a")
			if !noop {
				pushCfg[tid][configID] = cfg{url: url, owner: who, id: configID}
			}
			if method == "CreateTaskPushNotificationConfig" {
				lastSetResult = map[string]interface{}{"taskId": tid, "id": configID, "url": url}
			} else {
				lastSetResult = map[string]interface{}{"taskId": tid, "pushNotificationConfig": map[string]string{"id": configID, "url": url}}
			}
			lastSetID = reqID
			result(lastSetResult)
		case "GetTaskPushNotificationConfig", "tasks/pushNotificationConfig/get":
			if mode == "replay-set" {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": lastSetID, "result": lastSetResult})
				return
			}
			if mode == "replay-owner-read" && who == "tenant-b" {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": ownerGetID, "result": ownerGetResult})
				return
			}
			tid, _ := params["id"].(string)
			configID := ""
			if method == "GetTaskPushNotificationConfig" {
				tid, _ = params["taskId"].(string)
				configID, _ = params["id"].(string)
			}
			if who == "" {
				rpcErr("auth required")
				return
			}
			if mode == "noop-write-blind" && who == "tenant-b" {
				rpcErr("read denied")
				return
			}
			if mode == "bound" && taskOwner[tid] != who {
				rpcErr("not task owner")
				return
			}
			if method == "GetTaskPushNotificationConfig" {
				c, ok := pushCfg[tid][configID]
				if !ok {
					rpcErr("config not found")
					return
				}
				if mode == "read-echo" && who == "tenant-b" && c.owner == "tenant-a" {
					result(map[string]interface{}{"taskId": tid, "id": c.id, "url": "redacted", "metadata": c.url})
					return
				}
				getResult := map[string]interface{}{"taskId": tid, "id": c.id, "url": c.url}
				if who == "tenant-a" {
					ownerGetID, ownerGetResult = reqID, getResult
				}
				result(getResult)
			} else {
				configID, _ = params["pushNotificationConfigId"].(string)
				if configID != "" {
					c, ok := pushCfg[tid][configID]
					if !ok {
						rpcErr("config not found")
						return
					}
					result(map[string]interface{}{"taskId": tid, "pushNotificationConfig": map[string]string{"id": c.id, "url": c.url}})
					return
				}
				for _, c := range pushCfg[tid] {
					result(map[string]interface{}{"taskId": tid, "pushNotificationConfig": map[string]string{"id": c.id, "url": c.url}})
					return
				}
				rpcErr("config not found")
			}
		default:
			rpcErr("method not found")
		}
	}))
}

// pushURL reads the callback from the v1 or v0.3 request shape.
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

// TestPushBinding_Unbound expects read and write findings.
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

// The v1-only server catches invalid v1 request shapes.
func TestPushBinding_UnboundV1Only(t *testing.T) {
	ts := pushServerVersioned("unbound", true)
	defer ts.Close()

	findings := runPushBinding(t, ts, pushPrincipals())
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings against a v1.0-only server, got %d: %+v", len(findings), findings)
	}
}

func TestPushBinding_LegacyOnly(t *testing.T) {
	ts := pushServer("legacy-only")
	defer ts.Close()

	if findings := runPushBinding(t, ts, pushPrincipals()); len(findings) != 2 {
		t.Fatalf("expected read and write findings on v0.3, got %+v", findings)
	}
}

func TestPushBinding_LegacyVersionStrict(t *testing.T) {
	for _, conflictingHeader := range []bool{false, true} {
		name := "default"
		if conflictingHeader {
			name = "principal version header"
		}
		t.Run(name, func(t *testing.T) {
			ts := pushServer("legacy-version-strict")
			defer ts.Close()

			principals := pushPrincipals()
			if conflictingHeader {
				for i := range principals {
					principals[i].Headers = map[string]string{"a2a-version": "1.0"}
				}
			}
			if findings := runPushBinding(t, ts, principals); len(findings) != 2 {
				t.Fatalf("expected read and write findings on a version-strict v0.3 server, got %+v", findings)
			}
		})
	}
}

func TestPushBinding_AcknowledgedWriteWithoutMutation(t *testing.T) {
	ts := pushServer("noop-write")
	defer ts.Close()

	findings := runPushBinding(t, ts, pushPrincipals())
	if len(findings) != 1 || !strings.Contains(findings[0].Title, "readable") {
		t.Fatalf("expected only a read finding, got %+v", findings)
	}
}

func TestPushBinding_AcknowledgedWriteWithoutReadback(t *testing.T) {
	ts := pushServer("noop-write-blind")
	defer ts.Close()

	findings, err := a2a.NewPushBindingExecutor(testRuleCtx()).Execute(context.Background(), ts.URL,
		attack.Options{TimeoutSeconds: 5, Principals: pushPrincipals()})
	if !errors.Is(err, attack.ErrInconclusive) || len(findings) != 0 {
		t.Fatalf("unverified write must be inconclusive, got findings=%+v err=%v", findings, err)
	}
}

func TestPushBinding_AcknowledgedAnonymousNoOp(t *testing.T) {
	ts := pushServer("noop-anon")
	defer ts.Close()

	if findings := runPushBinding(t, ts, pushPrincipals()); len(findings) != 2 {
		t.Fatalf("anonymous no-op must not suppress findings, got %+v", findings)
	}
}

func TestPushBinding_AcknowledgedOwnerNoOp(t *testing.T) {
	ts := pushServer("noop-owner")
	defer ts.Close()

	_, err := a2a.NewPushBindingExecutor(testRuleCtx()).Execute(context.Background(), ts.URL,
		attack.Options{TimeoutSeconds: 5, Principals: pushPrincipals()})
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("owner no-op must be inconclusive, got %v", err)
	}
}

func TestPushBinding_MetadataEchoIsNotReadEvidence(t *testing.T) {
	ts := pushServer("read-echo")
	defer ts.Close()

	findings := runPushBinding(t, ts, pushPrincipals())
	if len(findings) != 1 || !strings.Contains(findings[0].Title, "writable") {
		t.Fatalf("expected only a write finding, got %+v", findings)
	}
}

func TestPushBinding_ReplayedSetIsNotReadback(t *testing.T) {
	ts := pushServer("replay-set")
	defer ts.Close()

	_, err := a2a.NewPushBindingExecutor(testRuleCtx()).Execute(context.Background(), ts.URL,
		attack.Options{TimeoutSeconds: 5, Principals: pushPrincipals()})
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("replayed set response must not confirm owner readback, got %v", err)
	}
}

func TestPushBinding_ReplayedOwnerReadIsNotCrossRead(t *testing.T) {
	ts := pushServer("replay-owner-read")
	defer ts.Close()

	findings := runPushBinding(t, ts, pushPrincipals())
	if len(findings) != 1 || !strings.Contains(findings[0].Title, "writable") {
		t.Fatalf("replayed owner read must not prove cross-principal read, got %+v", findings)
	}
}

// TestPushBinding_Bound permits only the owner.
func TestPushBinding_Bound(t *testing.T) {
	ts := pushServer("bound")
	defer ts.Close()

	if findings := runPushBinding(t, ts, pushPrincipals()); len(findings) != 0 {
		t.Errorf("expected zero findings against an owner-bound server, got %d: %+v", len(findings), findings)
	}
}

func TestPushBinding_Open(t *testing.T) {
	ts := pushServer("open")
	defer ts.Close()

	findings := runPushBinding(t, ts, pushPrincipals())
	if len(findings) != 1 || !strings.Contains(findings[0].Title, "without authentication") {
		t.Fatalf("expected one anonymous-write finding, got %+v", findings)
	}
	if findings[0].Severity != "high" || findings[0].Confidence != attack.ConfirmedExploit {
		t.Errorf("want high/ConfirmedExploit, got %q/%q", findings[0].Severity, findings[0].Confidence)
	}
}

func TestPushBinding_OpenWithOnePrincipal(t *testing.T) {
	ts := pushServer("open")
	defer ts.Close()

	findings := runPushBinding(t, ts, pushPrincipals()[:1])
	if len(findings) != 1 || !strings.Contains(findings[0].Title, "without authentication") {
		t.Fatalf("expected anonymous-write finding with one principal, got %+v", findings)
	}
}

func TestPushBinding_OpenWithDuplicateSecondPrincipal(t *testing.T) {
	ts := pushServer("open")
	defer ts.Close()

	principals := pushPrincipals()
	principals[1].Token = principals[0].Token
	findings := runPushBinding(t, ts, principals)
	if len(findings) != 1 || !strings.Contains(findings[0].Title, "without authentication") {
		t.Fatalf("expected anonymous-write finding despite duplicate second credential, got %+v", findings)
	}
}

func TestPushBinding_EmptyOwnerToken(t *testing.T) {
	findings, err := a2a.NewPushBindingExecutor(testRuleCtx()).Execute(context.Background(), "http://target.invalid",
		attack.Options{TimeoutSeconds: 5, Principals: []attack.Principal{{Name: "owner"}}})
	if !errors.Is(err, attack.ErrInconclusive) || len(findings) != 0 {
		t.Fatalf("unauthenticated owner cannot establish a protected task, got findings=%+v err=%v", findings, err)
	}
}

// TestPushBinding_InsufficientPrincipals requires two identities.
func TestPushBinding_InsufficientPrincipals(t *testing.T) {
	ts := pushServer("unbound")
	defer ts.Close()

	// Inspect the error directly.
	findings, err := a2a.NewPushBindingExecutor(testRuleCtx()).Execute(context.Background(), ts.URL,
		attack.Options{TimeoutSeconds: 5, Principals: pushPrincipals()[:1]})
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("one principal cannot exercise a cross-principal rule; want ErrInconclusive, got %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings, got %d", len(findings))
	}
}

// TestPushBinding_OwnerSetPushRefused is inconclusive when setup is gated.
func TestPushBinding_OwnerSetPushRefused(t *testing.T) {
	ts := pushServer("push-gated")
	defer ts.Close()

	_, err := a2a.NewPushBindingExecutor(testRuleCtx()).Execute(context.Background(), ts.URL,
		attack.Options{TimeoutSeconds: 5, Principals: pushPrincipals()})
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("an owner setPush refused for authorization must be not-tested, not clean; "+
			"want ErrInconclusive, got %v", err)
	}
}
