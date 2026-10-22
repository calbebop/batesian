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
	if mode == "reused-with-existing" {
		pushCfg["task-tenant-a"] = map[string]cfg{
			"existing": {url: "https://user.example/cb", owner: "tenant-a", id: "existing"},
		}
		taskOwner["task-tenant-a"] = "tenant-a"
	}
	var lastSetID, ownerGetID interface{}
	var lastSetResult, ownerGetResult map[string]interface{}

	tenant := func(r *http.Request) string {
		switch r.Header.Get("X-API-Key") {
		case "key-a":
			return "tenant-a"
		case "key-b":
			return "tenant-b"
		}
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
			code := -32600
			if msg == "method not found" {
				code = -32601
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": reqID,
				"error": map[string]interface{}{"code": code, "message": msg}})
		}

		if v1Only && strings.Contains(method, "/") {
			rpcErr("method not found")
			return
		}
		if (mode == "legacy-only" || mode == "legacy-version-strict" || mode == "lifecycle-legacy-open") && !strings.Contains(method, "/") {
			rpcErr("method not found")
			return
		}
		if mode == "legacy-version-strict" && strings.Contains(method, "/") && r.Header.Get("A2A-Version") != "" {
			rpcErr("version not supported")
			return
		}
		if v1Only && (method == "CreateTaskPushNotificationConfig" || method == "GetTaskPushNotificationConfig" ||
			method == "DeleteTaskPushNotificationConfig") &&
			r.Header.Get("A2A-Version") != "1.0" {
			rpcErr("version not supported")
			return
		}

		switch method {
		case "GetTask", "tasks/get":
			tid, _ := params["id"].(string)
			if taskOwner[tid] == "" {
				rpcErr("task not found")
				return
			}
			if who != taskOwner[tid] && mode != "lifecycle-shared" {
				rpcErr("not task owner")
				return
			}
			result(map[string]interface{}{"id": tid, "contextId": "ctx-tenant-a", "status": map[string]string{"state": "working"}})
		case "SendMessage", "message/send":
			if method == "SendMessage" && (mode == "v1-create-unavailable" || mode == "v1-create-unavailable-bound") {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			if who == "" {
				rpcErr("auth required")
				return
			}
			tid := "task-" + who
			taskOwner[tid] = who
			result(map[string]interface{}{"id": tid, "contextId": "ctx-" + who, "status": map[string]string{"state": "working"}})
		case "CreateTaskPushNotificationConfig", "tasks/pushNotificationConfig/set":
			if method == "CreateTaskPushNotificationConfig" &&
				((mode == "v1-owner-set-unavailable" && who == "tenant-a") ||
					(mode == "v1-attacker-set-unavailable" && who == "tenant-b") ||
					(mode == "v1-anon-set-unavailable-open" && who == "")) {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			tid, _ := params["taskId"].(string)
			if (mode == "write-anon-timeout" && who == "") ||
				(mode == "write-cross-timeout" && who == "tenant-b") {
				w.WriteHeader(http.StatusRequestTimeout)
				rpcErr("not task owner")
				return
			}
			if method == "CreateTaskPushNotificationConfig" &&
				((mode == "write-anon-mixed" && who == "") || (mode == "write-cross-mixed" && who == "tenant-b")) {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			if (mode == "write-anon-unavailable" && who == "") ||
				(mode == "write-cross-unavailable" && who == "tenant-b") {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			if (mode == "write-anon-malformed" && who == "") ||
				(mode == "write-cross-malformed" && who == "tenant-b") {
				_, _ = w.Write([]byte("not json"))
				return
			}
			if mode == "write-anon-generic-error" && who == "" {
				rpcErr("invalid request")
				return
			}
			if mode == "write-cross-wrong-id" && who == "tenant-b" {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": "other-request",
					"error": map[string]interface{}{"code": -32600, "message": "not task owner"}})
				return
			}
			if (mode == "write-anon-http-denied" && who == "") ||
				(mode == "write-cross-http-denied" && who == "tenant-b") {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
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
			if mode != "open" && mode != "v1-anon-set-unavailable-open" &&
				mode != "open-anon-readback-unavailable" && mode != "noop-anon" && who == "" {
				rpcErr("auth required")
				return
			}
			if (mode == "bound" || mode == "v1-create-unavailable-bound" || strings.HasPrefix(mode, "cross-read-") || strings.HasPrefix(mode, "write-")) && who != "" && taskOwner[tid] != who {
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
			if method == "GetTaskPushNotificationConfig" && mode == "open-anon-readback-unavailable" && who == "tenant-a" {
				configID, _ := params["id"].(string)
				if strings.HasPrefix(configID, "open-") {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
			}
			if who == "tenant-b" {
				switch mode {
				case "cross-read-unavailable":
					http.Error(w, "unavailable", http.StatusServiceUnavailable)
					return
				case "cross-read-malformed":
					_, _ = w.Write([]byte("not json"))
					return
				case "cross-read-empty-result":
					configID, _ := params["id"].(string)
					result(map[string]interface{}{"taskId": "task-tenant-a", "id": configID})
					return
				case "cross-read-generic-error":
					rpcErr("invalid request")
					return
				case "cross-read-wrong-id":
					_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": "other-request",
						"result": map[string]interface{}{"url": "unrelated"}})
					return
				case "cross-read-http-denied":
					http.Error(w, "forbidden", http.StatusForbidden)
					return
				case "cross-read-rpc-denied":
					rpcErr("not authorized")
					return
				}
			}
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
			if (mode == "bound" || mode == "v1-create-unavailable-bound" || strings.HasPrefix(mode, "cross-read-") || strings.HasPrefix(mode, "write-")) && taskOwner[tid] != who {
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
		case "ListTaskPushNotificationConfigs", "tasks/pushNotificationConfig/list":
			tid, _ := params["id"].(string)
			if method == "ListTaskPushNotificationConfigs" {
				tid, _ = params["taskId"].(string)
			}
			if who != taskOwner[tid] && mode != "lifecycle-list-open" && mode != "lifecycle-open" &&
				mode != "lifecycle-legacy-open" && mode != "lifecycle-list-wrong-id" &&
				mode != "lifecycle-list-malformed" && mode != "lifecycle-paged-open" {
				rpcErr("not task owner")
				return
			}
			if mode == "lifecycle-paged-open" && params["pageToken"] == nil {
				result(map[string]interface{}{"configs": []interface{}{}, "nextPageToken": "second"})
				return
			}
			if mode == "lifecycle-list-loop" && who == "tenant-a" {
				result(map[string]interface{}{"configs": []interface{}{}, "nextPageToken": "loop"})
				return
			}
			if mode == "lifecycle-list-wrong-id" && who == "tenant-b" {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": "other-request", "result": map[string]interface{}{"configs": []interface{}{}}})
				return
			}
			if mode == "lifecycle-list-malformed" && who == "tenant-b" {
				result(map[string]interface{}{"configs": []interface{}{}, "nextPageToken": nil})
				return
			}
			configs := make([]interface{}, 0, len(pushCfg[tid]))
			for _, c := range pushCfg[tid] {
				if method == "ListTaskPushNotificationConfigs" {
					configs = append(configs, map[string]string{"taskId": tid, "id": c.id, "url": c.url})
				} else {
					configs = append(configs, map[string]interface{}{"taskId": tid, "pushNotificationConfig": map[string]string{"id": c.id, "url": c.url}})
				}
			}
			if method == "ListTaskPushNotificationConfigs" {
				result(map[string]interface{}{"configs": configs})
			} else {
				result(configs)
			}
		case "DeleteTaskPushNotificationConfig", "tasks/pushNotificationConfig/delete":
			if mode == "delete-denied" {
				rpcErr("not task owner")
				return
			}
			if who != "tenant-a" && mode != "lifecycle-delete-open" && mode != "lifecycle-open" &&
				mode != "lifecycle-legacy-open" && mode != "lifecycle-delete-noop" && mode != "lifecycle-delete-wrong-id" {
				rpcErr("not task owner")
				return
			}
			tid, configID := "", ""
			if method == "DeleteTaskPushNotificationConfig" {
				tid, _ = params["taskId"].(string)
				configID, _ = params["id"].(string)
			} else {
				tid, _ = params["id"].(string)
				configID, _ = params["pushNotificationConfigId"].(string)
			}
			if _, ok := pushCfg[tid][configID]; !ok {
				rpcErr("config not found")
				return
			}
			if mode != "lifecycle-delete-noop" || who != "tenant-b" {
				delete(pushCfg[tid], configID)
			}
			if mode == "lifecycle-delete-wrong-id" && who == "tenant-b" {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": "other-request", "result": map[string]interface{}{}})
				return
			}
			if method == "tasks/pushNotificationConfig/delete" {
				result(nil)
				return
			}
			result(map[string]interface{}{})
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

func pushConfigObjects(objects []attack.TargetObject) []attack.TargetObject {
	var configs []attack.TargetObject
	for _, object := range objects {
		if object.Kind == "a2a_push_config" {
			configs = append(configs, object)
		}
	}
	return configs
}

func TestPushBindingCleansVerifiedMarkers(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want int
	}{
		{"unbound", 2},
		{"legacy-only", 2},
		{"open", 2},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			ts := pushServer(tc.mode)
			defer ts.Close()
			state := &attack.TargetState{}
			findings, err := a2a.NewPushBindingExecutor(testRuleCtx()).Execute(t.Context(), ts.URL,
				attack.Options{TimeoutSeconds: 5, Principals: pushPrincipals(), TargetState: state})
			if err != nil || len(findings) == 0 {
				t.Fatalf("findings=%+v err=%v", findings, err)
			}
			objects := pushConfigObjects(state.Snapshot())
			if len(objects) != tc.want {
				t.Fatalf("target objects = %+v", objects)
			}
			for _, object := range objects {
				if object.Kind != "a2a_push_config" || object.Cleanup != attack.CleanupCompleted {
					t.Fatalf("target objects = %+v", objects)
				}
			}
			if !strings.Contains(findings[0].Evidence, "deleted after probe") {
				t.Fatalf("cleanup omitted from finding evidence: %q", findings[0].Evidence)
			}
		})
	}
}

func TestPushBindingPreservesExistingConfigOnReusedTask(t *testing.T) {
	ts := pushServer("reused-with-existing")
	defer ts.Close()
	bb := attack.NewBlackboard()
	bb.Publish(attack.Artifact{Kind: attack.ArtifactTaskID, Value: "task-tenant-a", Principal: "tenant-a"})
	state := &attack.TargetState{}
	findings, err := a2a.NewPushBindingExecutor(testRuleCtx()).ExecuteChained(t.Context(), ts.URL,
		attack.Options{TimeoutSeconds: 5, Principals: pushPrincipals(), TargetState: state}, bb)
	if err != nil || len(findings) != 2 {
		t.Fatalf("findings=%+v err=%v", findings, err)
	}
	objects := pushConfigObjects(state.Snapshot())
	if len(objects) != 2 || objects[0].Cleanup != attack.CleanupCompleted || objects[1].Cleanup != attack.CleanupCompleted {
		t.Fatalf("target objects = %+v", objects)
	}
	client := attack.NewHTTPClient(attack.Options{Token: "tok-a"}, attack.NewVars(ts.URL, ""))
	resp, err := client.POST(t.Context(), ts.URL, map[string]string{"A2A-Version": "1.0"}, map[string]interface{}{
		"jsonrpc": "2.0", "id": "existing-read", "method": "GetTaskPushNotificationConfig",
		"params": map[string]string{"taskId": "task-tenant-a", "id": "existing"},
	})
	if err != nil || resp == nil || !strings.Contains(string(resp.Body), "https://user.example/cb") {
		t.Fatalf("pre-existing config was changed: response=%v err=%v", resp, err)
	}
}

func TestPushBindingSkipsUnconfirmedMarkerCleanup(t *testing.T) {
	ts := pushServer("noop-write")
	defer ts.Close()
	state := &attack.TargetState{}
	_, err := a2a.NewPushBindingExecutor(testRuleCtx()).Execute(t.Context(), ts.URL,
		attack.Options{TimeoutSeconds: 5, Principals: pushPrincipals(), TargetState: state})
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected inconclusive write, got %v", err)
	}
	objects := pushConfigObjects(state.Snapshot())
	if len(objects) != 2 || !strings.HasPrefix(objects[0].ID, "attacker-") ||
		objects[0].Cleanup != attack.CleanupUnavailable || objects[1].Cleanup != attack.CleanupCompleted {
		t.Fatalf("target objects = %+v", objects)
	}
}

func TestPushBindingReportsRefusedCleanup(t *testing.T) {
	ts := pushServer("delete-denied")
	defer ts.Close()
	state := &attack.TargetState{}
	findings, err := a2a.NewPushBindingExecutor(testRuleCtx()).Execute(t.Context(), ts.URL,
		attack.Options{TimeoutSeconds: 5, Principals: pushPrincipals(), TargetState: state})
	if err != nil || len(findings) != 2 {
		t.Fatalf("findings=%+v err=%v", findings, err)
	}
	objects := pushConfigObjects(state.Snapshot())
	if len(objects) != 2 || objects[0].Cleanup != attack.CleanupAttempted || objects[1].Cleanup != attack.CleanupAttempted ||
		!strings.Contains(objects[0].CleanupDetail, "JSON-RPC error -32600") ||
		!strings.Contains(findings[0].Evidence, "verify on target") {
		t.Fatalf("refused cleanup = %+v, evidence = %q", objects, findings[0].Evidence)
	}
}

func TestPushBinding_PartialFallbackOutcomes(t *testing.T) {
	for _, tc := range []struct {
		mode     string
		findings int
	}{
		{"v1-create-unavailable", 2},
		{"v1-create-unavailable-bound", 0},
		{"v1-owner-set-unavailable", 2},
		{"v1-attacker-set-unavailable", 2},
		{"v1-anon-set-unavailable-open", 1},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			ts := pushServer(tc.mode)
			defer ts.Close()
			findings, err := a2a.NewPushBindingExecutor(testRuleCtx()).Execute(context.Background(), ts.URL,
				attack.Options{TimeoutSeconds: 5, Principals: pushPrincipals()})
			if len(findings) != tc.findings || !errors.Is(err, attack.ErrInconclusive) {
				t.Fatalf("want %d findings and incomplete fallback, got findings=%+v err=%v", tc.findings, findings, err)
			}
		})
	}
}

func TestPushBinding_UnjudgedAnonymousReadbackRetainsCrossFindings(t *testing.T) {
	ts := pushServer("open-anon-readback-unavailable")
	defer ts.Close()
	findings, err := a2a.NewPushBindingExecutor(testRuleCtx()).Execute(context.Background(), ts.URL,
		attack.Options{TimeoutSeconds: 5, Principals: pushPrincipals()})
	if len(findings) != 2 || !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("want cross-principal findings and incomplete anonymous readback, got findings=%+v err=%v", findings, err)
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
			state := &attack.TargetState{}
			findings, err := a2a.NewPushBindingExecutor(testRuleCtx()).Execute(t.Context(), ts.URL,
				attack.Options{TimeoutSeconds: 5, Principals: principals, TargetState: state})
			if err != nil || len(findings) != 2 {
				t.Fatalf("expected read and write findings on a version-strict v0.3 server, got %+v, err=%v", findings, err)
			}
			configs := pushConfigObjects(state.Snapshot())
			if len(configs) != 2 || configs[0].Cleanup != attack.CleanupCompleted || configs[1].Cleanup != attack.CleanupCompleted {
				t.Fatalf("version-strict cleanup = %+v", configs)
			}
		})
	}
}

func TestPushBinding_AcknowledgedWriteWithoutMutation(t *testing.T) {
	ts := pushServer("noop-write")
	defer ts.Close()

	findings, err := a2a.NewPushBindingExecutor(testRuleCtx()).Execute(context.Background(), ts.URL,
		attack.Options{TimeoutSeconds: 5, Principals: pushPrincipals()})
	if len(findings) != 1 || !strings.Contains(findings[0].Title, "readable") || !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected a read finding and incomplete write check, got findings=%+v err=%v", findings, err)
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

	findings, err := a2a.NewPushBindingExecutor(testRuleCtx()).Execute(context.Background(), ts.URL,
		attack.Options{TimeoutSeconds: 5, Principals: pushPrincipals()})
	if len(findings) != 1 || !strings.Contains(findings[0].Title, "writable") || !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("replayed owner read must leave cross-principal read incomplete: findings=%+v err=%v", findings, err)
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

func TestPushBinding_CrossReadOutcomes(t *testing.T) {
	for _, tc := range []struct {
		mode         string
		inconclusive bool
	}{
		{"cross-read-unavailable", true},
		{"cross-read-malformed", true},
		{"cross-read-empty-result", true},
		{"cross-read-generic-error", true},
		{"cross-read-wrong-id", true},
		{"cross-read-http-denied", false},
		{"cross-read-rpc-denied", false},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			ts := pushServer(tc.mode)
			defer ts.Close()
			findings, err := a2a.NewPushBindingExecutor(testRuleCtx()).Execute(context.Background(), ts.URL,
				attack.Options{TimeoutSeconds: 5, Principals: pushPrincipals()})
			if len(findings) != 0 || errors.Is(err, attack.ErrInconclusive) != tc.inconclusive ||
				(!tc.inconclusive && err != nil) {
				t.Fatalf("findings=%+v err=%v, want inconclusive=%t", findings, err, tc.inconclusive)
			}
		})
	}
}

func TestPushBinding_WriteOutcomes(t *testing.T) {
	for _, tc := range []struct {
		mode         string
		inconclusive bool
	}{
		{"write-anon-unavailable", true},
		{"write-anon-timeout", true},
		{"write-anon-malformed", true},
		{"write-anon-generic-error", true},
		{"write-anon-mixed", true},
		{"write-cross-unavailable", true},
		{"write-cross-timeout", true},
		{"write-cross-malformed", true},
		{"write-cross-wrong-id", true},
		{"write-cross-mixed", true},
		{"write-anon-http-denied", false},
		{"write-cross-http-denied", false},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			ts := pushServer(tc.mode)
			defer ts.Close()
			findings, err := a2a.NewPushBindingExecutor(testRuleCtx()).Execute(context.Background(), ts.URL,
				attack.Options{TimeoutSeconds: 5, Principals: pushPrincipals()})
			if len(findings) != 0 || errors.Is(err, attack.ErrInconclusive) != tc.inconclusive ||
				(!tc.inconclusive && err != nil) {
				t.Fatalf("findings=%+v err=%v, want inconclusive=%t", findings, err, tc.inconclusive)
			}
		})
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

func TestPushBinding_HeaderOnlyOwner(t *testing.T) {
	ts := pushServer("unbound")
	defer ts.Close()

	principals := []attack.Principal{
		{Name: "tenant-a", Headers: map[string]string{"X-API-Key": "key-a"}},
		{Name: "tenant-b", Headers: map[string]string{"X-API-Key": "key-b"}},
	}
	state := &attack.TargetState{}
	findings, err := a2a.NewPushBindingExecutor(testRuleCtx()).Execute(t.Context(), ts.URL,
		attack.Options{TimeoutSeconds: 5, Principals: principals, TargetState: state})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected header-authenticated cross-principal findings, got %+v", findings)
	}
	objects := pushConfigObjects(state.Snapshot())
	if len(objects) != 2 || objects[0].Cleanup != attack.CleanupCompleted || objects[1].Cleanup != attack.CleanupCompleted {
		t.Fatalf("header-authenticated cleanup = %+v", objects)
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
