package a2a_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"testing"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/attack/a2a"
)

// pushSSRFServer optionally sends a callback to the registered URL.
func pushSSRFServer(t *testing.T, callBack bool) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	var registeredURL, registeredID string
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		req := readBody(r)
		method, _ := req["method"].(string)
		id := req["id"]
		switch method {
		case "SendMessage":
			writeJSON(w, map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{
					"id": "task-push-001", "contextId": "ctx-push-001", "status": map[string]string{"state": "TASK_STATE_SUBMITTED"},
				},
			})
		case "CreateTaskPushNotificationConfig":
			params, _ := req["params"].(map[string]interface{})
			mu.Lock()
			registeredURL, _ = params["url"].(string)
			registeredID, _ = params["id"].(string)
			mu.Unlock()
			if callBack {
				if url, _ := params["url"].(string); url != "" {
					token, _ := params["token"].(string)
					hc := &http.Client{Timeout: 3 * time.Second}
					if cbReq, err := http.NewRequest(http.MethodPost, url, nil); err == nil {
						cbReq.Header.Set("X-A2A-Notification-Token", token)
						if resp, err := hc.Do(cbReq); err == nil {
							_ = resp.Body.Close()
						}
					}
				}
			}
			writeJSON(w, map[string]interface{}{"jsonrpc": "2.0", "id": id, "result": map[string]interface{}{
				"taskId": "task-push-001", "id": params["id"], "url": params["url"],
			}})
		case "GetTaskPushNotificationConfig":
			params, _ := req["params"].(map[string]interface{})
			mu.Lock()
			callbackURL, configID := registeredURL, registeredID
			mu.Unlock()
			if params["taskId"] != "task-push-001" || params["id"] != configID {
				t.Error("readback targeted the wrong push config")
			}
			writeJSON(w, map[string]interface{}{"jsonrpc": "2.0", "id": id, "result": map[string]interface{}{
				"taskId": "task-push-001", "id": configID, "url": callbackURL,
			}})
		case "DeleteTaskPushNotificationConfig":
			params, _ := req["params"].(map[string]interface{})
			if params["taskId"] != "task-push-001" || !strings.HasPrefix(params["id"].(string), "batesian-") {
				t.Error("cleanup targeted the wrong push config")
			}
			writeJSON(w, map[string]interface{}{"jsonrpc": "2.0", "id": id, "result": map[string]interface{}{}})
		default:
			writeJSON(w, jsonRPCError(-32601, "Method not found"))
		}
	}))
}

func TestPushSSRF_PrivateCallbackConfirmed(t *testing.T) {
	ts := pushSSRFServer(t, true)
	defer ts.Close()

	// No OOBListenerURL => the executor spins up its own local listener.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	state := &attack.TargetState{}
	opts := testOpts()
	opts.TargetState = state
	findings, err := a2a.NewPushSSRFExecutor(testRuleCtx()).Execute(ctx, ts.URL, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one private callback finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Severity != "medium" || findings[0].Confidence != attack.RiskIndicator {
		t.Errorf("want medium/indicator, got %q/%q", findings[0].Severity, findings[0].Confidence)
	}
	objects := state.Snapshot()
	if len(objects) != 2 || objects[1].Cleanup != attack.CleanupCompleted ||
		!strings.Contains(findings[0].Evidence, "deleted after probe") {
		t.Fatalf("cleanup state = %+v, evidence = %q", objects, findings[0].Evidence)
	}
}

// v03PushServer speaks only the v0.3 methods: SendMessage is unknown, message/send
// returns a task, and tasks/pushNotificationConfig/set performs the outbound
// call. It exists because the v0.3 path used to send tasks/send, a v0.2-era
// method name that a2a-sdk answers -32601, so that whole branch was dead against
// any current server and no test noticed.
func v03PushServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		req := readBody(r)
		method, _ := req["method"].(string)
		id := req["id"]
		params, _ := req["params"].(map[string]interface{})

		switch method {
		case "message/send":
			writeJSON(w, map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{
					"id": "task-v03-001", "contextId": "ctx-v03-001", "status": map[string]string{"state": "submitted"},
				},
			})
		case "tasks/pushNotificationConfig/set":
			cfg, _ := params["pushNotificationConfig"].(map[string]interface{})
			if url, _ := cfg["url"].(string); url != "" {
				token, _ := cfg["token"].(string)
				hc := &http.Client{Timeout: 3 * time.Second}
				if cbReq, err := http.NewRequest(http.MethodPost, url, nil); err == nil {
					cbReq.Header.Set("X-A2A-Notification-Token", token)
					if resp, err := hc.Do(cbReq); err == nil {
						_ = resp.Body.Close()
					}
				}
			}
			writeJSON(w, map[string]interface{}{"jsonrpc": "2.0", "id": id, "result": map[string]interface{}{
				"taskId": "task-v03-001", "pushNotificationConfig": cfg,
			}})
		default:
			// Covers SendMessage and tasks/send alike: a v0.3-only server knows
			// neither.
			rpcErr(w, id, -32601, "Method not found")
		}
	}))
}

func TestPushSSRF_V03BindingConfirmed(t *testing.T) {
	ts := v03PushServer(t)
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	findings, err := a2a.NewPushSSRFExecutor(testRuleCtx()).Execute(ctx, ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one private callback finding over the v0.3 binding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Severity != "medium" || findings[0].Confidence != attack.RiskIndicator {
		t.Errorf("want medium/indicator, got %q/%q", findings[0].Severity, findings[0].Confidence)
	}
}

// A server that answers message/send with a Message rather than a Task has
// nothing to attach a push config to. Treating that as an accepted registration
// would have the rule wait for a callback nobody agreed to send, and, on the
// external-OOB path, report a task acceptance that never happened.
func TestPushSSRF_MessageReplyIsNotARegistration(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		req := readBody(r)
		method, _ := req["method"].(string)
		if method == "message/send" {
			writeJSON(w, map[string]interface{}{
				"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]interface{}{
					"kind": "message", "messageId": "m-1", "role": "agent",
					"parts": []interface{}{map[string]string{"kind": "text", "text": "Echo: ping"}},
				},
			})
			return
		}
		rpcErr(w, req["id"], -32601, "Method not found")
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	findings, err := a2a.NewPushSSRFExecutor(testRuleCtx()).Execute(ctx, ts.URL, attack.Options{
		TimeoutSeconds: 5,
		OOBListenerURL: "http://oob.batesian.invalid",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no finding when the agent replies with a Message, got %d: %+v", len(findings), findings)
	}
}

// restPushServer speaks only the HTTP+JSON binding, mounted under a prefix the
// card advertises. JSON-RPC is dead here, so the rule can only get there through
// the card.
//
// The REST attempt used to POST a fixed /tasks/send. No binding defines that
// path, and the prefix cannot be guessed either: a2a-sdk takes it as a parameter
// and lets the deployment choose which protocol version sits under it.
func restPushServer(t *testing.T, prefix string, staleFirst bool) *httptest.Server {
	t.Helper()
	var host string
	mux := http.NewServeMux()
	srv := httptest.NewUnstartedServer(mux)

	mux.HandleFunc("/.well-known/agent-card.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		interfaces := []map[string]string{}
		if staleFirst {
			interfaces = append(interfaces, map[string]string{
				"url": host + "/old", "protocolBinding": "HTTP+JSON", "protocolVersion": "1.0",
			})
		}
		interfaces = append(interfaces, map[string]string{
			"url": host + prefix, "protocolBinding": "HTTP+JSON", "protocolVersion": "1.0",
		})
		writeJSON(w, map[string]interface{}{"name": "REST Agent", "supportedInterfaces": interfaces})
	})
	mux.HandleFunc(prefix+"/message:send", func(w http.ResponseWriter, r *http.Request) {
		// The shape a2a-sdk actually returns from REST message:send.
		writeJSON(w, map[string]interface{}{
			"task": map[string]interface{}{
				"id": "task-rest-001", "contextId": "ctx-rest-001", "status": map[string]string{"state": "TASK_STATE_SUBMITTED"},
			},
		})
	})
	mux.HandleFunc(prefix+"/tasks/task-rest-001/pushNotificationConfigs", func(w http.ResponseWriter, r *http.Request) {
		body := readBody(r)
		if url, _ := body["url"].(string); url != "" {
			token, _ := body["token"].(string)
			hc := &http.Client{Timeout: 3 * time.Second}
			if cbReq, err := http.NewRequest(http.MethodPost, url, nil); err == nil {
				cbReq.Header.Set("X-A2A-Notification-Token", token)
				if resp, err := hc.Do(cbReq); err == nil {
					_ = resp.Body.Close()
				}
			}
		}
		writeJSON(w, map[string]interface{}{"taskId": "task-rest-001", "url": body["url"]})
	})

	srv.Start()
	host = srv.URL
	return srv
}

func TestPushSSRF_RESTBindingFromCard(t *testing.T) {
	ts := restPushServer(t, "/v1", false)
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	findings, err := a2a.NewPushSSRFExecutor(testRuleCtx()).Execute(ctx, ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one private callback finding over the REST binding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Severity != "medium" || findings[0].Confidence != attack.RiskIndicator {
		t.Errorf("want medium/indicator, got %q/%q", findings[0].Severity, findings[0].Confidence)
	}
}

func TestPushSSRF_SecondRESTBindingFromCard(t *testing.T) {
	ts := restPushServer(t, "/v1", true)
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	findings, err := a2a.NewPushSSRFExecutor(testRuleCtx()).Execute(ctx, ts.URL, testOpts())
	if err != nil || len(findings) != 1 {
		t.Fatalf("expected a finding through the later REST binding: findings=%+v err=%v", findings, err)
	}
}

func TestPushSSRF_RESTTaskSetupOutcomes(t *testing.T) {
	tests := []struct {
		name         string
		status       int
		body         string
		inconclusive bool
	}{
		{"service unavailable", http.StatusServiceUnavailable, "", true},
		{"service error with RPC code", http.StatusServiceUnavailable, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}`, true},
		{"authentication refused", http.StatusUnauthorized, "", true},
		{"message without task", http.StatusOK, `{"message":{"messageId":"reply","role":"agent","parts":[]}}`, true},
		{"route absent", http.StatusNotFound, "", false},
		{"method absent", http.StatusMethodNotAllowed, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/.well-known/agent-card.json" {
					writeJSON(w, map[string]interface{}{
						"name": "REST agent",
						"supportedInterfaces": []interface{}{map[string]string{
							"url": "http://" + r.Host + "/rest", "protocolBinding": "HTTP+JSON", "protocolVersion": "1.0",
						}},
					})
					return
				}
				if r.URL.Path == "/rest/message:send" {
					w.WriteHeader(tt.status)
					_, _ = w.Write([]byte(tt.body))
					return
				}
				if r.URL.Path != "/" {
					http.NotFound(w, r)
					return
				}
				method, id := decodeRPC(r)
				if method == "GetTask" || method == "tasks/get" {
					rpcErr(w, id, -32001, "Task not found")
					return
				}
				rpcErr(w, id, -32601, "Method not found")
			}))
			defer ts.Close()

			opts := testOpts()
			opts.OOBListenerURL = "https://oob.example.invalid"
			findings, err := a2a.NewPushSSRFExecutor(testRuleCtx()).Execute(t.Context(), ts.URL, opts)
			if len(findings) != 0 || errors.Is(err, attack.ErrInconclusive) != tt.inconclusive ||
				(!tt.inconclusive && err != nil) {
				t.Fatalf("want inconclusive=%t without findings, got findings=%v err=%v",
					tt.inconclusive, findings, err)
			}
		})
	}
}

// An agent that advertises no HTTP+JSON interface must not be probed for one.
// The old code POSTed /tasks/send at every target regardless, which was a
// guaranteed 404 on each scan.
func TestPushSSRF_NoRESTInterfaceIsNotProbed(t *testing.T) {
	var restProbes int
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/agent-card.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"JSONRPC Only","preferredTransport":"JSONRPC"}`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, ":send") || strings.Contains(r.URL.Path, "tasks/send") {
			restProbes++
		}
		writeJSON(w, jsonRPCError(-32601, "Method not found"))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	_, _ = a2a.NewPushSSRFExecutor(testRuleCtx()).Execute(ctx, ts.URL, testOpts())

	if restProbes != 0 {
		t.Errorf("sent %d REST probes to an agent that advertises no HTTP+JSON interface, want 0", restProbes)
	}
}

func TestPushSSRF_AcceptedNoCallbackIsIncomplete(t *testing.T) {
	ts := pushSSRFServer(t, false)
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	findings, err := a2a.NewPushSSRFExecutor(testRuleCtx()).Execute(ctx, ts.URL, testOpts())
	if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("unobserved callback must be incomplete, got findings=%+v err=%v", findings, err)
	}
	if !strings.Contains(err.Error(), "callback") {
		t.Errorf("skip reason should identify the missing callback: %v", err)
	}
}

func TestPushSSRF_ExternalOOBNeedsVerification(t *testing.T) {
	ts := pushSSRFServer(t, false)
	defer ts.Close()

	opts := testOpts()
	opts.OOBListenerURL = "http://oob.batesian.invalid"
	state := &attack.TargetState{}
	opts.TargetState = state
	findings, err := a2a.NewPushSSRFExecutor(testRuleCtx()).Execute(t.Context(), ts.URL, opts)
	if err != nil || len(findings) != 1 {
		t.Fatalf("external callback needs manual verification, got findings=%+v err=%v", findings, err)
	}
	if findings[0].Severity != "info" || findings[0].Confidence != attack.RiskIndicator {
		t.Errorf("external OOB should remain an unverified indicator: %+v", findings[0])
	}
	objects := state.Snapshot()
	if len(objects) != 2 || objects[1].Cleanup != attack.CleanupNotAttempted ||
		!strings.Contains(findings[0].Evidence, "remove after manual verification") {
		t.Fatalf("external OOB cleanup state = %+v, evidence = %q", objects, findings[0].Evidence)
	}
}

// TestPushSSRFExecutor_MethodNotFound verifies that a server rejecting all A2A
// methods with JSON-RPC -32601 produces zero findings.
func TestPushSSRFExecutor_MethodNotFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			rpcErr(w, readBody(r)["id"], -32601, "Method not found")
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	findings, err := a2a.NewPushSSRFExecutor(testRuleCtx()).Execute(ctx, ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings, got %d: %+v", len(findings), findings)
	}
}

// TestPushSSRF_DryRunBindsNoListener verifies that a dry run previews the SSRF
// probe against the non-resolving placeholder callback instead of binding a local
// OOB listener. A dry run must open no socket, so the recorded plan must carry the
// placeholder host and never a real listener address.
func TestPushSSRF_DryRunBindsNoListener(t *testing.T) {
	rec := &attack.Recorder{}
	rec.SetCurrentRule("a2a-push-ssrf-001")
	opts := attack.Options{DryRun: true, Recorder: rec}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// A dry run answers every request with a synthetic 200 {} and reaches no
	// agent, so ErrInconclusive is the truthful outcome and is accepted here.
	// What this test is actually about is the two assertions below: no socket,
	// and the placeholder callback in the recorded plan.
	_, err := a2a.NewPushSSRFExecutor(testRuleCtx()).Execute(ctx, "http://target.invalid", opts)
	if err != nil && !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("dry-run Execute returned error: %v", err)
	}

	reqs := rec.Requests()
	if len(reqs) == 0 {
		t.Fatal("dry run recorded no requests")
	}
	var sawPlaceholder bool
	for _, r := range reqs {
		if strings.Contains(r.Body, "oob.batesian.invalid") {
			sawPlaceholder = true
		}
		if strings.Contains(r.Body, "127.0.0.1") || strings.Contains(r.Body, "0.0.0.0") {
			t.Errorf("dry-run request body references a real listener address: %s", r.Body)
		}
	}
	if !sawPlaceholder {
		t.Error("dry-run plan never used the placeholder OOB callback URL")
	}
}
