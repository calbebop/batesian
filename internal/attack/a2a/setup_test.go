package a2a_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	a2aattack "github.com/calbebop/batesian/internal/attack/a2a"
)

// These rules need a task before their oracle can run. A refused setup must be
// reported as incomplete, not clean.

type securedAgentFixture struct {
	*httptest.Server
	authorizedCreates atomic.Int64
}

// securedAgent admits the listed credentials and counts authorized task creates.
func securedAgent(t *testing.T, validTokens ...string) *securedAgentFixture {
	t.Helper()
	fixture := &securedAgentFixture{}
	fixture.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/.well-known/") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"name":"Secured Agent","description":"d","version":"1.0.0",`+
				`"protocolVersion":"1.0","capabilities":{},"skills":[],`+
				`"supportedInterfaces":[{"url":"http://`+r.Host+`/","protocolBinding":"JSONRPC","protocolVersion":"1.0"}]}`)
			return
		}
		authorized := false
		for _, token := range validTokens {
			if r.Header.Get("Authorization") == "Bearer "+token {
				authorized = true
				break
			}
		}
		if !authorized {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":"unauthenticated","message":"a valid bearer token is required"}`)
			return
		}
		// Authorized callers get a task, so the rules have something to work with and
		// this fixture cannot pass by refusing everything.
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if method, _ := req["method"].(string); method == "SendMessage" || method == "message/send" {
			fixture.authorizedCreates.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": req["id"],
			"result": map[string]interface{}{
				"id": "task-1", "contextId": "ctx-1",
				"status": map[string]interface{}{"state": "working"},
			},
		})
	}))
	return fixture
}

// taskSetupRules exercise task creation before their authorization probes.
func taskSetupRules() map[string]func(attack.RuleContext) attack.Executor {
	return map[string]func(attack.RuleContext) attack.Executor{
		"a2a-task-idor-001": func(rc attack.RuleContext) attack.Executor {
			return a2aattack.NewTaskIDORExecutor(rc)
		},
		"a2a-push-ssrf-001": func(rc attack.RuleContext) attack.Executor {
			return a2aattack.NewPushSSRFExecutor(rc)
		},
		"a2a-session-smuggle-001": func(rc attack.RuleContext) attack.Executor {
			return a2aattack.NewSessionSmuggleExecutor(rc)
		},
		"a2a-context-fixation-001": func(rc attack.RuleContext) attack.Executor {
			return a2aattack.NewContextFixationExecutor(rc)
		},
		"a2a-delegation-integrity-001": func(rc attack.RuleContext) attack.Executor {
			return a2aattack.NewDelegationIntegrityExecutor(rc)
		},
		"a2a-multitenant-isolation-001": func(rc attack.RuleContext) attack.Executor {
			return a2aattack.NewMultiTenantIsolationExecutor(rc)
		},
		"a2a-push-binding-001": func(rc attack.RuleContext) attack.Executor {
			return a2aattack.NewPushBindingExecutor(rc)
		},
		"a2a-push-lifecycle-001": func(rc attack.RuleContext) attack.Executor {
			return a2aattack.NewPushLifecycleExecutor(rc)
		},
		"a2a-task-cancel-idor-001": func(rc attack.RuleContext) attack.Executor {
			return a2aattack.NewTaskCancelIDORExecutor(rc)
		},
	}
}

// Both configured identities are rejected by the fixture.
func twoRejectedPrincipals() attack.Options {
	return attack.Options{
		TimeoutSeconds: 5,
		Token:          "not-the-valid-token",
		Principals: []attack.Principal{
			{Name: "a", Token: "rejected-a", Tenant: "A"},
			{Name: "b", Token: "rejected-b", Tenant: "B"},
		},
	}
}

// A rejected credential must not produce a clean result.
func TestTaskSetup_RejectedCredentialIsNotTestedForEveryRule(t *testing.T) {
	srv := securedAgent(t, "the-valid-token")
	defer srv.Close()

	for id, build := range taskSetupRules() {
		t.Run(id, func(t *testing.T) {
			exec := build(attack.RuleContext{ID: id, Severity: "high"})
			findings, err := exec.Execute(context.Background(), srv.URL, twoRejectedPrincipals())
			if len(findings) != 0 {
				t.Fatalf("expected no findings against a secured agent, got %d", len(findings))
			}
			if !errors.Is(err, attack.ErrInconclusive) {
				t.Fatalf("a rule that never created a task must report not tested, got err=%v", err)
			}
			// The reason has to be usable, or the operator learns nothing from it.
			if !strings.Contains(err.Error(), srv.URL) {
				t.Errorf("reason should name the endpoint; got: %v", err)
			}
			for _, want := range []string{"401", "credential"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("reason should mention %q; got: %v", want, err)
				}
			}
		})
	}
}

// Each rule must create a task with accepted credentials before its oracle runs.
func TestTaskSetup_AcceptedCredentialGetsPastSetup(t *testing.T) {
	srv := securedAgent(t, "valid-a", "valid-b")
	defer srv.Close()

	opts := attack.Options{
		TimeoutSeconds: 5,
		Token:          "valid-a",
		Principals: []attack.Principal{
			{Name: "a", Token: "valid-a", Tenant: "A"},
			{Name: "b", Token: "valid-b", Tenant: "B"},
		},
	}
	for id, build := range taskSetupRules() {
		t.Run(id, func(t *testing.T) {
			exec := build(attack.RuleContext{ID: id, Severity: "high"})
			before := srv.authorizedCreates.Load()
			findings, err := exec.Execute(context.Background(), srv.URL, opts)
			if srv.authorizedCreates.Load() == before {
				t.Fatalf("accepted credentials did not create a task: findings=%+v err=%v", findings, err)
			}
			if err != nil && !errors.Is(err, attack.ErrInconclusive) {
				t.Fatalf("rule failed after task creation: %v", err)
			}
		})
	}
}

// An agent that implements no task-creation method at all is a different fact: there
// is nothing to test and nothing wrong, which is the same call the OAuth-gated rules
// make for a server exposing no OAuth. It must stay a clean result, or every agent
// without a task surface would be reported as not tested.
func TestTaskSetup_FeatureAbsentStaysClean(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/.well-known/") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"name":"No Tasks","description":"d","version":"1.0.0",`+
				`"protocolVersion":"1.0","capabilities":{},"skills":[],`+
				`"supportedInterfaces":[{"url":"http://`+r.Host+`/","protocolBinding":"JSONRPC","protocolVersion":"1.0"}]}`)
			return
		}
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": req["id"],
			"error": map[string]interface{}{"code": -32601, "message": "method not found"}})
	}))
	defer srv.Close()

	for _, id := range []string{
		"a2a-multitenant-isolation-001", "a2a-delegation-integrity-001",
		"a2a-push-binding-001", "a2a-push-lifecycle-001", "a2a-task-cancel-idor-001",
	} {
		t.Run(id, func(t *testing.T) {
			exec := taskSetupRules()[id](attack.RuleContext{ID: id, Severity: "high"})
			findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{
				TimeoutSeconds: 5,
				Principals: []attack.Principal{
					{Name: "a", Token: "tok-a", Tenant: "A"},
					{Name: "b", Token: "tok-b", Tenant: "B"},
				},
			})
			if err != nil {
				t.Fatalf("an agent with no task surface is not applicable, not untested: %v", err)
			}
			if len(findings) != 0 {
				t.Errorf("expected no findings, got %d", len(findings))
			}
		})
	}
}

func TestTaskSetup_HTTPFailureWithUnsupportedBodyIsIncomplete(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		code   int
	}{
		{"request timeout", http.StatusRequestTimeout, -32601},
		{"rate limited", http.StatusTooManyRequests, -32601},
		{"service unavailable", http.StatusServiceUnavailable, -32004},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.URL.Path, "/.well-known/") {
					writeJSON(w, map[string]interface{}{
						"name": "Setup agent", "supportedInterfaces": []interface{}{
							map[string]string{"url": "http://" + r.Host + "/", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"},
						},
					})
					return
				}
				if r.URL.Path != "/" {
					http.NotFound(w, r)
					return
				}
				method, id := decodeRPC(r)
				switch method {
				case "GetTask", "tasks/get":
					rpcErr(w, id, -32001, "Task not found")
				case "SendMessage":
					w.WriteHeader(tc.status)
					rpcErr(w, id, tc.code, "Method not found")
				default:
					rpcErr(w, id, -32601, "Method not found")
				}
			}))
			defer srv.Close()

			for _, rule := range []struct {
				id    string
				build func(attack.RuleContext) attack.Executor
			}{
				{"a2a-task-cancel-idor-001", taskSetupRules()["a2a-task-cancel-idor-001"]},
				{"a2a-task-enumeration-001", func(rc attack.RuleContext) attack.Executor {
					return a2aattack.NewTaskEnumerationExecutor(rc)
				}},
			} {
				t.Run(rule.id, func(t *testing.T) {
					findings, err := rule.build(attack.RuleContext{ID: rule.id}).Execute(
						context.Background(), srv.URL, twoRejectedPrincipals())
					if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
						t.Fatalf("findings=%+v err=%v, want incomplete", findings, err)
					}
				})
			}
		})
	}
}

// a2a-session-smuggle-001 sends a message claiming the agent role, which the
// specification requires the server to REFUSE. That refusal is the pass this rule
// looks for, so it must stay a clean result: only an authorization refusal means the
// message never reached the role handling. Getting this wrong would take a genuine
// pass away from every well-behaved agent.
func TestTaskSetup_SpecRequiredRejectionStaysClean(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/.well-known/") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"name":"Strict Agent","description":"d","version":"1.0.0",`+
				`"protocolVersion":"1.0","capabilities":{},"skills":[],`+
				`"supportedInterfaces":[{"url":"http://`+r.Host+`/","protocolBinding":"JSONRPC","protocolVersion":"1.0"}]}`)
			return
		}
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		// Refuses the forged role on its merits, with no authorization involved.
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": req["id"],
			"error": map[string]interface{}{"code": -32602, "message": "message role must be user"}})
	}))
	defer srv.Close()

	exec := a2aattack.NewSessionSmuggleExecutor(attack.RuleContext{ID: "a2a-session-smuggle-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("a spec-required rejection is a pass, not an untested result: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}
