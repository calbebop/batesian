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
	a2aattack "github.com/calbebop/batesian/internal/attack/a2a"
)

// Eight A2A rules need a task before their oracle means anything, and each of them
// used to report a clean result when no task could be created. On an agent that
// enforces authorization and is scanned without a usable credential, that is a
// high- or critical-severity claim with nothing behind it: "this agent does not
// leak tasks across principals" when no task was ever created.
//
// It survived five validation rounds because it needs an agent that is reachable
// AND enforces authorization, and no fixture in testdata/ is one. This is that
// fixture, in-process.

// securedAgent serves a valid agent card so endpoint resolution succeeds, then
// refuses every JSON-RPC call with HTTP 401 unless it carries validToken. That is
// the shape of the a2a-sdk agent this defect was found against, and of every
// correctly secured deployment.
func securedAgent(t *testing.T, validToken string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/.well-known/") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"name":"Secured Agent","description":"d","version":"1.0.0",`+
				`"protocolVersion":"1.0","capabilities":{},"skills":[],`+
				`"supportedInterfaces":[{"url":"http://`+r.Host+`/","protocolBinding":"JSONRPC","protocolVersion":"1.0"}]}`)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+validToken {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":"unauthenticated","message":"a valid bearer token is required"}`)
			return
		}
		// Authorized callers get a task, so the rules have something to work with and
		// this fixture cannot pass by refusing everything.
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": req["id"],
			"result": map[string]interface{}{
				"id": "task-1", "contextId": "ctx-1",
				"status": map[string]interface{}{"state": "working"},
			},
		})
	}))
}

// theEightRules are every rule whose oracle needs a task it has to create first.
func theEightRules() map[string]func(attack.RuleContext) attack.Executor {
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
		"a2a-task-cancel-idor-001": func(rc attack.RuleContext) attack.Executor {
			return a2aattack.NewTaskCancelIDORExecutor(rc)
		},
	}
}

// twoRejectedPrincipals is the case that produced eight silent false cleans: the
// operator configured two identities, so the two-principal gate from #170 passes,
// and the agent rejects both.
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

// No rule may report a clean result when the credential it was given cannot create
// a task. Every one of these reported clean before.
func TestTaskSetup_RejectedCredentialIsNotTestedForEveryRule(t *testing.T) {
	srv := securedAgent(t, "the-valid-token")
	defer srv.Close()

	for id, build := range theEightRules() {
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

// The same agent with the credential it accepts. Every rule must get past setup, so
// the fixture above cannot be passing merely by being unreachable, and so this
// change cannot be silencing rules that could in fact run.
func TestTaskSetup_AcceptedCredentialGetsPastSetup(t *testing.T) {
	srv := securedAgent(t, "the-valid-token")
	defer srv.Close()

	opts := attack.Options{
		TimeoutSeconds: 5,
		Token:          "the-valid-token",
		Principals: []attack.Principal{
			{Name: "a", Token: "the-valid-token", Tenant: "A"},
			{Name: "b", Token: "the-valid-token", Tenant: "B"},
		},
	}
	for id, build := range theEightRules() {
		t.Run(id, func(t *testing.T) {
			exec := build(attack.RuleContext{ID: id, Severity: "high"})
			_, err := exec.Execute(context.Background(), srv.URL, opts)
			if errors.Is(err, attack.ErrInconclusive) &&
				strings.Contains(err.Error(), "no task existed to test with") {
				t.Errorf("setup should have succeeded with the accepted credential; got: %v", err)
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
		"a2a-push-binding-001", "a2a-task-cancel-idor-001",
	} {
		t.Run(id, func(t *testing.T) {
			exec := theEightRules()[id](attack.RuleContext{ID: id, Severity: "high"})
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
