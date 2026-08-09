package mcp_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

// mcp-task-idor-001 against a server that scopes tasks the way 2025-11-25 actually
// requires: by AUTHORIZATION CONTEXT, not by session.
//
//	"When an authorization context is provided, receivers MUST bind tasks to said
//	context."
//
// The existing fixture scopes by Mcp-Session-Id, which is stricter than the spec and
// is why a whole class of false positive was invisible to the suite. Two sessions of
// the SAME credential are one authorization context, so a server that hands the second
// session the first session's task is conformant. The rule used to fall back to
// opts.Token for both identities and report that as an IDOR, at high plus two
// criticals, on a plain --token scan.

// ctxScopedConfig shapes the spec-conformant fixture.
type ctxScopedConfig struct {
	// stateless mints no Mcp-Session-Id, as a stateless Streamable HTTP deployment.
	stateless bool
	// listStatus, when non-zero, is the HTTP status tools/list answers with.
	listStatus int
	// createStatus, when non-zero, is the HTTP status a CREDENTIALLED tools/call gets.
	createStatus int
	// anonCreateStatus, when non-zero, is what an ANONYMOUS tools/call gets, which is
	// how the discriminator's control is made to produce no verdict.
	anonCreateStatus int
	// tenantHeader, when set, is the header the server reads the owner from instead of
	// the bearer token, as a gateway-resolved tenant.
	tenantHeader string
	// seen records the owner identity of every tasks/get, for header assertions.
	seen *[]string
}

func ctxScopedServer(t *testing.T, cfg ctxScopedConfig) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	sessions, tasks := 0, 0
	owner := map[string]string{} // taskId -> owning authorization context

	// identity is the authorization context a request presents.
	identity := func(r *http.Request) string {
		if cfg.tenantHeader != "" {
			return r.Header.Get(cfg.tenantHeader)
		}
		return r.Header.Get("Authorization")
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		method, _ := body["method"].(string)
		params, _ := body["params"].(map[string]interface{})
		id := body["id"]
		who := identity(r)
		authed := who != ""

		w.Header().Set("Content-Type", "application/json")
		result := func(v map[string]interface{}) {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id, "result": v,
			})
		}
		rpcErr := func(code int, msg string) {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"error": map[string]interface{}{"code": code, "message": msg},
			})
		}

		switch method {
		case "initialize":
			mu.Lock()
			sessions++
			sid := fmt.Sprintf("sess-%d", sessions)
			mu.Unlock()
			if !cfg.stateless {
				w.Header().Set("Mcp-Session-Id", sid)
			}
			result(map[string]interface{}{
				"protocolVersion": "2025-11-25",
				"serverInfo":      map[string]interface{}{"name": "ctx-scoped", "version": "1.0"},
				"capabilities": map[string]interface{}{
					"tools": map[string]interface{}{},
					"tasks": map[string]interface{}{
						"list":     map[string]interface{}{},
						"cancel":   map[string]interface{}{},
						"requests": map[string]interface{}{"tools": map[string]interface{}{"call": map[string]interface{}{}}},
					},
				},
			})

		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)

		case "tools/list":
			if cfg.listStatus != 0 {
				w.WriteHeader(cfg.listStatus)
				return
			}
			result(map[string]interface{}{"tools": []interface{}{map[string]interface{}{
				"name":        "research",
				"description": "long running research",
				"execution":   map[string]interface{}{"taskSupport": "required"},
				"annotations": map[string]interface{}{"readOnlyHint": true},
				"inputSchema": map[string]interface{}{
					"type":       "object",
					"properties": map[string]interface{}{"topic": map[string]interface{}{"type": "string"}},
				},
			}}})

		case "tools/call":
			if _, isTask := params["task"]; !isTask {
				rpcErr(-32600, "task augmentation required")
				return
			}
			if !authed {
				if cfg.anonCreateStatus != 0 {
					w.WriteHeader(cfg.anonCreateStatus)
					return
				}
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if cfg.createStatus != 0 {
				w.WriteHeader(cfg.createStatus)
				return
			}
			mu.Lock()
			tasks++
			tid := fmt.Sprintf("task-%d", tasks)
			owner[tid] = who
			mu.Unlock()
			result(map[string]interface{}{"task": map[string]interface{}{
				"taskId": tid, "status": "working", "createdAt": "2026-07-20T07:00:00Z",
			}})

		case "tasks/get", "tasks/result", "tasks/list":
			if cfg.seen != nil {
				mu.Lock()
				*cfg.seen = append(*cfg.seen, who)
				mu.Unlock()
			}
			if !authed {
				rpcErr(-32001, "Unauthorized")
				return
			}
			if method == "tasks/list" {
				mu.Lock()
				var mine []interface{}
				for tid, o := range owner {
					if o == who {
						mine = append(mine, map[string]interface{}{"taskId": tid, "status": "working"})
					}
				}
				mu.Unlock()
				result(map[string]interface{}{"tasks": mine})
				return
			}
			tid, _ := params["taskId"].(string)
			mu.Lock()
			o, exists := owner[tid]
			mu.Unlock()
			// Bound to the AUTHORIZATION CONTEXT, exactly as the spec requires.
			if !exists || o != who {
				rpcErr(-32602, "Invalid params: unknown task")
				return
			}
			if method == "tasks/result" {
				result(map[string]interface{}{"content": []interface{}{
					map[string]interface{}{"type": "text", "text": "research output"},
				}})
				return
			}
			result(map[string]interface{}{
				"status": "working", "createdAt": "2026-07-20T07:00:00Z",
			})

		default:
			rpcErr(-32601, "Method not found")
		}
	}))
}

func execTaskIDOR(t *testing.T, srv *httptest.Server, opts attack.Options) ([]attack.Finding, error) {
	t.Helper()
	if opts.TimeoutSeconds == 0 {
		opts.TimeoutSeconds = 5
	}
	return mcpattack.NewTaskIDORExecutor(attack.RuleContext{ID: "mcp-task-idor-001"}).
		Execute(t.Context(), srv.URL, opts)
}

// The headline false positive. A single credential is ONE authorization context, so
// there is no boundary to cross and nothing to report. The rule used to run anyway and
// emit three findings against this conformant server.
func TestTaskIDOR_SingleCredentialIsNotTested(t *testing.T) {
	ts := ctxScopedServer(t, ctxScopedConfig{})
	defer ts.Close()

	findings, err := execTaskIDOR(t, ts, attack.Options{Token: "tok-a"})
	if len(findings) != 0 {
		t.Fatalf("one credential cannot cross an authorization boundary, got %d finding(s): %+v",
			len(findings), findings)
	}
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("want ErrInconclusive, got %v", err)
	}
	if !strings.Contains(err.Error(), "principal") {
		t.Errorf("the reason should say a second identity is needed; got: %v", err)
	}
}

// Two principals carrying the SAME credential are also one context.
func TestTaskIDOR_TwoPrincipalsSameTokenIsNotTested(t *testing.T) {
	ts := ctxScopedServer(t, ctxScopedConfig{})
	defer ts.Close()

	findings, err := execTaskIDOR(t, ts, attack.Options{Principals: []attack.Principal{
		{Name: "a", Token: "same"}, {Name: "b", Token: "same"},
	}})
	if len(findings) != 0 {
		t.Fatalf("expected zero findings, got %d: %+v", len(findings), findings)
	}
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("want ErrInconclusive, got %v", err)
	}
	if !strings.Contains(err.Error(), "same credential") {
		t.Errorf("the reason should say the two identities are the same; got: %v", err)
	}
}

// A server that binds tasks to the authorization context is CLEAN, and clean rather
// than not tested: two real identities were used and the second was refused.
func TestTaskIDOR_ContextScopedIsClean(t *testing.T) {
	ts := ctxScopedServer(t, ctxScopedConfig{})
	defer ts.Close()

	findings, err := execTaskIDOR(t, ts, attack.Options{Principals: []attack.Principal{
		{Name: "a", Token: "tok-a"}, {Name: "b", Token: "tok-b"},
	}})
	if err != nil {
		t.Fatalf("a server that scopes by authorization context is a real clean result: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings, got %d: %+v", len(findings), findings)
	}
}

// Two identities distinguished only by a gateway-resolved tenant header. They ARE two
// authorization contexts, so the rule must run, and it must actually send the headers.
// Ignoring Principal.Headers collapsed such a pair into one identity.
func TestTaskIDOR_PrincipalHeadersAreSentAndCountAsIdentity(t *testing.T) {
	var seen []string
	ts := ctxScopedServer(t, ctxScopedConfig{tenantHeader: "X-Tenant-Id", seen: &seen})
	defer ts.Close()

	findings, err := execTaskIDOR(t, ts, attack.Options{Principals: []attack.Principal{
		{Name: "a", Token: "shared", Headers: map[string]string{"X-Tenant-Id": "tenant-a"}},
		{Name: "b", Token: "shared", Headers: map[string]string{"X-Tenant-Id": "tenant-b"}},
	}})
	if err != nil {
		t.Fatalf("two tenants are two authorization contexts, so this is testable: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("the fixture scopes by tenant, so it is clean; got %d: %+v", len(findings), findings)
	}
	// The identities must have reached the server, or the "clean" above is an artefact
	// of both requests being anonymous.
	var sawB bool
	for _, who := range seen {
		if who == "tenant-b" {
			sawB = true
		}
	}
	if !sawB {
		t.Errorf("principal B's tenant header never reached the server; saw %v", seen)
	}
}

// A stateless deployment mints no Mcp-Session-Id. The rule used to require the two
// sessions to have DIFFERENT ids, so both were empty, the comparison held, and it
// returned clean without sending the cross-principal read at all.
func TestTaskIDOR_StatelessServerIsStillProbed(t *testing.T) {
	var seen []string
	ts := ctxScopedServer(t, ctxScopedConfig{stateless: true, seen: &seen})
	defer ts.Close()

	_, err := execTaskIDOR(t, ts, attack.Options{Principals: []attack.Principal{
		{Name: "a", Token: "tok-a"}, {Name: "b", Token: "tok-b"},
	}})
	if err != nil {
		t.Fatalf("a stateless server is testable: %v", err)
	}
	var sawB bool
	for _, who := range seen {
		if who == "Bearer tok-b" {
			sawB = true
		}
	}
	if !sawB {
		t.Error("principal B never read the task: a stateless server has no session ids to " +
			"differ, and requiring them to differ skipped the probe entirely")
	}
}

// The premise steps must not report clean when they produced no verdict.
func TestTaskIDOR_PremiseFailuresAreNotClean(t *testing.T) {
	cases := []struct {
		name string
		cfg  ctxScopedConfig
		want string
	}{
		{"tools/list scope-gated", ctxScopedConfig{listStatus: http.StatusForbidden}, "tools/list"},
		{"task creation refused", ctxScopedConfig{createStatus: http.StatusForbidden}, "could not create a task"},
		{"task creation errors", ctxScopedConfig{createStatus: http.StatusBadGateway}, "could not create a task"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := ctxScopedServer(t, tc.cfg)
			defer ts.Close()

			findings, err := execTaskIDOR(t, ts, attack.Options{Principals: []attack.Principal{
				{Name: "a", Token: "tok-a"}, {Name: "b", Token: "tok-b"},
			}})
			if len(findings) != 0 {
				t.Fatalf("no task existed, so nothing could be found: %+v", findings)
			}
			if !errors.Is(err, attack.ErrInconclusive) {
				t.Fatalf("a premise that was never established is not a clean pass, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the reason should name what failed (%q); got: %v", tc.want, err)
			}
		})
	}
}

// The anonymous discriminator decides whether this server has an authorization context
// at all, which is what makes the requirement bind. A control that produced no verdict
// used to be written into the finding's evidence as "anonymous task creation: refused".
func TestTaskIDOR_UndeterminedAnonymousControlIsNotTested(t *testing.T) {
	ts := ctxScopedServer(t, ctxScopedConfig{anonCreateStatus: http.StatusBadGateway})
	defer ts.Close()

	findings, err := execTaskIDOR(t, ts, attack.Options{Principals: []attack.Principal{
		{Name: "a", Token: "tok-a"}, {Name: "b", Token: "tok-b"},
	}})
	if len(findings) != 0 {
		t.Fatalf("the discriminator never resolved, so no finding may assert one: %+v", findings)
	}
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("want ErrInconclusive, got %v", err)
	}
	if !strings.Contains(err.Error(), "authorization context") {
		t.Errorf("the reason should say the discriminator could not resolve; got: %v", err)
	}
}
