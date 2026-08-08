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

// a2a-task-enumeration-001 asks whether one authenticated principal can enumerate
// another's tasks. Both directions are covered by the posture matrix; these are the
// controls it cannot reach, each of which is a way for the rule to be wrong without
// the matrix noticing.

// enumBehaviour decides how the fixture answers ListTasks.
type enumBehaviour int

const (
	// enumUnscoped returns every task to any authenticated caller: the finding.
	enumUnscoped enumBehaviour = iota
	// enumAbsent implements no list method at all.
	enumAbsent
	// enumRefused answers the list with an authorization error.
	enumRefused
	// enumOwnerBlind implements the list but never returns the caller's own task.
	enumOwnerBlind
	// enumWideOpen returns every task to ANYONE, including an anonymous caller.
	enumWideOpen
)

// enumAgent is an A2A agent whose ListTasks behaviour is configurable. Task creation
// always works for a known token, so a failure here is about the listing.
func enumAgent(t *testing.T, behaviour enumBehaviour) *httptest.Server {
	t.Helper()
	type task struct{ id, ctxID, owner string }
	tasks := map[string]*task{}
	n := 0

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/.well-known/") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"name":"Enum Agent","description":"d","version":"1.0.0",`+
				`"protocolVersion":"1.0","capabilities":{},"skills":[],`+
				`"supportedInterfaces":[{"url":"http://`+r.Host+`/","protocolBinding":"JSONRPC","protocolVersion":"1.0"}]}`)
			return
		}
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		method, _ := req["method"].(string)
		id := req["id"]
		w.Header().Set("Content-Type", "application/json")

		caller := ""
		switch r.Header.Get("Authorization") {
		case "Bearer tok-a":
			caller = "a"
		case "Bearer tok-b":
			caller = "b"
		}

		rpcErr := func(code int, msg string) {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"error": map[string]interface{}{"code": code, "message": msg},
			})
		}

		switch method {
		case "SendMessage", "message/send":
			if caller == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			n++
			tk := &task{id: "task-" + string(rune('0'+n)), ctxID: "ctx", owner: caller}
			tasks[tk.id] = tk
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{"task": map[string]interface{}{
					"id": tk.id, "contextId": tk.ctxID,
					"status": map[string]interface{}{"state": "TASK_STATE_SUBMITTED"},
				}},
			})
		case "ListTasks", "tasks/list":
			if behaviour == enumAbsent {
				rpcErr(-32601, "Method not found")
				return
			}
			if behaviour == enumRefused {
				rpcErr(-32600, "not authorized to list tasks")
				return
			}
			if caller == "" && behaviour != enumWideOpen {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			out := []interface{}{}
			for _, tk := range tasks {
				if behaviour == enumOwnerBlind {
					continue // implements the list, never returns anything
				}
				out = append(out, map[string]interface{}{"id": tk.id, "contextId": tk.ctxID})
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{"tasks": out, "totalSize": len(out)},
			})
		default:
			rpcErr(-32601, "Method not found")
		}
	}))
}

func enumOpts() attack.Options {
	return attack.Options{
		TimeoutSeconds: 5,
		Principals: []attack.Principal{
			{Name: "a", Token: "tok-a", Tenant: "A"},
			{Name: "b", Token: "tok-b", Tenant: "B"},
		},
	}
}

func runEnum(t *testing.T, srv *httptest.Server, opts attack.Options) ([]attack.Finding, error) {
	t.Helper()
	exec := a2aattack.NewTaskEnumerationExecutor(attack.RuleContext{
		ID: "a2a-task-enumeration-001", Severity: "high",
	})
	return exec.Execute(context.Background(), srv.URL, opts)
}

// The finding: B is authenticated, has no claim to A's task, and its identifier comes
// back in B's listing.
func TestTaskEnumeration_UnscopedListingFires(t *testing.T) {
	srv := enumAgent(t, enumUnscoped)
	defer srv.Close()

	findings, err := runEnum(t, srv, enumOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected the enumeration finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != "high" || f.Confidence != attack.ConfirmedExploit {
		t.Errorf("want high/ConfirmedExploit, got %s/%s", f.Severity, f.Confidence)
	}
	// The evidence has to name both principals and the task, or the claim is not
	// checkable by the person reading it.
	for _, want := range []string{"task owner: a", "enumerating principal: b", "task ids returned to b"} {
		if !strings.Contains(f.Evidence, want) {
			t.Errorf("evidence missing %q; got:\n%s", want, f.Evidence)
		}
	}
}

// An agent that implements no list method has nothing to scope. That is not
// applicable rather than insecure, the same call the OAuth-gated rules make for a
// server exposing no OAuth, and it must not be reported as either a finding or a
// failure to test.
func TestTaskEnumeration_NoListMethodIsClean(t *testing.T) {
	srv := enumAgent(t, enumAbsent)
	defer srv.Close()

	findings, err := runEnum(t, srv, enumOpts())
	if err != nil {
		t.Fatalf("an agent without ListTasks is not applicable, not untested: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}

// The listing is refused even for the owner, so whether it is scoped was never
// established. Reporting that clean would claim a property this rule did not test.
func TestTaskEnumeration_RefusedListingIsNotTested(t *testing.T) {
	srv := enumAgent(t, enumRefused)
	defer srv.Close()

	findings, err := runEnum(t, srv, enumOpts())
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected ErrInconclusive, got %v", err)
	}
	if !strings.Contains(err.Error(), "refused for the task's own owner") {
		t.Errorf("the reason should say the owner's own listing was refused; got: %v", err)
	}
}

// The agent implements ListTasks and returns nothing, even to the task's owner. B
// seeing nothing then proves nothing about scoping, so this is not tested rather than
// clean: without this control, any server with a broken listing would look scoped.
func TestTaskEnumeration_OwnerCannotSeeOwnTaskIsNotTested(t *testing.T) {
	srv := enumAgent(t, enumOwnerBlind)
	defer srv.Close()

	findings, err := runEnum(t, srv, enumOpts())
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected ErrInconclusive, got %v", err)
	}
	if !strings.Contains(err.Error(), "did not return principal a's own task") {
		t.Errorf("the reason should name the owner's missing task; got: %v", err)
	}
}

// A server that lists every task to an ANONYMOUS caller enforces no authorization on
// this surface at all. That is a2a-task-idor-001's finding, and reporting it here as
// well would count one defect twice.
func TestTaskEnumeration_WideOpenBelongsToTaskIDOR(t *testing.T) {
	srv := enumAgent(t, enumWideOpen)
	defer srv.Close()

	findings, err := runEnum(t, srv, enumOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("a server with no authorization at all is task-idor's finding, not this "+
			"rule's; got %d: %+v", len(findings), findings)
	}
}

// Two identities are the premise: the question is whether B sees A's task. With one
// principal, or none, there is no comparison to make and the rule must say so rather
// than call the target clean.
func TestTaskEnumeration_NeedsTwoPrincipals(t *testing.T) {
	srv := enumAgent(t, enumUnscoped)
	defer srv.Close()

	for _, tc := range []struct {
		name string
		opts attack.Options
	}{
		{"no principals", attack.Options{TimeoutSeconds: 5}},
		{"one principal", attack.Options{TimeoutSeconds: 5, Principals: []attack.Principal{
			{Name: "a", Token: "tok-a", Tenant: "A"},
		}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			findings, err := runEnum(t, srv, tc.opts)
			if len(findings) != 0 {
				t.Fatalf("expected no findings, got %d", len(findings))
			}
			if !errors.Is(err, attack.ErrInconclusive) {
				t.Fatalf("expected ErrInconclusive, got %v", err)
			}
		})
	}
}

// Identifiers, never key names. A scoped server returns a NON-EMPTY list to B
// containing only B's own task, which is the case a key-name oracle would fire on:
// the body contains "tasks" and a task id, just not A's.
func TestTaskEnumeration_ScopedListingWithOwnTasksIsClean(t *testing.T) {
	// Each caller sees exactly their own task, so both lists are non-empty.
	type task struct{ id, owner string }
	tasks := map[string]*task{}
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/.well-known/") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"name":"Scoped","description":"d","version":"1.0.0",`+
				`"protocolVersion":"1.0","capabilities":{},"skills":[],`+
				`"supportedInterfaces":[{"url":"http://`+r.Host+`/","protocolBinding":"JSONRPC","protocolVersion":"1.0"}]}`)
			return
		}
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		method, _ := req["method"].(string)
		id := req["id"]
		caller := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer tok-")
		w.Header().Set("Content-Type", "application/json")
		if caller != "a" && caller != "b" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch method {
		case "SendMessage", "message/send":
			n++
			tk := &task{id: "t" + string(rune('0'+n)), owner: caller}
			tasks[tk.id] = tk
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{"task": map[string]interface{}{
					"id": tk.id, "contextId": "ctx-" + caller,
				}},
			})
		case "ListTasks", "tasks/list":
			out := []interface{}{}
			for _, tk := range tasks {
				if tk.owner == caller {
					out = append(out, map[string]interface{}{"id": tk.id, "contextId": "ctx-" + caller})
				}
			}
			// B's own task, so B can list and gets a non-empty answer.
			if caller == "b" && len(out) == 0 {
				out = append(out, map[string]interface{}{"id": "t-b-own", "contextId": "ctx-b"})
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{"tasks": out, "totalSize": len(out)},
			})
		default:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"error": map[string]interface{}{"code": -32601, "message": "Method not found"},
			})
		}
	}))
	defer srv.Close()

	findings, err := runEnum(t, srv, enumOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("B's listing contains only B's own task, so the surface is scoped; got %d: %+v",
			len(findings), findings)
	}
}
