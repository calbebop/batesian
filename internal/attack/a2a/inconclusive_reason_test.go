package a2a_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	a2aattack "github.com/calbebop/batesian/internal/attack/a2a"
)

// reachableNoCardServer answers JSON-RPC normally but serves no agent card. The
// endpoint is plainly reachable, so a rule that gives up here has not failed to
// reach anything: it has failed to find the card it analyses.
//
// This distinction is the point of the test. Every one of these rules reported
// "could not reach a testable endpoint", which is what an operator reads as a
// network or address problem, when the target was answering the whole time.
func reachableNoCardServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, ".well-known") {
			http.NotFound(w, r)
			return
		}
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": body["id"],
			"result": map[string]interface{}{
				"id": "task-1", "contextId": "ctx-1",
				"status": map[string]interface{}{"state": "completed"},
			},
		})
	}))
}

// The card-analysing rules must attribute their skip to the missing card rather
// than to reachability, and must name the card so the operator knows what to fix.
func TestCardRules_InconclusiveReasonNamesTheMissingCard(t *testing.T) {
	srv := reachableNoCardServer(t)
	defer srv.Close()

	cases := map[string]func(attack.RuleContext) attack.Executor{
		"a2a-card-trust-001": func(rc attack.RuleContext) attack.Executor {
			return a2aattack.NewCardTrustExecutor(rc)
		},
		"a2a-jws-algconf-001": func(rc attack.RuleContext) attack.Executor {
			return a2aattack.NewJWSAlgConfExecutor(rc)
		},
		"a2a-card-security-unenforced-001": func(rc attack.RuleContext) attack.Executor {
			return a2aattack.NewCardSecurityUnenforcedExecutor(rc)
		},
		"a2a-wellknown-hostinject-001": func(rc attack.RuleContext) attack.Executor {
			return a2aattack.NewWellKnownHostInjectExecutor(rc)
		},
	}

	for id, mk := range cases {
		t.Run(id, func(t *testing.T) {
			exec := mk(attack.RuleContext{ID: id, Name: id, Severity: "medium"})
			findings, err := exec.Execute(context.Background(), srv.URL, testOpts())
			if len(findings) != 0 {
				t.Fatalf("expected no findings against a server serving no card, got %d", len(findings))
			}
			if !errors.Is(err, attack.ErrInconclusive) {
				t.Fatalf("no card means the rule was not exercised; want ErrInconclusive, got %v", err)
			}
			if !strings.Contains(err.Error(), "agent card") {
				t.Errorf("reason should name the missing agent card, got: %v", err)
			}
		})
	}
}
