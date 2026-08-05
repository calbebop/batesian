package a2a_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/attack/a2a"
)

// A rule that finds nothing has to distinguish "this agent is not vulnerable to
// this" from "nothing here is an A2A agent". These pin both sides of that line,
// because a fix that only widens the inconclusive case is easy to write and
// turns every clean scan into a skipped one.

// cardlessAgentServer answers a task lookup the way an A2A agent with no such
// task does, and method-not-found for everything else. It serves no agent card,
// which several real agents and three of this repository's fixtures also do.
func cardlessAgentServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		method, _ := req["method"].(string)
		w.Header().Set("Content-Type", "application/json")
		switch method {
		case "tasks/get", "GetTask":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"Task not found"}}`))
		default:
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}`))
		}
	}))
}

// mcpLikeServer answers method-not-found for A2A methods and a valid MCP
// initialize result, which is what made endpoint discovery accept it.
func mcpLikeServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		method, _ := req["method"].(string)
		w.Header().Set("Content-Type", "application/json")
		if method == "initialize" {
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18",` +
				`"serverInfo":{"name":"mcp","version":"1.0"},"capabilities":{}}}`))
			return
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}`))
	}))
}

// cardOnlyServer serves a valid agent card that advertises no capabilities, and
// 404s everything else. This is an A2A agent, so a rule whose feature is absent
// here is genuinely reporting a clean result.
func cardOnlyServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/agent-card.json" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"Minimal Agent","url":"http://example.invalid/","capabilities":{}}`))
	}))
}

func executors() map[string]attack.Executor {
	rc := testRuleCtx()
	return map[string]attack.Executor{
		"card-trust":           a2a.NewCardTrustExecutor(rc),
		"jws-algconf":          a2a.NewJWSAlgConfExecutor(rc),
		"wellknown-hostinject": a2a.NewWellKnownHostInjectExecutor(rc),
		"extension-downgrade":  a2a.NewExtensionDowngradeExecutor(rc),
		"extcard":              a2a.NewExtCardExecutor(rc),
		"session-smuggle":      a2a.NewSessionSmuggleExecutor(rc),
		"push-ssrf":            a2a.NewPushSSRFExecutor(rc),
	}
}

// Every rule that used to report clean against a non-A2A target must now report
// that it could not test.
func TestRules_NonA2ATargetIsNotTested(t *testing.T) {
	ts := mcpLikeServer()
	defer ts.Close()

	for name, exec := range executors() {
		t.Run(name, func(t *testing.T) {
			findings, err := exec.Execute(context.Background(), ts.URL, attack.Options{TimeoutSeconds: 5})
			if len(findings) != 0 {
				t.Fatalf("expected no findings against a non-A2A target, got %d: %+v", len(findings), findings)
			}
			if !errors.Is(err, attack.ErrInconclusive) {
				t.Errorf("expected ErrInconclusive, got err=%v", err)
			}
		})
	}
}

// The regression this change could easily cause: an agent that serves no card is
// still an agent when its JSON-RPC endpoint answers, and must stay testable.
// a2a_delegation_server.py and a2a_push_binding_server.py are both cardless.
func TestRules_CardlessAgentStaysTestable(t *testing.T) {
	ts := cardlessAgentServer()
	defer ts.Close()

	// The card rules genuinely cannot run without a card, so they are excluded:
	// this asserts the endpoint rules are not skipped for want of one.
	for _, name := range []string{"extension-downgrade", "extcard", "session-smuggle"} {
		t.Run(name, func(t *testing.T) {
			_, err := executors()[name].Execute(context.Background(), ts.URL, attack.Options{TimeoutSeconds: 5})
			if errors.Is(err, attack.ErrInconclusive) {
				t.Errorf("rule reported it could not test a cardless agent whose endpoint answers")
			}
		})
	}
}

// The other regression: a card is served and the rule's feature is simply not
// present. That is a real clean result and must not become a skip.
func TestRules_CardServedButFeatureAbsentIsClean(t *testing.T) {
	ts := cardOnlyServer()
	defer ts.Close()

	// extension-downgrade is the clearest case: a card advertising no required
	// extension leaves nothing to downgrade.
	findings, err := executors()["extension-downgrade"].Execute(context.Background(), ts.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("expected a clean result for a card with no required extensions, got err=%v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d: %+v", len(findings), findings)
	}
}
