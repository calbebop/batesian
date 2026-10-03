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

// Shared helpers used by all test files in this package.

func testRuleCtx() attack.RuleContext {
	return attack.RuleContext{
		ID:          "a2a-test-001",
		Name:        "Test",
		Severity:    "high",
		Remediation: "Fix it",
	}
}

func testOpts() attack.Options {
	return attack.Options{TimeoutSeconds: 5}
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func jsonRPCError(code int, message string) map[string]interface{} {
	return map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "1",
		"error": map[string]interface{}{
			"code":    code,
			"message": message,
		},
	}
}

func extendedCard() map[string]interface{} {
	return map[string]interface{}{
		"name":        "Extended Agent",
		"description": "Private capabilities",
		"version":     "1.0.0",
		"supportedInterfaces": []map[string]string{{
			"url": "https://agent.example.com", "protocolBinding": "JSONRPC", "protocolVersion": "1.0",
		}},
		"capabilities":       map[string]interface{}{"extendedAgentCard": true},
		"defaultInputModes":  []string{"text/plain"},
		"defaultOutputModes": []string{"text/plain"},
		"skills":             []interface{}{},
	}
}

// TestExtCardExecutor_Vulnerable checks a card returned to an invalid token.
func TestExtCardExecutor_Vulnerable(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      readBody(r)["id"],
			"result":  extendedCard(),
		})
	}))
	defer ts.Close()

	ex := a2a.NewExtCardExecutor(testRuleCtx())
	findings, err := ex.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding, got zero")
	}
	var hasHighOrCritical bool
	for _, f := range findings {
		if f.Severity == "high" || f.Severity == "critical" {
			hasHighOrCritical = true
			break
		}
	}
	if !hasHighOrCritical {
		t.Errorf("expected at least one high or critical finding, got: %+v", findings)
	}
	// A server that accepts a fabricated invalid token is an auth bypass: at
	// least one finding must be critical.
	hasCritical := false
	for _, f := range findings {
		if f.Severity == "critical" {
			hasCritical = true
		}
		if f.Confidence != attack.ConfirmedExploit {
			t.Errorf("finding %q: want ConfirmedExploit, got %q", f.Title, f.Confidence)
		}
	}
	if !hasCritical {
		t.Errorf("expected a critical finding for fabricated-token acceptance, got: %+v", findings)
	}
}

func TestExtCardExecutor_AnonymousCard(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			http.NotFound(w, r)
			return
		}
		request := readBody(r)
		if request["method"] != "GetExtendedAgentCard" {
			response := jsonRPCError(-32601, "method not found")
			response["id"] = request["id"]
			writeJSON(w, response)
			return
		}
		if r.Header.Get("Authorization") != "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]interface{}{
			"jsonrpc": "2.0", "id": request["id"], "result": extendedCard(),
		})
	}))
	defer ts.Close()

	findings, err := a2a.NewExtCardExecutor(testRuleCtx()).Execute(t.Context(), ts.URL, testOpts())
	if err != nil || len(findings) != 1 || findings[0].Severity != "high" {
		t.Fatalf("want one high disclosure, got findings=%+v err=%v", findings, err)
	}
}

func TestExtCardExecutor_JSONRPCNonCardNotFinding(t *testing.T) {
	tests := []struct {
		name  string
		reply func(string) map[string]interface{}
	}{
		{"empty result", func(id string) map[string]interface{} {
			return map[string]interface{}{"jsonrpc": "2.0", "id": id, "result": map[string]interface{}{}}
		}},
		{"null result", func(id string) map[string]interface{} {
			return map[string]interface{}{"jsonrpc": "2.0", "id": id, "result": nil}
		}},
		{"partial card", func(id string) map[string]interface{} {
			return map[string]interface{}{"jsonrpc": "2.0", "id": id, "result": map[string]string{"name": "Agent"}}
		}},
		{"wrong id", func(string) map[string]interface{} {
			return map[string]interface{}{"jsonrpc": "2.0", "id": "other", "result": extendedCard()}
		}},
		{"missing jsonrpc version", func(id string) map[string]interface{} {
			return map[string]interface{}{"id": id, "result": extendedCard()}
		}},
		{"error and result", func(id string) map[string]interface{} {
			return map[string]interface{}{"jsonrpc": "2.0", "id": id, "result": extendedCard(), "error": map[string]interface{}{"code": -1, "message": "error"}}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					http.NotFound(w, r)
					return
				}
				writeJSON(w, tt.reply(readBody(r)["id"].(string)))
			}))
			defer ts.Close()

			findings, _ := a2a.NewExtCardExecutor(testRuleCtx()).Execute(t.Context(), ts.URL, testOpts())
			if len(findings) != 0 {
				t.Fatalf("non-card response raised a finding: %+v", findings)
			}
		})
	}
}

// TestExtCardExecutor_JSONRPCErrorNotFinding verifies that a server which
// returns HTTP 200 with a JSON-RPC error envelope (auth required at the
// protocol layer) for the extended-card method, and 404 for the legacy GET
// path, produces zero findings.
func TestExtCardExecutor_JSONRPCErrorNotFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			http.NotFound(w, r)
			return
		}
		response := jsonRPCError(-32600, "authentication required for extended card")
		response["id"] = readBody(r)["id"]
		writeJSON(w, response)
	}))
	defer ts.Close()

	findings, err := a2a.NewExtCardExecutor(testRuleCtx()).Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings when server rejects via JSON-RPC error, got %d: %+v", len(findings), findings)
	}
}

// TestExtCardExecutor_Clean verifies that a server enforcing authentication
// (returning 401 for all requests) produces zero findings.
func TestExtCardExecutor_Clean(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
	}))
	defer ts.Close()

	ex := a2a.NewExtCardExecutor(testRuleCtx())
	findings, err := ex.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings, got %d: %+v", len(findings), findings)
	}
}

// TestExtCardExecutor_HTMLLoginNotFinding verifies that a server answering the
// extended-card probe with a 200 HTML login page produces no finding. Previously
// the rule treated any 2xx non-error body as a card and raised a CRITICAL
// finding, which false-positived any target that redirects/answers probes with a
// login page.
func TestExtCardExecutor_HTMLLoginNotFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body><h1>Please log in</h1></body></html>"))
	}))
	defer ts.Close()

	findings, err := a2a.NewExtCardExecutor(testRuleCtx()).Execute(context.Background(), ts.URL, testOpts())
	if len(findings) != 0 {
		t.Errorf("expected zero findings for a 200 HTML login page, got %d: %+v", len(findings), findings)
	}
	// Nothing here identifies as an A2A agent: every path answers with the same
	// login page. Silence is the right finding count, but the run must say it
	// could not test rather than that the target is clean.
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Errorf("expected ErrInconclusive against a login-page server, got err=%v", err)
	}
}

// TestExtCardExecutor_HTTPGetRawCard is the positive control for the legacy
// HTTP-GET transport: a server that serves a raw agent card (top-level name/url)
// at the extended-card path. This exercises the parseCard-based extCardDisclosed
// gate, which the other tests (which serve a JSON-RPC result envelope) do not.
func TestExtCardExecutor_HTTPGetRawCard(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/extendedAgentCard" {
			writeJSON(w, extendedCard())
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	findings, err := a2a.NewExtCardExecutor(testRuleCtx()).Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding from the HTTP-GET raw-card path, got %d: %+v", len(findings), findings)
	}
	// The first GET carries a fabricated invalid token; a card returned to it is
	// a critical auth bypass.
	if findings[0].Severity != "critical" {
		t.Errorf("expected critical (fabricated token accepted), got %q", findings[0].Severity)
	}
}
