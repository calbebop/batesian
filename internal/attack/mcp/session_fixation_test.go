package mcp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

func sfRuleCtx() attack.RuleContext {
	return attack.RuleContext{ID: "mcp-session-fixation-001", Name: "MCP Session Fixation", Severity: "high", Remediation: "Mint server-side."}
}

func writeInitResult(w http.ResponseWriter, id interface{}) {
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"jsonrpc": "2.0", "id": id,
		"result": map[string]interface{}{
			"protocolVersion": "2025-03-26",
			"serverInfo":      map[string]interface{}{"name": "fixation-fixture", "version": "1.0"},
			"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
		},
	})
}

func writeToolsResult(w http.ResponseWriter, id interface{}) {
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"jsonrpc": "2.0", "id": id,
		"result": map[string]interface{}{
			"tools": []interface{}{map[string]interface{}{"name": "echo", "description": "echo"}},
		},
	})
}

// fixationServer models an MCP Streamable HTTP server. mode selects the posture:
//   - "fixable":      adopts a client-supplied Mcp-Session-Id; rejects unknown ids (404)
//   - "server-minted": ignores the supplied id and mints its own; rejects unknown ids
//   - "sessionless":  does not track sessions at all (accepts any id, never 404)
func fixationServer(mode string) *httptest.Server {
	var mu sync.Mutex
	valid := map[string]bool{}
	counter := 0

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		method, _ := req["method"].(string)
		id := req["id"]
		supplied := r.Header.Get("Mcp-Session-Id")
		w.Header().Set("Content-Type", "application/json")

		switch method {
		case "initialize":
			sid := ""
			switch mode {
			case "fixable":
				if supplied != "" {
					sid = supplied // VULNERABLE: trusts the client-chosen id
				} else {
					counter++
					sid = fmt.Sprintf("srv-%d", counter)
				}
			case "sessionless":
				sid = "" // no session tracking
			default: // server-minted
				counter++
				sid = fmt.Sprintf("srv-%d", counter)
			}
			if sid != "" {
				mu.Lock()
				valid[sid] = true
				mu.Unlock()
				w.Header().Set("Mcp-Session-Id", sid)
			}
			writeInitResult(w, id)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			if mode == "sessionless" {
				writeToolsResult(w, id) // accepts regardless of session
				return
			}
			mu.Lock()
			known := valid[supplied]
			mu.Unlock()
			if !known {
				w.WriteHeader(http.StatusNotFound) // spec: unknown session => 404
				return
			}
			writeToolsResult(w, id)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// TestSessionFixation_Confirmed: the server adopts the client-supplied id and
// rejects an un-initialized id. The rule MUST fire (confirmed, high) with a
// 3-hop provenance chain.
func TestSessionFixation_Confirmed(t *testing.T) {
	srv := fixationServer("fixable")
	defer srv.Close()

	findings, err := mcpattack.NewSessionFixationExecutor(sfRuleCtx()).
		Execute(context.Background(), srv.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 fixation finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Confidence != attack.ConfirmedExploit || f.Severity != "high" {
		t.Errorf("want high/ConfirmedExploit, got %q/%q", f.Severity, f.Confidence)
	}
	if len(f.Chain) != 3 {
		t.Errorf("expected a 3-hop chain (no second principal), got %d: %+v", len(f.Chain), f.Chain)
	}
}

// TestSessionFixation_ServerMinted: the server mints its own session id and
// ignores the client-supplied one. The rule MUST stay silent.
func TestSessionFixation_ServerMinted(t *testing.T) {
	srv := fixationServer("server-minted")
	defer srv.Close()

	findings, err := mcpattack.NewSessionFixationExecutor(sfRuleCtx()).
		Execute(context.Background(), srv.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings against a server-minted session id, got %d: %+v", len(findings), findings)
	}
}

// TestSessionFixation_SessionlessIsNotFixation: the server tracks no sessions at
// all (accepts any id). That is a different posture, not fixation. The rule MUST
// stay silent (the control discriminator suppresses it).
func TestSessionFixation_SessionlessIsNotFixation(t *testing.T) {
	srv := fixationServer("sessionless")
	defer srv.Close()

	findings, err := mcpattack.NewSessionFixationExecutor(sfRuleCtx()).
		Execute(context.Background(), srv.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings against a sessionless server, got %d: %+v", len(findings), findings)
	}
}

// TestSessionFixation_NotMCPServer: a non-MCP server yields no findings.
func TestSessionFixation_NotMCPServer(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()

	findings, err := mcpattack.NewSessionFixationExecutor(sfRuleCtx()).
		Execute(context.Background(), srv.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings against a non-MCP server, got %d", len(findings))
	}
}

// TestSessionFixation_CrossPrincipal: with a second principal configured the
// rule adds a 4th provenance hop proving the pre-seeded session is borrowable
// across principals.
func TestSessionFixation_CrossPrincipal(t *testing.T) {
	srv := fixationServer("fixable")
	defer srv.Close()

	opts := testOpts()
	opts.Principals = []attack.Principal{
		{Name: "attacker", Token: ""},
		{Name: "victim", Token: "victim-token"},
	}
	findings, err := mcpattack.NewSessionFixationExecutor(sfRuleCtx()).
		Execute(context.Background(), srv.URL, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if len(findings[0].Chain) != 4 {
		t.Errorf("expected a 4-hop chain with the cross-principal borrow, got %d: %+v", len(findings[0].Chain), findings[0].Chain)
	}
	if findings[0].Chain[3].Principal != "victim" {
		t.Errorf("expected hop 4 by principal 'victim', got %q", findings[0].Chain[3].Principal)
	}
}
