package mcp_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

func sessionPrincipalOptions() attack.Options {
	return attack.Options{
		TimeoutSeconds: 5,
		Principals: []attack.Principal{
			{Name: "alice", Token: "token-a", Tenant: "A"},
			{Name: "bob", Token: "token-b", Tenant: "B"},
		},
		ExpectedDenials: []attack.ExpectedDenial{{
			Operation: attack.MCPSessionUse, Owner: "alice", OwnerTenant: "A",
			Caller: "bob", CallerTenant: "B",
		}},
	}
}

func sessionPrincipalServer(t *testing.T, mode string, closed *atomic.Int32) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	sessions := map[string]string{}
	sequence := 0
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		sid := r.Header.Get("Mcp-Session-Id")
		if r.Method == http.MethodDelete {
			closed.Add(1)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		principal := ""
		switch r.Header.Get("Authorization") {
		case "Bearer token-a":
			principal = "alice"
		case "Bearer token-b":
			principal = "bob"
		}
		var req struct {
			ID     int    `json:"id"`
			Method string `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		result := func(value interface{}) {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": req.ID, "result": value})
		}
		switch req.Method {
		case "initialize":
			if principal == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if mode != "stateless" {
				mu.Lock()
				sequence++
				sid = fmt.Sprintf("secret-session-%d", sequence)
				sessions[sid] = principal
				mu.Unlock()
				w.Header().Set("Mcp-Session-Id", sid)
			}
			result(map[string]interface{}{
				"protocolVersion": "2025-11-25", "capabilities": map[string]interface{}{"tools": map[string]interface{}{}},
				"serverInfo": map[string]interface{}{"name": "fixture", "version": "1"},
			})
		case "notifications/initialized":
			if principal == "" || sid == "" || r.Header.Get("Mcp-Protocol-Version") != "2025-11-25" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			if r.Header.Get("Mcp-Protocol-Version") != "2025-11-25" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if sid == "" && mode != "missing-open" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			mu.Lock()
			owner, issued := sessions[sid]
			mu.Unlock()
			if !issued && mode != "bogus-open" && mode != "missing-open" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if principal == "" && mode != "anonymous-open" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if principal == "bob" && owner == "alice" && mode == "secure" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			result(map[string]interface{}{"tools": []interface{}{}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestSessionPrincipalBinding(t *testing.T) {
	for _, mode := range []string{"vulnerable", "secure", "anonymous-open", "bogus-open", "missing-open", "stateless"} {
		t.Run(mode, func(t *testing.T) {
			var closed atomic.Int32
			srv := sessionPrincipalServer(t, mode, &closed)
			defer srv.Close()
			findings, err := mcpattack.NewSessionPrincipalExecutor(attack.RuleContext{
				ID: "mcp-session-principal-001", Name: "MCP Session Principal Binding",
			}).Execute(context.Background(), srv.URL+"/mcp", sessionPrincipalOptions())
			switch mode {
			case "vulnerable":
				if err != nil || len(findings) != 1 || findings[0].Confidence != attack.ConfirmedExploit {
					t.Fatalf("vulnerable result: findings=%+v, err=%v", findings, err)
				}
				for _, secret := range []string{"secret-session", "token-a", "token-b"} {
					if strings.Contains(findings[0].Description+findings[0].Evidence, secret) {
						t.Fatalf("finding leaked %s", secret)
					}
				}
			case "secure":
				if err != nil || len(findings) != 0 {
					t.Fatalf("secure result: findings=%+v, err=%v", findings, err)
				}
			default:
				if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
					t.Fatalf("control failed: findings=%+v, err=%v", findings, err)
				}
			}
			wantClosed := int32(2)
			if mode == "stateless" {
				wantClosed = 0
			}
			if closed.Load() != wantClosed {
				t.Fatalf("closed %d sessions, want %d", closed.Load(), wantClosed)
			}
		})
	}
}

func TestSessionPrincipalRequiresPolicyAndDistinctTokens(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	for _, mode := range []string{"no policy", "same token", "missing caller"} {
		opts := sessionPrincipalOptions()
		switch mode {
		case "no policy":
			opts.ExpectedDenials = nil
		case "same token":
			opts.Principals[1].Token = opts.Principals[0].Token
		case "missing caller":
			opts.Principals = opts.Principals[:1]
		}
		findings, err := mcpattack.NewSessionPrincipalExecutor(attack.RuleContext{
			ID: "mcp-session-principal-001",
		}).Execute(context.Background(), srv.URL, opts)
		if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
			t.Fatalf("%s: findings=%+v, err=%v", mode, findings, err)
		}
	}
	if requests.Load() != 0 {
		t.Fatalf("invalid policy sent %d requests", requests.Load())
	}
}
