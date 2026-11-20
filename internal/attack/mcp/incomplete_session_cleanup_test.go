package mcp_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcp "github.com/calbebop/batesian/internal/attack/mcp"
)

func TestOriginProbesCloseIncompleteHandshake(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(string) ([]attack.Finding, error)
	}{
		{"dns rebinding", func(target string) ([]attack.Finding, error) {
			return mcp.NewDNSRebindOriginExecutor(dnsRebindRC()).Execute(context.Background(), target, attack.Options{TimeoutSeconds: 5})
		}},
		{"origin prefix", func(target string) ([]attack.Finding, error) {
			return mcp.NewOriginPrefixBypassExecutor(originPfxRC()).Execute(context.Background(), target, attack.Options{TimeoutSeconds: 5})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, closes := recordSessionCloses(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/mcp" || r.Method != http.MethodPost {
					http.NotFound(w, r)
					return
				}
				var req map[string]interface{}
				_ = json.NewDecoder(r.Body).Decode(&req)
				if req["method"] != "initialize" {
					http.NotFound(w, r)
					return
				}
				if r.Header.Get("Origin") != "" {
					w.Header().Set("Mcp-Session-Id", "incomplete-origin")
					w.WriteHeader(http.StatusBadGateway)
					return
				}
				w.Header().Set("Mcp-Session-Id", "baseline")
				writeLegacyInitialize(w, req["id"], map[string]interface{}{})
			})
			defer server.Close()
			findings, err := tc.run(server.URL)
			if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
				t.Fatalf("findings=%+v err=%v", findings, err)
			}
			got := closes()
			if len(got) != 2 || got[0].id != "incomplete-origin" || got[0].origin == "" ||
				got[1].id != "baseline" || got[1].origin != "" {
				t.Fatalf("DELETE calls=%v", got)
			}
		})
	}
}

func TestShadowClosesIncompleteHandshakes(t *testing.T) {
	server, closes := recordSessionCloses(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			return
		}
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		switch req["method"] {
		case "initialize":
			if r.URL.Path == "/mcp" {
				w.Header().Set("Mcp-Session-Id", "incomplete-path")
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
				return
			}
			if r.Header.Get("Origin") != "" {
				w.Header().Set("Mcp-Session-Id", "incomplete-origin")
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
				return
			}
			w.Header().Set("Mcp-Session-Id", "baseline")
			writeLegacyInitialize(w, req["id"], map[string]interface{}{"tools": map[string]interface{}{}})
		case "tools/list":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]interface{}{"tools": []interface{}{map[string]string{"name": "inspect"}}},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		default:
			http.NotFound(w, r)
		}
	})
	defer server.Close()
	withShadowPorts(t, portOf(server.URL))
	findings, err := runShadow(t, "http://127.0.0.1:1")
	if len(findings) != 1 || !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("findings=%+v err=%v", findings, err)
	}
	got := closes()
	if len(got) != 3 || got[0].id != "incomplete-path" || got[0].origin != "" ||
		got[1].id != "incomplete-origin" || got[1].origin == "" ||
		got[2].id != "baseline" || got[2].origin != "" {
		t.Fatalf("DELETE calls=%v", got)
	}
}

func TestPrincipalProbeClosesIncompleteHandshakes(t *testing.T) {
	for _, ownerFails := range []bool{true, false} {
		t.Run(map[bool]string{true: "owner", false: "caller"}[ownerFails], func(t *testing.T) {
			server, closes := recordSessionCloses(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/mcp" {
					http.NotFound(w, r)
					return
				}
				var req map[string]interface{}
				_ = json.NewDecoder(r.Body).Decode(&req)
				switch req["method"] {
				case "initialize":
					owner := r.Header.Get("Authorization") == "Bearer token-a"
					if ownerFails || !owner {
						w.Header().Set("Mcp-Session-Id", map[bool]string{true: "owner-incomplete", false: "caller-incomplete"}[owner])
						_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
						return
					}
					w.Header().Set("Mcp-Session-Id", "owner-valid")
					writeLegacyInitialize(w, req["id"], map[string]interface{}{"tools": map[string]interface{}{}})
				case "notifications/initialized":
					w.WriteHeader(http.StatusAccepted)
				default:
					http.NotFound(w, r)
				}
			})
			defer server.Close()
			findings, err := mcp.NewSessionPrincipalExecutor(attack.RuleContext{}).Execute(
				context.Background(), server.URL, sessionPrincipalOptions())
			if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
				t.Fatalf("findings=%+v err=%v", findings, err)
			}
			got := closes()
			if ownerFails {
				if len(got) != 1 || got[0].id != "owner-incomplete" {
					t.Fatalf("DELETE calls=%v", got)
				}
			} else if len(got) != 2 || got[0].id != "caller-incomplete" || got[1].id != "owner-valid" {
				t.Fatalf("DELETE calls=%v", got)
			}
		})
	}
}

func TestFixationClosesIncompleteSeededHandshake(t *testing.T) {
	server, closes := recordSessionCloses(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req["method"] != "initialize" {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		if r.Header.Get("Mcp-Session-Id") != "" {
			w.Header().Set("Mcp-Session-Id", "seeded-incomplete")
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.Header().Set("Mcp-Session-Id", "baseline")
		writeLegacyInitialize(w, req["id"], map[string]interface{}{"tools": map[string]interface{}{}})
	})
	defer server.Close()
	findings, err := mcp.NewSessionFixationExecutor(attack.RuleContext{}).Execute(
		context.Background(), server.URL, attack.Options{TimeoutSeconds: 5})
	if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("findings=%+v err=%v", findings, err)
	}
	got := closes()
	if len(got) != 2 || got[0].id != "seeded-incomplete" || got[1].id != "baseline" {
		t.Fatalf("DELETE calls=%v", got)
	}
}
