package mcp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcp "github.com/calbebop/batesian/internal/attack/mcp"
)

type sessionClose struct {
	id, origin string
}

func recordSessionCloses(handler http.HandlerFunc) (*httptest.Server, func() []sessionClose) {
	var mu sync.Mutex
	var closes []sessionClose
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			mu.Lock()
			closes = append(closes, sessionClose{r.Header.Get("Mcp-Session-Id"), r.Header.Get("Origin")})
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		handler(w, r)
	}))
	return server, func() []sessionClose {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(closes)
	}
}

func writeLegacyInitialize(w http.ResponseWriter, id interface{}, capabilities map[string]interface{}) {
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"jsonrpc": "2.0", "id": id, "result": map[string]interface{}{
			"protocolVersion": "2025-11-25", "capabilities": capabilities,
			"serverInfo": map[string]string{"name": "cleanup-fixture", "version": "1"},
		},
	})
}

func TestLegacyOriginProbesCloseAcceptedSessions(t *testing.T) {
	for _, tc := range []struct {
		name        string
		allowOrigin func(string, string) bool
		run         func(*testing.T, *httptest.Server) ([]attack.Finding, error)
		wantForeign bool
	}{
		{"dns open", func(string, string) bool { return true }, func(t *testing.T, s *httptest.Server) ([]attack.Finding, error) {
			return runDNSRebind(t, s), nil
		}, true},
		{"dns blocked", func(origin, _ string) bool { return origin == "" }, func(t *testing.T, s *httptest.Server) ([]attack.Finding, error) {
			return runDNSRebind(t, s), nil
		}, false},
		{"prefix bypass", func(origin, own string) bool { return originAllowed(opfxPrefix, origin, own) }, runOriginPfx, true},
		{"prefix blocked", func(origin, own string) bool { return originAllowed(opfxParsedHost, origin, own) }, runOriginPfx, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, closes := recordSessionCloses(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					http.NotFound(w, r)
					return
				}
				var req map[string]interface{}
				_ = json.NewDecoder(r.Body).Decode(&req)
				switch req["method"] {
				case "initialize":
					if !tc.allowOrigin(r.Header.Get("Origin"), "http://"+r.Host) {
						w.WriteHeader(http.StatusForbidden)
						return
					}
					id := "baseline"
					if r.Header.Get("Origin") != "" {
						id = "foreign"
					}
					w.Header().Set("Mcp-Session-Id", id)
					writeLegacyInitialize(w, req["id"], map[string]interface{}{})
				case "server/discover":
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"jsonrpc": "2.0", "id": req["id"],
						"error": map[string]interface{}{"code": -32601, "message": "Method not found"},
					})
				case "notifications/initialized":
					w.WriteHeader(http.StatusAccepted)
				default:
					http.NotFound(w, r)
				}
			})
			defer server.Close()
			_, err := tc.run(t, server)
			if err != nil {
				t.Fatal(err)
			}
			got := closes()
			wantCount := 1
			if tc.wantForeign {
				wantCount++
			}
			if len(got) != wantCount {
				t.Fatalf("closed sessions=%v, want %d", got, wantCount)
			}
			for _, closed := range got {
				if closed.id == "baseline" && closed.origin == "" {
					continue
				}
				if tc.wantForeign && closed.id == "foreign" && closed.origin != "" {
					continue
				}
				t.Fatalf("unexpected DELETE: %+v", closed)
			}
		})
	}
}

func TestLoggingProbeClosesSession(t *testing.T) {
	for _, withLogging := range []bool{false, true} {
		t.Run(map[bool]string{false: "no capability", true: "auth refusal"}[withLogging], func(t *testing.T) {
			server, closes := recordSessionCloses(func(w http.ResponseWriter, r *http.Request) {
				var req map[string]interface{}
				_ = json.NewDecoder(r.Body).Decode(&req)
				switch req["method"] {
				case "initialize":
					caps := map[string]interface{}{}
					if withLogging {
						caps["logging"] = map[string]interface{}{}
					}
					w.Header().Set("Mcp-Session-Id", "logging-session")
					writeLegacyInitialize(w, req["id"], caps)
				case "notifications/initialized":
					w.WriteHeader(http.StatusAccepted)
				case "logging/setLevel":
					w.WriteHeader(http.StatusUnauthorized)
				default:
					http.NotFound(w, r)
				}
			})
			defer server.Close()
			findings, err := mcp.NewLoggingUnauthExecutor(attack.RuleContext{}).Execute(
				context.Background(), server.URL, attack.Options{TimeoutSeconds: 5})
			if err != nil || len(findings) != 0 {
				t.Fatalf("findings=%+v err=%v", findings, err)
			}
			if got := closes(); len(got) != 1 || got[0].id != "logging-session" || got[0].origin != "" {
				t.Fatalf("DELETE calls=%v", got)
			}
		})
	}
}

func TestFixationProbeClosesUnusedSessions(t *testing.T) {
	for _, mintSeeded := range []bool{false, true} {
		t.Run(map[bool]string{false: "seed refused", true: "server minted"}[mintSeeded], func(t *testing.T) {
			server, closes := recordSessionCloses(func(w http.ResponseWriter, r *http.Request) {
				var req map[string]interface{}
				_ = json.NewDecoder(r.Body).Decode(&req)
				switch req["method"] {
				case "initialize":
					id := "baseline"
					if r.Header.Get("Mcp-Session-Id") != "" {
						if !mintSeeded {
							w.WriteHeader(http.StatusForbidden)
							return
						}
						id = "seeded"
					}
					w.Header().Set("Mcp-Session-Id", id)
					writeLegacyInitialize(w, req["id"], map[string]interface{}{"tools": map[string]interface{}{}})
				case "notifications/initialized":
					w.WriteHeader(http.StatusAccepted)
				default:
					http.NotFound(w, r)
				}
			})
			defer server.Close()
			findings, err := mcp.NewSessionFixationExecutor(attack.RuleContext{}).Execute(
				context.Background(), server.URL, attack.Options{TimeoutSeconds: 5})
			if err != nil || len(findings) != 0 {
				t.Fatalf("findings=%+v err=%v", findings, err)
			}
			got := closes()
			want := []string{"baseline"}
			if mintSeeded {
				want = append(want, "seeded")
			}
			ids := make([]string, len(got))
			for i, closed := range got {
				ids[i] = closed.id
			}
			slices.Sort(ids)
			slices.Sort(want)
			if !slices.Equal(ids, want) {
				t.Fatalf("DELETE sessions=%v, want %v", ids, want)
			}
		})
	}
}
