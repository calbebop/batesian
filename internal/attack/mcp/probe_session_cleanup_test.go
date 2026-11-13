package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/calbebop/batesian/internal/attack"
)

type cleanupFixture struct {
	*httptest.Server
	mu       sync.Mutex
	issued   map[string]string
	closed   map[string]bool
	invalid  []string
	version  string
	gate     string
	batch    bool
	badInit  bool
	badNotif bool
}

func newCleanupFixture(t *testing.T, gate string, batch, badInit, badNotif bool) *cleanupFixture {
	t.Helper()
	f := &cleanupFixture{
		issued: make(map[string]string), closed: make(map[string]bool),
		version: "2025-03-26", gate: gate, batch: batch, badInit: badInit, badNotif: badNotif,
	}
	if batch && !badInit {
		f.version = "2024-11-05"
	}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/oauth-authorization-server" {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer": f.URL, "token_endpoint": f.URL + "/token",
			})
			return
		}
		if r.URL.Path != "/mcp" && r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodDelete {
			id := r.Header.Get("Mcp-Session-Id")
			wantVersion := f.version
			if f.badInit && !f.batch {
				wantVersion = latestStable
			}
			f.mu.Lock()
			auth, known := f.issued[id]
			if !known || f.closed[id] || r.Header.Get("Authorization") != auth ||
				r.Header.Get("Mcp-Protocol-Version") != wantVersion {
				f.invalid = append(f.invalid, fmt.Sprintf("id=%q known=%t duplicate=%t auth=%t version=%q",
					id, known, f.closed[id], r.Header.Get("Authorization") == auth, r.Header.Get("Mcp-Protocol-Version")))
			} else {
				f.closed[id] = true
			}
			f.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var raw json.RawMessage
		if json.NewDecoder(r.Body).Decode(&raw) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		batched := len(raw) > 0 && raw[0] == '['
		if batched && !f.batch {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if batched {
			var requests []json.RawMessage
			_ = json.Unmarshal(raw, &requests)
			if len(requests) != 1 {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			raw = requests[0]
		}
		_ = json.Unmarshal(raw, &req)
		w.Header().Set("Content-Type", "application/json")
		auth := r.Header.Get("Authorization")
		switch req.Method {
		case "initialize":
			if (f.batch && !batched) || (f.gate == "init" && auth == "") {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if f.gate == "unknown" && auth == "" {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0", "id": req.ID,
					"error": map[string]interface{}{"code": -32002, "message": "Resource not found"},
				})
				return
			}
			f.mu.Lock()
			id := fmt.Sprintf("session-%d", len(f.issued)+1)
			f.issued[id] = auth
			f.mu.Unlock()
			w.Header().Set("Mcp-Session-Id", id)
			if f.badInit {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			result := map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID,
				"result": map[string]interface{}{
					"protocolVersion": f.version,
					"serverInfo":      map[string]string{"name": "cleanup-fixture", "version": "1"},
					"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
				},
			}
			if batched {
				_ = json.NewEncoder(w).Encode([]interface{}{result})
			} else {
				_ = json.NewEncoder(w).Encode(result)
			}
		case "notifications/initialized":
			if f.badNotif {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			if auth == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID,
				"result": map[string]interface{}{"tools": []interface{}{}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	return f
}

func (f *cleanupFixture) assertClosed(t *testing.T, want int) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.issued) != want || len(f.closed) != want || len(f.invalid) != 0 {
		t.Fatalf("issued=%d closed=%d invalid=%v, want %d closed sessions",
			len(f.issued), len(f.closed), f.invalid, want)
	}
}

func TestProbeSessionCleanup_GateAndForgedMethod(t *testing.T) {
	for _, badNotif := range []bool{false, true} {
		t.Run(fmt.Sprintf("notification-fails=%t", badNotif), func(t *testing.T) {
			f := newCleanupFixture(t, "method", false, false, badNotif)
			defer f.Close()
			client := attack.NewUnauthHTTPClient(attack.Options{TimeoutSeconds: 5}, attack.NewVars(f.URL, ""))
			gate := probeInitGate(context.Background(), client, f.URL+"/mcp")
			if badNotif && gate.gate != gateUnknown || !badNotif && gate.gate != gateAfterInit {
				t.Fatalf("gate = %v", gate.gate)
			}
			_, verdict, _ := probeForgedAtMethod(context.Background(), client, f.URL+"/mcp", "tools/list", "forged")
			if badNotif && verdict != accessUndetermined || !badNotif && verdict != accessGranted {
				t.Fatalf("forged verdict = %v", verdict)
			}
			f.assertClosed(t, 2)
		})
	}
}

func TestProbeSessionCleanup_TokenReplay(t *testing.T) {
	f := newCleanupFixture(t, "init", false, false, false)
	defer f.Close()
	exec := NewTokenReplayExecutor(attack.RuleContext{ID: "mcp-token-replay", Name: "token replay"})
	findings, _ := exec.Execute(context.Background(), f.URL+"/mcp", attack.Options{TimeoutSeconds: 5, Token: "operator-token"})
	if len(findings) != 3 {
		t.Fatalf("findings = %d, want 3", len(findings))
	}
	f.assertClosed(t, 3)
}

func TestProbeSessionCleanup_Audience(t *testing.T) {
	for _, gate := range []string{"init", "unknown"} {
		t.Run(gate, func(t *testing.T) {
			f := newCleanupFixture(t, gate, false, false, false)
			defer f.Close()
			client := attack.NewHTTPClient(attack.Options{TimeoutSeconds: 5, Token: "operator-token"}, attack.NewVars(f.URL, ""))
			anon := attack.NewUnauthHTTPClient(attack.Options{TimeoutSeconds: 5}, attack.NewVars(f.URL, ""))
			_, outcomes, err := runProbesAgainstEndpoint(context.Background(), client, anon, f.URL+"/mcp", []audienceProbe{{name: "test", audClaim: "other"}})
			if gate == "unknown" && !errors.Is(err, attack.ErrInconclusive) || gate == "init" && (err != nil || len(outcomes) != 1) {
				t.Fatalf("outcomes = %d, err = %v", len(outcomes), err)
			}
			f.assertClosed(t, 1)
		})
	}
}

func TestProbeSessionCleanup_CrossAudience(t *testing.T) {
	for _, badInit := range []bool{false, true} {
		t.Run(fmt.Sprintf("initialize-fails=%t", badInit), func(t *testing.T) {
			f := newCleanupFixture(t, "init", false, badInit, false)
			defer f.Close()
			client := attack.NewUnauthHTTPClient(attack.Options{TimeoutSeconds: 5}, attack.NewVars(f.URL, ""))
			verdict := crossLegacyBearer(context.Background(), client, f.URL+"/mcp", gateProbe{gate: gateOnInit}, "other-resource-token")
			if badInit && verdict != accessUndetermined || !badInit && verdict != accessGranted {
				t.Fatalf("verdict = %v", verdict)
			}
			f.assertClosed(t, 1)
		})
	}
}

func TestProbeSessionCleanup_BatchInitialize(t *testing.T) {
	for _, badInit := range []bool{false, true} {
		t.Run(fmt.Sprintf("initialize-fails=%t", badInit), func(t *testing.T) {
			f := newCleanupFixture(t, "", true, badInit, false)
			defer f.Close()
			client := attack.NewUnauthHTTPClient(attack.Options{TimeoutSeconds: 5}, attack.NewVars(f.URL, ""))
			exec := NewBatchBypassExecutor(attack.RuleContext{ID: "mcp-jsonrpc-batch-bypass"})
			_, _, _ = exec.probeEndpoint(context.Background(), client, f.URL+"/mcp")
			f.assertClosed(t, 1)
		})
	}
}

func TestProbeSessionCleanup_StatelessResponse(t *testing.T) {
	f := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			t.Error("stateless response triggered DELETE")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","serverInfo":{"name":"test","version":"1"},"capabilities":{"tools":{}}}}`))
	}))
	defer f.Close()
	client := attack.NewUnauthHTTPClient(attack.Options{TimeoutSeconds: 5}, attack.NewVars(f.URL, ""))
	_ = probeInitGate(context.Background(), client, f.URL)
}

func TestProbeSessionCleanup_BoundedAfterCancel(t *testing.T) {
	deleteSeen := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.Header.Get("Mcp-Session-Id") != "session-1" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		deleteSeen <- struct{}{}
		<-r.Context().Done()
	}))
	defer srv.Close()
	client := attack.NewUnauthHTTPClient(attack.Options{TimeoutSeconds: 10}, attack.NewVars(srv.URL, ""))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	closeProbeSession(ctx, client, srv.URL, &attack.Response{
		Headers: http.Header{"Mcp-Session-Id": []string{"session-1"}},
	}, "", latestStable)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("DELETE cleanup took %s, want at most 5s", elapsed)
	}
	select {
	case <-deleteSeen:
	default:
		t.Fatal("DELETE was not sent after the parent context was cancelled")
	}
}
