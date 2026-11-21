package mcp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
)

const handshakeResult = `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"fixture","version":"1"}}}`

func TestSharedHandshakeClosesFailedCandidate(t *testing.T) {
	for _, badStatus := range []bool{false, true} {
		t.Run(map[bool]string{false: "invalid result", true: "bad status"}[badStatus], func(t *testing.T) {
			var mu sync.Mutex
			var closed []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodDelete {
					if r.Header.Get("Mcp-Protocol-Version") != "2025-11-25" {
						t.Errorf("DELETE used protocol version %q", r.Header.Get("Mcp-Protocol-Version"))
					}
					mu.Lock()
					closed = append(closed, r.Header.Get("Mcp-Session-Id"))
					mu.Unlock()
					w.WriteHeader(http.StatusNoContent)
					return
				}
				if r.URL.Path == "/mcp" {
					w.Header().Set("Mcp-Session-Id", "failed-candidate")
					if badStatus {
						w.WriteHeader(http.StatusBadGateway)
					} else {
						_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
					}
					return
				}
				if r.URL.Path != "/" {
					http.NotFound(w, r)
					return
				}
				if r.Header.Get("Mcp-Session-Id") != "" {
					w.WriteHeader(http.StatusAccepted)
					return
				}
				w.Header().Set("Mcp-Session-Id", "usable-session")
				_, _ = w.Write([]byte(handshakeResult))
			}))
			defer server.Close()
			client := attack.NewUnauthHTTPClient(attack.Options{TimeoutSeconds: 5}, attack.NewVars(server.URL, ""))
			session, err := initializeMCP(context.Background(), client, server.URL)
			if err != nil || session.SessionID != "usable-session" {
				t.Fatalf("session=%+v err=%v", session, err)
			}
			closeLegacySessions(context.Background(), client, []mcpSession{session})
			mu.Lock()
			defer mu.Unlock()
			if len(closed) != 2 || closed[0] != "failed-candidate" || closed[1] != "usable-session" {
				t.Fatalf("DELETE sessions=%v", closed)
			}
		})
	}
}

func TestSharedHandshakeRequiresInitializedNotification(t *testing.T) {
	for _, rpcError := range []bool{false, true} {
		t.Run(map[bool]string{false: "HTTP failure", true: "JSON-RPC error"}[rpcError], func(t *testing.T) {
			var closed atomic.Bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/mcp" {
					http.NotFound(w, r)
					return
				}
				if r.Method == http.MethodDelete {
					closed.Store(r.Header.Get("Mcp-Session-Id") == "uninitialized")
					w.WriteHeader(http.StatusNoContent)
					return
				}
				if r.Header.Get("Mcp-Session-Id") != "" {
					if rpcError {
						_, _ = w.Write([]byte(`{"jsonrpc":"2.0","error":{"code":-32600,"message":"not initialized"}}`))
					} else {
						w.WriteHeader(http.StatusInternalServerError)
					}
					return
				}
				w.Header().Set("Mcp-Session-Id", "uninitialized")
				_, _ = w.Write([]byte(handshakeResult))
			}))
			defer server.Close()
			client := attack.NewUnauthHTTPClient(attack.Options{TimeoutSeconds: 5}, attack.NewVars(server.URL, ""))
			session, err := initializeMCP(context.Background(), client, server.URL)
			if session.Endpoint != "" || !errors.Is(err, attack.ErrInconclusive) || !closed.Load() {
				t.Fatalf("session=%+v err=%v closed=%t", session, err, closed.Load())
			}
		})
	}
}

func TestTaskIDORClosesFailedCandidateForPrincipal(t *testing.T) {
	var mu sync.Mutex
	var closed []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer owner-token" || r.Header.Get("X-Tenant") != "owner" {
			t.Errorf("principal headers missing on %s %s", r.Method, r.URL.Path)
		}
		if r.Method == http.MethodDelete {
			mu.Lock()
			closed = append(closed, r.Header.Get("Mcp-Session-Id"))
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path == "/mcp" {
			w.Header().Set("Mcp-Session-Id", "failed-owner-session")
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Mcp-Session-Id") != "" {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Mcp-Session-Id", "usable-owner-session")
		_, _ = w.Write([]byte(handshakeResult))
	}))
	defer server.Close()
	client := attack.NewUnauthHTTPClient(attack.Options{TimeoutSeconds: 5}, attack.NewVars(server.URL, ""))
	principal := taskPrincipal{name: "owner", token: "owner-token", headers: map[string]string{"X-Tenant": "owner"}}
	session, err := (&TaskIDORExecutor{}).initSession(context.Background(), client, server.URL, principal)
	if err != nil || session.SessionID != "usable-owner-session" {
		t.Fatalf("session=%+v err=%v", session, err)
	}
	closeTaskIDORSession(context.Background(), client, session, principal)
	mu.Lock()
	defer mu.Unlock()
	if len(closed) != 2 || closed[0] != "failed-owner-session" || closed[1] != "usable-owner-session" {
		t.Fatalf("DELETE sessions=%v", closed)
	}
}
