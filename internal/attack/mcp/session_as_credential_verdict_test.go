package mcp_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
)

func sessionVerdictServer(t *testing.T, mode string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		rpcError := func(code int, message string) {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID,
				"error": map[string]interface{}{"code": code, "message": message},
			})
		}
		result := func(value interface{}) {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": req.ID, "result": value})
		}
		authed := r.Header.Get("Authorization") == "Bearer operator-token"
		switch req.Method {
		case "initialize":
			if !authed {
				switch mode {
				case "ambiguous-init":
					rpcError(-32602, "Invalid params")
					return
				case "rpc-auth-init":
					rpcError(-32001, "Permission denied")
					return
				case "expired-session", "expired-session-404":
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
			}
			sid := "anonymous"
			if authed {
				sid = "credentialed"
			}
			w.Header().Set("Mcp-Session-Id", sid)
			result(map[string]interface{}{
				"protocolVersion": "2025-06-18",
				"serverInfo":      map[string]string{"name": "verdict-test", "version": "1"},
				"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
			})
		case "tools/list":
			switch r.Header.Get("Mcp-Session-Id") {
			case "credentialed":
				if !authed && (mode == "expired-session" || mode == "expired-session-404") {
					if mode == "expired-session-404" {
						w.WriteHeader(http.StatusNotFound)
					} else {
						rpcError(-32001, "Session not found")
					}
					return
				}
				result(map[string]interface{}{"tools": []interface{}{}})
			case "anonymous":
				if mode == "rpc-auth-list" {
					rpcError(-32001, "Permission denied")
				} else {
					rpcError(-32001, "Session not found")
				}
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		default:
			rpcError(-32601, "Method not found")
		}
	}))
}

func TestSessionAsCredential_AuthControlRequiresAuthRefusal(t *testing.T) {
	for _, tc := range []struct {
		mode, reason string
	}{
		{"ambiguous-init", "anonymous initialize control"},
		{"ambiguous-anon-list", "anonymous-session control"},
		{"expired-session", "credential-stripped call"},
		{"expired-session-404", "credential-stripped call"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			srv := sessionVerdictServer(t, tc.mode)
			defer srv.Close()
			findings, err := runSessionCred(t, srv)
			if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
				t.Fatalf("unproven auth boundary: findings=%+v err=%v", findings, err)
			}
			if !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("incomplete control not identified: %v", err)
			}
		})
	}
}

func TestSessionAsCredential_JSONRPCAuthControl(t *testing.T) {
	for _, mode := range []string{"rpc-auth-init", "rpc-auth-list"} {
		t.Run(mode, func(t *testing.T) {
			srv := sessionVerdictServer(t, mode)
			defer srv.Close()
			findings, err := runSessionCred(t, srv)
			if err != nil || len(findings) != 1 || findings[0].Confidence != attack.ConfirmedExploit {
				t.Fatalf("explicit auth boundary and session-only access: findings=%+v err=%v", findings, err)
			}
		})
	}
}
