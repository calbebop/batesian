package a2a_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	a2aattack "github.com/calbebop/batesian/internal/attack/a2a"
)

// batchServer models an HTTP auth gate that may mishandle batch requests.
func batchServer(mode string) *httptest.Server {
	taskNotFound := func(id interface{}) map[string]interface{} {
		return map[string]interface{}{
			"jsonrpc": "2.0", "id": id,
			"error": map[string]interface{}{"code": -32001, "message": "Task not found"},
		}
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mode == "not-a2a" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		isBatch := len(bytes.TrimSpace(raw)) > 0 && bytes.TrimSpace(raw)[0] == '['
		authed := r.Header.Get("Authorization") != ""
		w.Header().Set("Content-Type", "application/json")

		gate := !authed
		if mode == "open" {
			gate = false
		}
		if isBatch && mode == "bypass" {
			gate = false
		}

		if gate {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if isBatch {
			var objs []map[string]interface{}
			_ = json.Unmarshal(raw, &objs)
			arr := make([]interface{}, 0, len(objs))
			for _, o := range objs {
				arr = append(arr, taskNotFound(o["id"]))
			}
			_ = json.NewEncoder(w).Encode(arr)
			return
		}
		var one map[string]interface{}
		_ = json.Unmarshal(raw, &one)
		_ = json.NewEncoder(w).Encode(taskNotFound(one["id"]))
	}))
}

func runBatchBypass(t *testing.T, srv *httptest.Server) []attack.Finding {
	t.Helper()
	exec := a2aattack.NewBatchBypassExecutor(attack.RuleContext{
		ID:   "a2a-jsonrpc-batch-bypass-001",
		Name: "A2A JSON-RPC Batch Authentication Bypass",
	})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return findings
}

func TestBatchBypass_Bypassed(t *testing.T) {
	srv := batchServer("bypass")
	defer srv.Close()

	findings := runBatchBypass(t, srv)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Confidence != attack.ConfirmedExploit {
		t.Errorf("expected ConfirmedExploit, got %v", f.Confidence)
	}
	if f.Severity != "high" {
		t.Errorf("expected high severity, got %q", f.Severity)
	}
}

func TestBatchBypass_SecureNoFinding(t *testing.T) {
	srv := batchServer("secure")
	defer srv.Close()

	if findings := runBatchBypass(t, srv); len(findings) != 0 {
		t.Errorf("expected 0 findings when batches are gated too, got %d: %+v", len(findings), findings)
	}
}

func TestBatchBypass_OpenNoFinding(t *testing.T) {
	srv := batchServer("open")
	defer srv.Close()

	if findings := runBatchBypass(t, srv); len(findings) != 0 {
		t.Errorf("expected 0 findings when there is no auth gate, got %d: %+v", len(findings), findings)
	}
}

func TestBatchBypass_NotA2A(t *testing.T) {
	srv := batchServer("not-a2a")
	defer srv.Close()

	exec := a2aattack.NewBatchBypassExecutor(attack.RuleContext{ID: "a2a-jsonrpc-batch-bypass-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected ErrInconclusive for a non-A2A endpoint, got err=%v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestBatchBypass_AuthRefusalWordingIsRecognized(t *testing.T) {
	for _, msg := range []string{"Not authorized", "Access denied", "Login required", "Invalid token"} {
		t.Run(msg, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, ".well-known") {
					writeJSON(w, map[string]interface{}{"name": "secure", "version": "1.0"})
					return
				}
				body, _ := io.ReadAll(r.Body)
				w.Header().Set("Content-Type", "application/json")
				if strings.HasPrefix(strings.TrimSpace(string(body)), "[") {
					var requests []map[string]interface{}
					_ = json.Unmarshal(body, &requests)
					_ = json.NewEncoder(w).Encode([]interface{}{map[string]interface{}{
						"jsonrpc": "2.0", "id": requests[0]["id"],
						"error": map[string]interface{}{"code": -32001, "message": msg},
					}})
					return
				}
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"` + msg + `"}}`))
			}))
			defer srv.Close()

			exec := a2aattack.NewBatchBypassExecutor(attack.RuleContext{ID: "a2a-jsonrpc-batch-bypass-001"})
			findings, _ := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
			if len(findings) != 0 {
				t.Errorf("FALSE POSITIVE for %q: the batch was refused for auth, got %q",
					msg, findings[0].Title)
			}
		})
	}
}

func TestBatchBypass_RequiresCorrelatedTaskResponse(t *testing.T) {
	tests := []struct {
		name         string
		inconclusive bool
		response     func(interface{}) map[string]interface{}
	}{
		{
			name: "null id invalid batch",
			response: func(interface{}) map[string]interface{} {
				return map[string]interface{}{
					"jsonrpc": "2.0", "id": nil,
					"error": map[string]interface{}{"code": -32600, "message": "Invalid Request"},
				}
			},
		},
		{
			name:         "unrelated task response",
			inconclusive: true,
			response: func(interface{}) map[string]interface{} {
				return map[string]interface{}{
					"jsonrpc": "2.0", "id": "unrelated",
					"error": map[string]interface{}{"code": -32001, "message": "Task not found"},
				}
			},
		},
		{
			name: "correlated protocol error",
			response: func(id interface{}) map[string]interface{} {
				return map[string]interface{}{
					"jsonrpc": "2.0", "id": id,
					"error": map[string]interface{}{"code": -32600, "message": "Invalid Request"},
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					writeJSON(w, map[string]interface{}{"name": "secure", "version": "1.0"})
					return
				}
				body, _ := io.ReadAll(r.Body)
				w.Header().Set("Content-Type", "application/json")
				if !strings.HasPrefix(strings.TrimSpace(string(body)), "[") {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				var requests []map[string]interface{}
				_ = json.Unmarshal(body, &requests)
				_ = json.NewEncoder(w).Encode([]interface{}{tt.response(requests[0]["id"])})
			}))
			defer srv.Close()

			exec := a2aattack.NewBatchBypassExecutor(attack.RuleContext{ID: "a2a-jsonrpc-batch-bypass-001"})
			findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
			if len(findings) != 0 || errors.Is(err, attack.ErrInconclusive) != tt.inconclusive {
				t.Fatalf("unproven dispatch: findings=%+v, err=%v", findings, err)
			}
		})
	}
}

func TestBatchBypass_FailedBatchIsIncomplete(t *testing.T) {
	for _, mode := range []string{"server error", "connection drop"} {
		t.Run(mode, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					writeJSON(w, map[string]interface{}{"name": "secure", "version": "1.0"})
					return
				}
				body, _ := io.ReadAll(r.Body)
				if !strings.HasPrefix(strings.TrimSpace(string(body)), "[") {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				if mode == "connection drop" {
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Errorf("hijack: %v", err)
						return
					}
					_ = conn.Close()
					return
				}
				w.WriteHeader(http.StatusBadGateway)
			}))
			defer srv.Close()

			exec := a2aattack.NewBatchBypassExecutor(attack.RuleContext{ID: "a2a-jsonrpc-batch-bypass-001"})
			findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
			if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) || !strings.Contains(err.Error(), "batch") {
				t.Fatalf("failed batch: findings=%+v, err=%v", findings, err)
			}
		})
	}
}

func TestBatchBypass_ExplicitProtocolRejectionIsClean(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			writeJSON(w, map[string]interface{}{"name": "secure", "version": "1.0"})
			return
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.HasPrefix(strings.TrimSpace(string(body)), "[") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]interface{}{
			"jsonrpc": "2.0", "id": nil,
			"error": map[string]interface{}{"code": -32600, "message": "Invalid Request"},
		})
	}))
	defer srv.Close()

	if findings := runBatchBypass(t, srv); len(findings) != 0 {
		t.Fatalf("rejected batch: findings=%+v", findings)
	}
}
