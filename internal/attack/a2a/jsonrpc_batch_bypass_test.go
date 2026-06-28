package a2a_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	a2aattack "github.com/calbebop/batesian/internal/attack/a2a"
)

// batchServer builds a mock A2A JSON-RPC server whose auth behavior depends on
// mode:
//   - "bypass": a single request is rejected at the HTTP layer (401) when
//     unauthenticated, but a batch array is dispatched without auth (the bug).
//   - "secure": the 401 gate applies to single AND batch requests alike.
//   - "open":   nothing is gated (every request reaches the handler).
//   - "not-a2a": every request 404s.
//
// A dispatched GetTask/tasks/get for the probe's non-existent id returns a
// TaskNotFound (-32001) application error, which is exactly what proves the
// dispatcher ran past the auth gate.
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

		// gate: is the HTTP auth gate active for this request shape?
		gate := !authed
		if mode == "open" {
			gate = false
		}
		// In "bypass" mode the gate is skipped for batches (the vulnerability); in
		// "secure" mode it applies to batches too.
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

// TestBatchBypass_Bypassed: single request gated (401), batch dispatched => confirmed.
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

// TestBatchBypass_SecureNoFinding: the gate applies to batches too => no finding.
func TestBatchBypass_SecureNoFinding(t *testing.T) {
	srv := batchServer("secure")
	defer srv.Close()

	if findings := runBatchBypass(t, srv); len(findings) != 0 {
		t.Errorf("expected 0 findings when batches are gated too, got %d: %+v", len(findings), findings)
	}
}

// TestBatchBypass_OpenNoFinding: nothing is gated, so there is no auth to bypass.
func TestBatchBypass_OpenNoFinding(t *testing.T) {
	srv := batchServer("open")
	defer srv.Close()

	if findings := runBatchBypass(t, srv); len(findings) != 0 {
		t.Errorf("expected 0 findings when there is no auth gate, got %d: %+v", len(findings), findings)
	}
}

// TestBatchBypass_NotA2A: a non-A2A endpoint that 404s must not produce a finding.
func TestBatchBypass_NotA2A(t *testing.T) {
	srv := batchServer("not-a2a")
	defer srv.Close()

	if findings := runBatchBypass(t, srv); len(findings) != 0 {
		t.Errorf("expected 0 findings for a non-A2A endpoint, got %d", len(findings))
	}
}
