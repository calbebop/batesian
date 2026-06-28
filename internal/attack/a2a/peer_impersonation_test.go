package a2a_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	a2aattack "github.com/calbebop/batesian/internal/attack/a2a"
)

func peerImpersonationRC() attack.RuleContext {
	return attack.RuleContext{
		ID:          "a2a-peer-impersonation-001",
		Name:        "A2A Peer Agent Impersonation via Forged JWT",
		Severity:    "high",
		Remediation: "Validate JWT signatures against a known JWKS endpoint.",
	}
}

// jwtAcceptingServer accepts any request that includes an Authorization header
// and rejects requests without one. This simulates a server that reads JWT
// claims without verifying the signature.
func jwtAcceptingServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "agent-card.json") {
			writeJSON(w, map[string]interface{}{
				"name":    "test-agent",
				"version": "1.0",
			})
			return
		}
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"result": map[string]interface{}{
				"id":     "task-001",
				"status": map[string]interface{}{"state": "completed"},
			},
		})
	}))
}

// unauthAllowedServer accepts all requests regardless of whether a token is present.
func unauthAllowedServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "agent-card.json") {
			writeJSON(w, map[string]interface{}{
				"name":    "open-agent",
				"version": "1.0",
			})
			return
		}
		writeJSON(w, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"result": map[string]interface{}{
				"id":     "task-002",
				"status": map[string]interface{}{"state": "completed"},
			},
		})
	}))
}

// properJWTServer rejects all bearer tokens (simulating real signature validation
// where the random key used to forge the JWT is unknown to the server).
func properJWTServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "agent-card.json") {
			http.NotFound(w, r)
			return
		}
		// Any bearer token is rejected; the forged token (random key) will fail.
		w.WriteHeader(http.StatusUnauthorized)
	}))
}

// TestPeerImpersonation_ForgedJWTAccepted verifies a high-severity finding is
// emitted when the server accepts a forged JWT but rejects unauthenticated requests.
func TestPeerImpersonation_ForgedJWTAccepted(t *testing.T) {
	ts := jwtAcceptingServer(t)
	defer ts.Close()

	exec := a2aattack.NewPeerImpersonationExecutor(peerImpersonationRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings on JWT-accepting server, got none")
	}
	if findings[0].Severity != "high" {
		t.Errorf("expected high severity, got %q", findings[0].Severity)
	}
	if findings[0].Confidence != attack.ConfirmedExploit {
		t.Errorf("expected ConfirmedExploit confidence, got %q", findings[0].Confidence)
	}
}

// TestPeerImpersonation_UnauthAllowed verifies a medium-severity finding is
// emitted when the server accepts requests without any authentication.
func TestPeerImpersonation_UnauthAllowed(t *testing.T) {
	ts := unauthAllowedServer(t)
	defer ts.Close()

	exec := a2aattack.NewPeerImpersonationExecutor(peerImpersonationRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings on unauthenticated-allow server, got none")
	}
	if findings[0].Severity != "medium" {
		t.Errorf("expected medium severity, got %q", findings[0].Severity)
	}
	if findings[0].Confidence != attack.ConfirmedExploit {
		t.Errorf("expected ConfirmedExploit confidence, got %q", findings[0].Confidence)
	}
}

// jwtAcceptingRPCErrorServer accepts requests with an Authorization header but
// rejects unauthenticated ones with HTTP 200 carrying a JSON-RPC error envelope
// (rather than a 401/403). This is the false-negative case the broadened
// rejection oracle (!baselineOK) is meant to catch.
func jwtAcceptingRPCErrorServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "agent-card.json") {
			writeJSON(w, map[string]interface{}{"name": "rpc-agent", "version": "1.0"})
			return
		}
		if r.Header.Get("Authorization") == "" {
			// HTTP 200 but a JSON-RPC error => rejection at the protocol layer.
			writeJSON(w, map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      1,
				"error":   map[string]interface{}{"code": -32001, "message": "unauthorized"},
			})
			return
		}
		writeJSON(w, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"result":  map[string]interface{}{"id": "task-003", "status": map[string]interface{}{"state": "completed"}},
		})
	}))
}

// TestPeerImpersonation_ForgedAcceptedRPCErrorBaseline verifies the forged-JWT
// finding still fires when the unauthenticated baseline is rejected via a
// JSON-RPC error envelope instead of an HTTP 401/403.
func TestPeerImpersonation_ForgedAcceptedRPCErrorBaseline(t *testing.T) {
	ts := jwtAcceptingRPCErrorServer(t)
	defer ts.Close()

	exec := a2aattack.NewPeerImpersonationExecutor(peerImpersonationRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected a finding when baseline is rejected via JSON-RPC error, got none")
	}
	if findings[0].Severity != "high" || findings[0].Confidence != attack.ConfirmedExploit {
		t.Errorf("expected high/ConfirmedExploit, got %q/%q", findings[0].Severity, findings[0].Confidence)
	}
}

// TestPeerImpersonation_ProperValidation verifies no finding is emitted when the
// server rejects all tokens (forged or absent), indicating real signature checks.
func TestPeerImpersonation_ProperValidation(t *testing.T) {
	ts := properJWTServer(t)
	defer ts.Close()

	exec := a2aattack.NewPeerImpersonationExecutor(peerImpersonationRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings on secure server, got %d: %v", len(findings), findings)
	}
}

// TestPeerImpersonation_NotA2AServer verifies that against a server that returns
// 404 for all requests (no reachable A2A endpoint) the rule reports inconclusive
// rather than a (misleading) clean result.
func TestPeerImpersonation_NotA2AServer(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	defer ts.Close()

	exec := a2aattack.NewPeerImpersonationExecutor(peerImpersonationRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected ErrInconclusive on non-A2A server, got err=%v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings on non-A2A server, got %d", len(findings))
	}
}
