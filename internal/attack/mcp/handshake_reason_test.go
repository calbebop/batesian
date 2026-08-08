package mcp_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

// "Could not reach a testable endpoint" sends an operator to look at their
// network. That is right when nothing answered, and wrong the rest of the time.
// The most common wrong case is the ordinary one: scanning a server that requires
// a credential without passing one. It answers every request, refuses the
// handshake, and the rule reported it as unreachable.
//
// These tests drive mcp-tools-unauth-001, which reaches the shared handshake
// through runOnEachWire -> openSessions -> inconclusive, the funnel every rule in
// this increment uses.

// toolsUnauthErr returns the error mcp-tools-unauth-001 reports against target.
func toolsUnauthErr(t *testing.T, target string) error {
	t.Helper()
	exec := mcpattack.NewToolsUnauthExecutor(attack.RuleContext{ID: "mcp-tools-unauth-001"})
	_, err := exec.Execute(context.Background(), target, testOpts())
	return err
}

// assertReason fails unless err is ErrInconclusive carrying every want substring.
func assertReason(t *testing.T, err error, want ...string) {
	t.Helper()
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected ErrInconclusive, got %v", err)
	}
	for _, w := range want {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("reason should contain %q; got: %v", w, err)
		}
	}
}

// jsonRPCError writes a JSON-RPC error envelope at the given HTTP status.
func jsonRPCError(w http.ResponseWriter, status, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"jsonrpc": "2.0", "id": 1,
		"error": map[string]interface{}{"code": code, "message": msg},
	})
}

// A credential-gated server answering with an HTTP status. The reason has to name
// the credential, because that is the operator's next action.
func TestHandshakeReason_UnauthorizedByStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	assertReason(t, toolsUnauthErr(t, srv.URL), "HTTP 401", "requires a credential", "--token")
}

// The same refusal as the real SDKs deliver it: a JSON-RPC error at HTTP 200.
// Gating on the status alone would miss every one of them.
func TestHandshakeReason_UnauthorizedByJSONRPCErrorAt200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsonRPCError(w, http.StatusOK, -32000, "authentication required")
	}))
	defer srv.Close()

	assertReason(t, toolsUnauthErr(t, srv.URL),
		"refused as unauthorized", "authentication required", "--token")
}

// Something is listening and it is not MCP. That is a different fact from
// unreachable, and the operator should not go looking at their network for it.
func TestHandshakeReason_AnsweredButNotMCP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsonRPCError(w, http.StatusOK, -32601, "Method not found")
	}))
	defer srv.Close()

	assertReason(t, toolsUnauthErr(t, srv.URL), "does not implement the MCP initialize method")
}

// The candidate walk is the reason a path can 404: the endpoint is unknown, so
// most of those 404s are the cost of looking rather than a fact about the target.
// When every candidate is absent, the generic message is the honest one, and
// naming an arbitrary candidate's 404 would be worse than saying nothing.
func TestHandshakeReason_AllCandidatesAbsentStaysGeneric(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	err := toolsUnauthErr(t, srv.URL)
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected ErrInconclusive, got %v", err)
	}
	if err.Error() != attack.ErrInconclusive.Error() {
		t.Errorf("expected the bare generic reason, got a detail: %v", err)
	}
}

// Nothing answered at all, which is what the generic message was written for.
func TestHandshakeReason_NothingListeningStaysGeneric(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // now nothing is listening on that port

	err := toolsUnauthErr(t, url)
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected ErrInconclusive, got %v", err)
	}
	if err.Error() != attack.ErrInconclusive.Error() {
		t.Errorf("expected the bare generic reason, got a detail: %v", err)
	}
}

// Candidates are walked in a fixed order (/mcp, /, /api, /rpc), so a less
// informative answer from a path the server barely serves can be seen before the
// refusal from the path it does. The reason must be ranked rather than first- or
// last-one-wins, or which message an operator gets depends on where the server
// happens to be mounted.
//
// The earlier candidates answer HTTP 500 with no JSON-RPC error, which is a real
// observation and the lowest rank. A first-one-wins implementation reports that
// and buries the refusal.
func TestHandshakeReason_RefusalOutranksALesserAnswer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		jsonRPCError(w, http.StatusOK, -32000, "authentication required")
	})
	// ServeMux treats "/" as a catch-all, so /mcp lands here too, which is what
	// gives both earlier candidates the lesser answer.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	assertReason(t, toolsUnauthErr(t, srv.URL), "/api", "requires a credential")
}
