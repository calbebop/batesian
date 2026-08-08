package mcp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
)

// answersMCPInitialize decides clean-versus-skipped for five rules, so what it
// accepts is load-bearing. It replaced looksJSONRPC, which matched any body
// containing "jsonrpc", "result", "error" or "protocolVersion" and therefore
// accepted every JSON-RPC service in existence as an MCP server.
func TestAnswersMCPInitialize(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{
			// The case that caused the defect: an A2A agent, or any other JSON-RPC
			// service, answers a method it does not implement with -32601 at HTTP 200.
			name: "method not found is not an MCP server",
			body: `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}`,
			want: false,
		},
		{
			name: "completed handshake names the revision",
			body: `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"s"}}}`,
			want: true,
		},
		{
			// A version rejection still means the endpoint speaks MCP; it declined
			// the offered revision. This is why the oracle cannot demand a result.
			name: "version rejection counts",
			body: `{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"Unsupported protocol version"}}`,
			want: true,
		},
		{
			name: "modern reserved error code counts",
			body: `{"jsonrpc":"2.0","id":1,"error":{"code":-32022,"message":"whatever"}}`,
			want: true,
		},
		{
			// A credential-gated MCP server refuses the handshake. Treating that as
			// not-MCP would give every secured server five spurious not-tested
			// entries when the honest answer is that it publishes no OAuth metadata.
			name: "auth rejection counts",
			body: `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"authentication failed for token: "}}`,
			want: true,
		},
		{
			name: "unrelated error does not count",
			body: `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"Bad Request"}}`,
			want: false,
		},
		{
			// looksJSONRPC accepted this. A result of any shape is not a handshake.
			name: "arbitrary result does not count",
			body: `{"jsonrpc":"2.0","id":1,"result":"pong"}`,
			want: false,
		},
		{
			name: "empty body does not count",
			body: ``,
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := answersMCPInitialize([]byte(tc.body)); got != tc.want {
				t.Errorf("answersMCPInitialize(%s) = %v, want %v", tc.body, got, tc.want)
			}
		})
	}
}

// negotiatedVersion falls back to latestStable when the server echoed nothing, so
// it never reports absence. answersMCPInitialize must not be built on it; an
// earlier version of this fix was, and accepted every body as an MCP handshake.
func TestNegotiatedVersion_NeverReportsAbsence(t *testing.T) {
	if got := negotiatedVersion([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32601}}`)); got == "" {
		t.Skip("negotiatedVersion now reports absence; answersMCPInitialize may be simplified")
	}
	if answersMCPInitialize([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32601}}`)) {
		t.Error("answersMCPInitialize must not treat negotiatedVersion's fallback as a handshake")
	}
}

// This pins the WIRING, not just the oracle. A unit test on
// answersMCPInitialize alone stays green when responsiveMCP is reverted to
// looksJSONRPC, so it does not protect the behaviour that matters.
//
// The five OAuth-gated rules use responsiveMCP to decide clean-versus-skipped.
// Pointed at a JSON-RPC service that is not an MCP server, they reported it clean
// with nothing skipped, which claims the OAuth handling is sound about a host that
// speaks no MCP.
func TestOAuthGatedRules_NotMCPServerIsInconclusive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No OAuth metadata anywhere.
		if r.Method == http.MethodGet {
			http.NotFound(w, r)
			return
		}
		// A JSON-RPC service that does not implement initialize: exactly what an
		// A2A agent answers, at HTTP 200.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}`))
	}))
	defer srv.Close()

	rules := map[string]attack.Executor{
		"mcp-oauth-dcr-001":           NewOAuthDCRExecutor(attack.RuleContext{ID: "mcp-oauth-dcr-001"}),
		"mcp-confused-deputy-001":     NewConfusedDeputyExecutor(attack.RuleContext{ID: "mcp-confused-deputy-001"}),
		"mcp-oauth-metadata-ssrf-001": NewOAuthMetadataSSRFExecutor(attack.RuleContext{ID: "mcp-oauth-metadata-ssrf-001"}),
		"mcp-token-replay-001":        NewTokenReplayExecutor(attack.RuleContext{ID: "mcp-token-replay-001"}),
	}
	for id, exec := range rules {
		t.Run(id, func(t *testing.T) {
			findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
			if len(findings) != 0 {
				t.Fatalf("expected no findings, got %d", len(findings))
			}
			if !errors.Is(err, attack.ErrInconclusive) {
				t.Errorf("a server that does not implement MCP must be not-tested, not clean; got err=%v", err)
			}
		})
	}
}
