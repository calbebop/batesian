package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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

// initializeSucceeded is the oracle every session-building call site gates the
// handshake on. It replaced a substring check over the raw body, which accepted
// any 2xx error envelope whose message quotes a field name, so the rules then
// built a session from an error body. The quoting case is the regression that
// motivates the JSON-level read; unlike answersMCPInitialize, no error counts,
// because the question is whether the handshake completed, not whether an MCP
// endpoint answered.
func TestInitializeSucceeded(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{
			name: "completed handshake",
			body: `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"s"}}}`,
			want: true,
		},
		{
			// The defect this oracle replaced: the error message quotes the field
			// names the substring gate matched on.
			name: "error envelope quoting the field names is not a handshake",
			body: `{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"unsupported \"protocolVersion\" value, expected \"serverInfo\" and \"capabilities\""}}`,
			want: false,
		},
		{
			// answersMCPInitialize deliberately counts this; the handshake oracle
			// must not, or a version rejection would open a session.
			name: "version rejection is not a completed handshake",
			body: `{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"Unsupported protocol version"}}`,
			want: false,
		},
		{
			name: "result without a protocolVersion is not a handshake",
			body: `{"jsonrpc":"2.0","id":1,"result":{"serverInfo":{"name":"s"}}}`,
			want: false,
		},
		{
			name: "batch response is not a handshake",
			body: `[{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25"}}]`,
			want: false,
		},
		{
			name: "non-JSON body is not a handshake",
			body: `<html>not json</html>`,
			want: false,
		},
		{
			name: "empty body is not a handshake",
			body: ``,
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := initializeSucceeded([]byte(tc.body)); got != tc.want {
				t.Errorf("initializeSucceeded(%s) = %v, want %v", tc.body, got, tc.want)
			}
		})
	}
}

// This pins the WIRING through initializeMCP, not just the oracle. A unit test
// on initializeSucceeded alone stays green when a call site is reverted to the
// substring gate, so it does not protect the behaviour that matters.
//
// initializeMCP is the shared handshake walk. Pointed at a server that answers
// every candidate with a 2xx error envelope quoting the field names, the old
// gate opened a session whose RawInit was that error body and cached the
// endpoint for the whole scan. Now the walk must fail with the reason
// classifyInitFailure derives from the envelope, and no session may come back.
func TestInitializeMCP_ErrorEnvelopeIsNotASession(t *testing.T) {
	const envelope = `{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"unsupported \"protocolVersion\" value, expected \"serverInfo\" and \"capabilities\""}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(envelope))
	}))
	defer srv.Close()

	client := attack.NewUnauthHTTPClient(attack.Options{TimeoutSeconds: 5}, attack.NewVars(srv.URL, ""))
	session, err := initializeMCP(context.Background(), client, srv.URL)
	if err == nil {
		t.Fatal("initializeMCP must not report success against an error-envelope server")
	}
	if session.Endpoint != "" {
		t.Fatalf("an error envelope must not produce a session; got endpoint %q", session.Endpoint)
	}
	var refusal handshakeRefusal
	if !errors.As(err, &refusal) {
		t.Fatalf("expected a handshakeRefusal naming the refusal, got %v", err)
	}
	if !strings.Contains(refusal.reason, `-32602`) {
		t.Errorf("the refusal should quote the server's own JSON-RPC code, got %q", refusal.reason)
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

// mcpInitBody is a raw JSON template and cannot reference latestStable, so when
// latestStable moved from 2025-06-18 to 2025-11-25 the template was left two
// revisions behind: a strict server then rejected every forged-token initialize as
// "Unsupported protocol version" and the OAuth rules reported clean on a server
// they had not tested (a silent false negative). latestStable has its own guard
// (TestOffersCurrentHandshakeRevision); this one pins the version embedded in the
// template to latestStable so the two cannot drift again.
func TestMcpInitBodyOffersCurrentRevision(t *testing.T) {
	var body struct {
		Params struct {
			ProtocolVersion string `json:"protocolVersion"`
		} `json:"params"`
	}
	if err := json.Unmarshal([]byte(mcpInitBody), &body); err != nil {
		t.Fatalf("mcpInitBody is not valid JSON: %v", err)
	}
	if body.Params.ProtocolVersion != latestStable {
		t.Fatalf("mcpInitBody offers protocolVersion %q; latestStable is %q "+
			"(a stale offered version is rejected by current servers as a silent false negative)",
			body.Params.ProtocolVersion, latestStable)
	}
}
