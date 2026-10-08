package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
)

// classifyProbe is the seam the unauth family hangs on, so the interesting cases
// are all in what a server can answer with. The gate it replaced treated a
// gateway failure, an auth rejection and an unparseable body identically, which
// let a wide-open server whose listings answered 502 report every surface clean.
func TestClassifyProbe(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   probeVerdict
		why    string
	}{
		{
			name: "2xx with a result", status: 200,
			body: `{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`,
			want: probeAnswered,
			why:  "a valid JSON-RPC result lets the caller interpret the answer",
		},
		{
			name: "2xx with a versionless result", status: 200,
			body: `{"id":1,"result":{"tools":[{"name":"admin"}]}}`,
			want: probeInconclusive,
			why:  "a generic JSON result is not an MCP answer",
		},
		{
			name: "2xx with a missing response id", status: 200,
			body: `{"jsonrpc":"2.0","result":{"tools":[{"name":"admin"}]}}`,
			want: probeInconclusive,
			why:  "an uncorrelated result does not prove the probe was answered",
		},
		{
			name: "2xx with both result and error", status: 200,
			body: `{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":-32603,"message":"Internal error"}}`,
			want: probeInconclusive,
			why:  "a JSON-RPC response cannot contain both result and error",
		},
		{
			name: "2xx with a large number", status: 200,
			body: `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"inputSchema":{"maxProperties":1e400}}]}}`,
			want: probeAnswered,
			why:  "a valid nested JSON number must not make the envelope inconclusive",
		},
		{
			name: "2xx with a JSON-RPC error", status: 200,
			body: `{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"Unauthorized"}}`,
			want: probeAnswered,
			why:  "the caller decides what a 2xx error means; it is still an answer",
		},
		{
			name: "401", status: 401, body: `{"error":"unauthenticated"}`,
			want: probeRejected,
			why:  "auth enforced, so a clean report is correct",
		},
		{
			name: "403 with an empty body", status: 403, body: ``,
			want: probeRejected,
			why:  "an auth status is an answer whatever the body looks like",
		},
		{
			name: "400 carrying an auth error", status: 400,
			body: `{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"Unauthorized"}}`,
			want: probeRejected,
			why:  "some servers signal auth with 400 plus a JSON-RPC error",
		},
		{
			name: "400 carrying method not found", status: 400,
			body: `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}`,
			want: probeRejected,
			why:  "the method is absent, so the surface is closed; this must stay clean, not become untested",
		},
		{
			name: "500 with a large error number", status: 500,
			body: `{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"Internal error","data":{"size":1e400}}}`,
			want: probeRejected,
			why:  "a valid JSON-RPC error remains a protocol-level answer",
		},
		{
			name: "502 with a JSON gateway error", status: 502,
			body: `{"error":"Bad Gateway"}`,
			want: probeInconclusive,
			why:  "a gateway error is not a JSON-RPC rejection",
		},
		{
			name: "500 with an incomplete JSON-RPC error", status: 500,
			body: `{"jsonrpc":"2.0","id":1,"error":{"code":-32603}}`,
			want: probeInconclusive,
			why:  "an error without a message is not a JSON-RPC error response",
		},
		{
			name: "500 with a versionless error", status: 500,
			body: `{"id":1,"error":{"code":-32603,"message":"Internal error"}}`,
			want: probeInconclusive,
			why:  "an unversioned error is not an MCP JSON-RPC response",
		},
		{
			name: "500 with a mismatched error shape", status: 500,
			body: `{"jsonrpc":"2.0","id":1,"error":{"code":"-32603","message":"Internal error"}}`,
			want: probeInconclusive,
			why:  "JSON-RPC error codes must be integers",
		},
		{
			// The case that motivated all of this.
			name: "502 from a gateway", status: 502, body: `Bad Gateway`,
			want: probeInconclusive,
			why:  "a gateway failure says nothing about authorization",
		},
		{
			name: "500 with an HTML body", status: 500, body: `<html><body>oops</body></html>`,
			want: probeInconclusive,
			why:  "a server error is not evidence of a closed surface",
		},
		{
			name: "empty 400", status: 400, body: ``,
			want: probeInconclusive,
			why:  "nothing was said in protocol terms",
		},
		{
			name: "2xx that will not parse", status: 200, body: `{"result":{"tools":[`,
			want: probeInconclusive,
			why:  "a truncated or malformed body establishes nothing; this is what the 1 MB read limit produced",
		},
		{
			name: "2xx with trailing JSON", status: 200, body: `{"result":{}}{"result":{}}`,
			want: probeInconclusive,
			why:  "multiple JSON values are not one response envelope",
		},
		{
			name: "2xx carrying JSON null", status: 200, body: `null`,
			want: probeInconclusive,
			why:  "null unmarshals without error but is not an object the caller can read",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()

			client := attack.NewUnauthHTTPClient(attack.Options{TimeoutSeconds: 5}, attack.NewVars(srv.URL, ""))
			resp, err := client.POST(context.Background(), srv.URL, nil, map[string]interface{}{"jsonrpc": "2.0"})

			got, body := classifyProbe(resp, err)
			if got != tt.want {
				t.Errorf("classifyProbe() = %v, want %v (%s)", got, tt.want, tt.why)
			}
			if tt.want == probeAnswered && body == nil {
				t.Error("an answered probe must hand back the parsed body")
			}
			if tt.want != probeAnswered && body != nil {
				t.Error("only an answered probe may hand back a body")
			}
		})
	}
}

// A transport failure establishes nothing. This is the path a connection reset,
// a timeout or an over-limit body takes.
func TestClassifyProbe_TransportFailure(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close() // closed before use, so the connection fails

	client := attack.NewUnauthHTTPClient(attack.Options{TimeoutSeconds: 5}, attack.NewVars(srv.URL, ""))
	resp, err := client.POST(context.Background(), srv.URL, nil, map[string]interface{}{"jsonrpc": "2.0"})
	if err == nil {
		t.Skip("expected the closed server to fail the request")
	}
	if got, _ := classifyProbe(resp, err); got != probeInconclusive {
		t.Errorf("classifyProbe() = %v, want probeInconclusive for a transport failure", got)
	}
}

func TestClassifyAccess(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   accessVerdict
	}{
		{"result", 200, `{"jsonrpc":"2.0","id":1,"result":{"value":1e400}}`, accessGranted},
		{"null result", 200, `{"jsonrpc":"2.0","id":1,"result":null}`, accessGranted},
		{"versionless result", 200, `{"id":1,"result":{"value":1}}`, accessUndetermined},
		{"missing response id", 200, `{"jsonrpc":"2.0","result":{"value":1}}`, accessUndetermined},
		{"RPC error over HTTP 200", 200, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}`, accessRefused},
		{"malformed RPC error over HTTP 200", 200, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601}}`, accessUndetermined},
		{"error", 500, `{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"Internal error","data":{"value":1e400}}}`, accessRefused},
		{"gateway error", 502, `{"error":"Bad Gateway"}`, accessUndetermined},
		{"incomplete JSON-RPC error", 500, `{"jsonrpc":"2.0","id":1,"error":{"code":-32603}}`, accessUndetermined},
		{"missing response id", 500, `{"jsonrpc":"2.0","error":{"code":-32603,"message":"Internal error"}}`, accessUndetermined},
		{"result and error", 500, `{"jsonrpc":"2.0","id":1,"result":null,"error":{"code":-32603,"message":"Internal error"}}`, accessUndetermined},
		{"auth status", 401, `{"error":"Unauthorized"}`, accessRefused},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := &attack.Response{StatusCode: tc.status, Body: []byte(tc.body)}
			if got := classifyAccess(resp, nil); got != tc.want {
				t.Errorf("classifyAccess() = %d, want %d", got, tc.want)
			}
		})
	}
}
