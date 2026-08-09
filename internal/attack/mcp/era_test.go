package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
)

// eraServer returns a server that answers every request with the given status
// and body, which is all era detection needs to classify it.
func eraServer(status int, body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

func detect(t *testing.T, srv *httptest.Server) Era {
	t.Helper()
	opts := attack.Options{TimeoutSeconds: 5}
	client := attack.NewUnauthHTTPClient(opts, attack.NewVars(srv.URL, ""))
	return detectEra(context.Background(), client, srv.URL)
}

func TestDetectEra(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   Era
		why    string
	}{
		{
			name:   "discover result",
			status: 200,
			body:   `{"jsonrpc":"2.0","id":"x","result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{}}}`,
			want:   EraModern,
			why:    "a DiscoverResult can only come from a server implementing the modern discovery RPC",
		},
		{
			name:   "unsupported protocol version",
			status: 400,
			body:   `{"jsonrpc":"2.0","id":1,"error":{"code":-32022,"message":"Unsupported protocol version","data":{"supported":["2026-07-28"]}}}`,
			want:   EraModern,
			why:    "-32022 is spec-reserved, so only a modern server emits it",
		},
		{
			name:   "header mismatch",
			status: 400,
			body:   `{"jsonrpc":"2.0","id":1,"error":{"code":-32020,"message":"Header mismatch"}}`,
			want:   EraModern,
			why:    "-32020 is spec-reserved",
		},
		{
			name:   "missing required client capability",
			status: 400,
			body:   `{"jsonrpc":"2.0","id":1,"error":{"code":-32021,"message":"Missing capability"}}`,
			want:   EraModern,
			why:    "-32021 is spec-reserved",
		},
		{
			name:   "unallocated code inside the reserved range",
			status: 400,
			body:   `{"jsonrpc":"2.0","id":1,"error":{"code":-32050,"message":"Some future spec error"}}`,
			want:   EraModern,
			why:    "detection keys on the reserved range, so a future spec-defined code still reads as modern",
		},
		{
			// The case that matters most. The reference server answers a modern
			// probe with exactly this. A naive "400 plus a JSON-RPC error means
			// modern" check would misclassify every legacy server in the wild.
			name:   "legacy implementation-defined error",
			status: 400,
			body:   `{"jsonrpc":"2.0","error":{"code":-32000,"message":"Bad Request: Server not initialized"},"id":null}`,
			want:   EraLegacy,
			why:    "-32000 is implementation-defined and carries no era meaning",
		},
		{
			name:   "method not found",
			status: 404,
			body:   `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}`,
			want:   EraLegacy,
			why:    "-32601 is a standard JSON-RPC code, not a modern signal",
		},
		{
			name:   "method not allowed with no body",
			status: 405,
			body:   ``,
			want:   EraLegacy,
			why:    "something answered but said nothing modern",
		},
		{
			name:   "empty 400 body",
			status: 400,
			body:   ``,
			want:   EraLegacy,
			why:    "the spec directs a fallback when the body is empty",
		},
		{
			name:   "html error page",
			status: 400,
			body:   `<html><body>Bad Request</body></html>`,
			want:   EraLegacy,
			why:    "a non-JSON body is not a modern error",
		},
		{
			name:   "2xx that is not a result envelope",
			status: 200,
			body:   `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"nope"}}`,
			want:   EraLegacy,
			why:    "a 2xx carrying a legacy error is not a DiscoverResult",
		},
		{
			// The shape a handshake-only server built on the Go SDK returns. It
			// answers discovery, as every server must, and names only the eras it
			// actually serves. Reading the answer itself as modern classified it
			// as a wire it rejects with HTTP 400.
			name:   "discover result advertising only handshake-era versions",
			status: 200,
			body:   `{"jsonrpc":"2.0","id":"x","result":{"resultType":"complete","supportedVersions":["2025-11-25","2025-06-18","2024-11-05"],"capabilities":{}}}`,
			want:   EraLegacy,
			why:    "the server names the versions it serves and the modern revision is not among them",
		},
		{
			name:   "discover result carrying no supportedVersions",
			status: 200,
			body:   `{"jsonrpc":"2.0","id":"x","result":{"resultType":"complete","capabilities":{}}}`,
			want:   EraLegacy,
			why:    "supportedVersions is required on a DiscoverResult, so a reply without it is not one",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := eraServer(tt.status, tt.body)
			defer srv.Close()

			if got := detect(t, srv); got != tt.want {
				t.Errorf("detectEra() = %v, want %v (%s)", got, tt.want, tt.why)
			}
		})
	}
}

// TestDetectEra_Unreachable: nothing answered, so no era can be determined.
func TestDetectEra_Unreachable(t *testing.T) {
	srv := eraServer(200, `{}`)
	srv.Close() // closed before use, so the connection fails

	if got := detect(t, srv); got != EraUnknown {
		t.Errorf("detectEra() = %v, want %v for an unreachable target", got, EraUnknown)
	}
}

// TestDetectEra_SendsRequiredModernFields verifies the probe is a fair test of
// the server: a modern server rejects a request missing the required headers or
// _meta fields, so a probe that omitted them would provoke a modern error and
// "detect" modernity that was never demonstrated.
func TestDetectEra_SendsRequiredModernFields(t *testing.T) {
	var gotProtoHeader, gotMethodHeader string
	var gotBody map[string]interface{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotProtoHeader = r.Header.Get("MCP-Protocol-Version")
		gotMethodHeader = r.Header.Get("Mcp-Method")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(404)
	}))
	defer srv.Close()

	_ = detect(t, srv)

	if gotProtoHeader != modernEraVersion {
		t.Errorf("MCP-Protocol-Version header = %q, want %q", gotProtoHeader, modernEraVersion)
	}
	if gotMethodHeader != "server/discover" {
		t.Errorf("Mcp-Method header = %q, want %q", gotMethodHeader, "server/discover")
	}
	if method, _ := gotBody["method"].(string); method != "server/discover" {
		t.Errorf("body method = %q, want server/discover", method)
	}

	params, _ := gotBody["params"].(map[string]interface{})
	meta, _ := params["_meta"].(map[string]interface{})
	if meta == nil {
		t.Fatalf("request carried no _meta; a modern server requires it")
	}
	if v, _ := meta[metaProtocolVersion].(string); v != modernEraVersion {
		t.Errorf("_meta[%s] = %q, want %q", metaProtocolVersion, v, modernEraVersion)
	}
	// clientCapabilities is REQUIRED on every modern request, so it must be
	// present even though this probe needs no capability.
	if _, ok := meta[metaClientCapabilities]; !ok {
		t.Errorf("_meta is missing the required %s", metaClientCapabilities)
	}
	// The header value must match the body value, or a modern server answers
	// -32020 HeaderMismatch and the probe measures our own bug.
	if bodyVer, _ := meta[metaProtocolVersion].(string); gotProtoHeader != bodyVer {
		t.Errorf("header/body protocol version mismatch: %q vs %q", gotProtoHeader, bodyVer)
	}
}

// TestIsModernError covers the reserved-range boundaries directly.
func TestIsModernError(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{"lower boundary -32020", `{"error":{"code":-32020}}`, true},
		{"upper boundary -32099", `{"error":{"code":-32099}}`, true},
		{"just outside, legacy side", `{"error":{"code":-32019}}`, false},
		{"just outside, below range", `{"error":{"code":-32100}}`, false},
		{"legacy -32000", `{"error":{"code":-32000}}`, false},
		{"standard method not found", `{"error":{"code":-32601}}`, false},
		{"result envelope, no error", `{"result":{}}`, false},
		{"error without a code", `{"error":{"message":"x"}}`, false},
		{"not json", `nope`, false},
		{"empty", ``, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isModernError([]byte(tt.body)); got != tt.want {
				t.Errorf("isModernError(%s) = %v, want %v", tt.body, got, tt.want)
			}
		})
	}
}

// TestModernWireAdvertised covers the discriminator directly, because both
// detectEra and discoverModern rest on it and the interesting cases are all in
// how a DiscoverResult is shaped rather than in the HTTP exchange around it.
func TestModernWireAdvertised(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{"modern only", `{"result":{"supportedVersions":["2026-07-28"],"capabilities":{}}}`, true},
		{"modern among others", `{"result":{"supportedVersions":["2026-07-28","2025-11-25"],"capabilities":{}}}`, true},
		{"modern last", `{"result":{"supportedVersions":["2025-06-18","2026-07-28"],"capabilities":{}}}`, true},
		{"handshake eras only", `{"result":{"supportedVersions":["2025-11-25","2024-11-05"],"capabilities":{}}}`, false},
		{"empty list", `{"result":{"supportedVersions":[],"capabilities":{}}}`, false},
		{"field absent", `{"result":{"capabilities":{},"resultType":"complete"}}`, false},
		{"no result object", `{"jsonrpc":"2.0","id":1,"error":{"code":-32601}}`, false},
		// The version must be read from result.supportedVersions and nowhere
		// else: a server may mention the revision in instructions or _meta
		// without serving it, and a substring match would take that as proof.
		{"version named outside supportedVersions", `{"result":{"supportedVersions":["2025-11-25"],"instructions":"upgrading to 2026-07-28 soon","capabilities":{}}}`, false},
		{"not json", `Bad Request: protocol version "2026-07-28" is only supported on stateless HTTP servers`, false},
		{"empty", ``, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := modernWireAdvertised([]byte(tt.body)); got != tt.want {
				t.Errorf("modernWireAdvertised(%s) = %v, want %v", tt.body, got, tt.want)
			}
		})
	}
}

// TestSpecDefinedModernErrorsAreDetected guards the seam between the named
// codes the specification defines and the range detection actually keys on. If
// a named code fell outside the range, a modern server that identified itself
// with that code would be misread as legacy.
func TestSpecDefinedModernErrorsAreDetected(t *testing.T) {
	for name, code := range specDefinedModernErrors {
		body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"error":{"code":%d,"message":%q}}`, code, name)
		if !isModernError([]byte(body)) {
			t.Errorf("%s (%d) is defined by the specification but is not detected as a modern error", name, code)
		}
		if code < modernErrCodeMin || code > modernErrCodeMax {
			t.Errorf("%s (%d) falls outside the reserved range [%d, %d]", name, code, modernErrCodeMin, modernErrCodeMax)
		}
	}
}

// TestEraString keeps the human-facing labels stable, since they appear in the
// operator-visible skip message.
func TestEraString(t *testing.T) {
	for era, want := range map[Era]string{EraUnknown: "unknown", EraLegacy: "legacy", EraModern: "modern"} {
		if got := era.String(); got != want {
			t.Errorf("Era(%d).String() = %q, want %q", era, got, want)
		}
	}
}

// TestInconclusive verifies a modern-era failure carries its reason forward
// while a plain failure stays generic, and that both remain ErrInconclusive so
// the engine records them as skipped rather than clean.
func TestInconclusive(t *testing.T) {
	modernErr := fmt.Errorf("%w: http://x/mcp speaks MCP %s (stateless era), which these rules do not yet support",
		errModernEra, modernEraVersion)
	got := inconclusive(modernErr)
	if !strings.Contains(got.Error(), modernEraVersion) {
		t.Errorf("modern-era inconclusive lost its detail: %v", got)
	}
	if !errors.Is(got, attack.ErrInconclusive) {
		t.Errorf("modern-era error must still be ErrInconclusive, got %v", got)
	}

	plain := inconclusive(errors.New("no MCP server found"))
	if plain.Error() != attack.ErrInconclusive.Error() {
		t.Errorf("plain inconclusive should stay generic, got %q", plain.Error())
	}
	if !errors.Is(plain, attack.ErrInconclusive) {
		t.Errorf("plain error must be ErrInconclusive, got %v", plain)
	}
}

// The era probe must send exactly what a modern session sends.
//
// It used to build the MCP-Protocol-Version and Mcp-Method headers and the whole
// mandatory _meta block by hand, duplicating request(). Two copies of a wire format
// drift, and this is the worst place for it: a request the server rejects as
// malformed reads as "not a modern server", and every modern-wire rule then skips a
// target it should have tested. So the probe goes through a session, and this pins
// that its request is byte-identical to one.
//
// The field-level assertions are in TestDetectEra_SendsRequiredModernFields; this
// one is only about the two sides agreeing.
func TestDetectEra_ProbeMatchesAModernSessionRequest(t *testing.T) {
	var gotHeaders http.Header
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"batesian-era-probe","result":{}}`))
	}))
	defer srv.Close()

	if era := detect(t, srv); era != EraLegacy {
		t.Fatalf("a result that advertises no modern version is legacy, got %v", era)
	}

	// What a modern session would have sent for the same call.
	want := mcpSession{Endpoint: srv.URL, Era: EraModern}
	wantHeaders, wantBody := want.request("batesian-era-probe", "server/discover", nil)

	for k, v := range wantHeaders {
		if got := gotHeaders.Get(k); got != v {
			t.Errorf("header %s: probe sent %q, a modern session sends %q", k, got, v)
		}
	}

	wantJSON, err := json.Marshal(wantBody)
	if err != nil {
		t.Fatalf("marshalling the reference body: %v", err)
	}
	// Compared as decoded values, since map key order in the encoded form is not
	// part of the contract.
	var gotAny, wantAny interface{}
	if err := json.Unmarshal(gotBody, &gotAny); err != nil {
		t.Fatalf("probe body is not JSON: %v", err)
	}
	if err := json.Unmarshal(wantJSON, &wantAny); err != nil {
		t.Fatalf("reference body is not JSON: %v", err)
	}
	if !reflect.DeepEqual(gotAny, wantAny) {
		t.Errorf("the era probe and a modern session disagree on the request body.\nprobe: %s\nsession: %s",
			gotBody, wantJSON)
	}
}
