package mcp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

// The Mcp-Name and case-sensitivity dimensions of mcp-header-body-split-001.
//
// The rule covered Mcp-Method only, so a server that validated the method and ignored
// the name passed. The binding makes Mcp-Name REQUIRED for tools/call, resources/read
// and prompts/get, requires its value to match params.name or params.uri, and requires
// a mismatch to earn 400 with -32020. An intermediary gating a dangerous tool or
// resource by name inspects Mcp-Name, so that is the header worth spoofing.
//
// Every probe here asks for a subject that does not exist, which is what keeps the
// dimension read-only: a server that does not validate the header is precisely one
// that would otherwise act on the body, and the rule must never let that be a tool
// call.

// nameSplitServer serves ONLY the 2026-07-28 wire and validates Mcp-Method fully, so
// the method dimension is clean and these tests measure the name dimension alone.
//
//	"validates" reject a missing or mismatched Mcp-Name with -32020
//	"ignores"   enforce presence but not value: the split this dimension catches
//	"absent"    enforce neither, so the dimension has no precondition
//	"nomethod"  answer -32601, so the method is not a surface here
func nameSplitServer(t *testing.T, nameMode string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		method, _ := body["method"].(string)
		params, _ := body["params"].(map[string]interface{})
		id := body["id"]
		w.Header().Set("Content-Type", "application/json")

		rpcErr := func(status, code int, msg string) {
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"error": map[string]interface{}{"code": code, "message": msg},
			})
		}

		// Modern wire only: refuse the handshake so the rule arrives via discovery.
		if r.Header.Get("MCP-Protocol-Version") != "2026-07-28" {
			rpcErr(http.StatusBadRequest, -32022, "UnsupportedProtocolVersion")
			return
		}
		if h := r.Header.Get("Mcp-Method"); h != method {
			rpcErr(http.StatusBadRequest, -32020, "HeaderMismatch: Mcp-Method")
			return
		}

		switch method {
		case "server/discover":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{
					"supportedVersions": []string{"2026-07-28"},
					"capabilities": map[string]interface{}{
						"tools": map[string]interface{}{}, "resources": map[string]interface{}{},
					},
				},
			})
		case "tools/list":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{"tools": []interface{}{map[string]interface{}{"name": "echo"}}},
			})
		case "resources/read", "prompts/get":
			if nameMode == "nomethod" {
				rpcErr(http.StatusOK, -32601, "Method not found")
				return
			}
			subject, _ := params["uri"].(string)
			if subject == "" {
				subject, _ = params["name"].(string)
			}
			hdr := r.Header.Get("Mcp-Name")
			switch nameMode {
			case "validates":
				if hdr != subject {
					rpcErr(http.StatusBadRequest, -32020, "HeaderMismatch: Mcp-Name")
					return
				}
			case "ignores":
				if hdr == "" { // presence enforced, value ignored
					rpcErr(http.StatusBadRequest, -32020, "HeaderMismatch: Mcp-Name missing")
					return
				}
			case "absent":
				// Neither presence nor value is enforced.
			}
			// Dispatched: the subject does not exist, so nothing was executed.
			rpcErr(http.StatusOK, -32002, "Resource not found: "+subject)
		default:
			rpcErr(http.StatusOK, -32601, "Method not found")
		}
	}))
}

func runSplitRule(t *testing.T, ts *httptest.Server) ([]attack.Finding, error) {
	t.Helper()
	return mcpattack.NewHeaderBodySplitExecutor(hbsRuleCtx()).
		Execute(context.Background(), ts.URL, testOpts())
}

// The gap this closes: Mcp-Method is validated perfectly, so the rule reported clean,
// while Mcp-Name is enforced for presence and not for value.
func TestSplit_McpNameValueNotValidated(t *testing.T) {
	ts := nameSplitServer(t, "ignores")
	defer ts.Close()

	findings, err := runSplitRule(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly the Mcp-Name finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != "high" || f.Confidence != attack.ConfirmedExploit {
		t.Errorf("want high/ConfirmedExploit, got %s/%s", f.Severity, f.Confidence)
	}
	if !strings.Contains(f.Title, "Mcp-Name") {
		t.Errorf("the finding should name the header it is about, got %q", f.Title)
	}
	if !strings.Contains(f.Title, "2026-07-28 wire") {
		t.Errorf("a modern-wire finding should be labelled as such, got %q", f.Title)
	}
	// The evidence has to record that the probe was read-only.
	if !strings.Contains(f.Evidence, "deliberately absent, so nothing was executed") {
		t.Errorf("evidence should record that no subject was executed; got:\n%s", f.Evidence)
	}
}

// A server that validates Mcp-Name against the body is clean, and must not be reported
// merely because the rule asked for a subject that does not exist.
func TestSplit_McpNameValidatedIsClean(t *testing.T) {
	ts := nameSplitServer(t, "validates")
	defer ts.Close()

	findings, err := runSplitRule(t, ts)
	if err != nil {
		t.Fatalf("a server validating both headers is a real clean result: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings, got %d: %+v", len(findings), findings)
	}
}

// Presence is not enforced, so a mismatch would prove nothing about value validation.
// Deliberately not a finding: omission is the precondition detector for both
// dimensions, and reporting it here while the Mcp-Method path calls the identical
// observation "not SEP-2243-aware" would be incoherent.
func TestSplit_McpNamePresenceNotEnforcedIsNotAFinding(t *testing.T) {
	ts := nameSplitServer(t, "absent")
	defer ts.Close()

	findings, err := runSplitRule(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("omission is the precondition, not the subject; got %d: %+v", len(findings), findings)
	}
}

// Neither name-bearing method exists, so the dimension has no surface and must fall
// through to the Mcp-Method verdict rather than blocking the rule.
func TestSplit_NoNameBearingMethodStillReportsTheMethodVerdict(t *testing.T) {
	ts := nameSplitServer(t, "nomethod")
	defer ts.Close()

	findings, err := runSplitRule(t, ts)
	if err != nil {
		t.Fatalf("the Mcp-Method dimension tested fine, so this is clean: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings, got %d: %+v", len(findings), findings)
	}
}

// caseFoldServer validates the Mcp-Method value but compares it case-insensitively,
// which the binding forbids: header names are case-insensitive, header VALUES are not.
func caseFoldServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		method, _ := body["method"].(string)
		id := body["id"]
		w.Header().Set("Content-Type", "application/json")

		write := func(result map[string]interface{}) {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id, "result": result,
			})
		}
		rpcErr := func(status, code int, msg string) {
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"error": map[string]interface{}{"code": code, "message": msg},
			})
		}

		if r.Header.Get("MCP-Protocol-Version") != "2026-07-28" {
			rpcErr(http.StatusBadRequest, -32022, "UnsupportedProtocolVersion")
			return
		}
		// The bug under test: compared with EqualFold rather than exactly.
		if !strings.EqualFold(r.Header.Get("Mcp-Method"), method) {
			rpcErr(http.StatusBadRequest, -32020, "HeaderMismatch")
			return
		}
		switch method {
		case "server/discover":
			write(map[string]interface{}{
				"supportedVersions": []string{"2026-07-28"},
				"capabilities":      map[string]interface{}{"tools": map[string]interface{}{}},
			})
		case "tools/list":
			write(map[string]interface{}{"tools": []interface{}{map[string]interface{}{"name": "echo"}}})
		default:
			rpcErr(http.StatusOK, -32601, "Method not found")
		}
	}))
}

// A server that rejects a plain mismatch looks compliant to the first three probes.
// Folding case is the narrower way to get it wrong, and an intermediary matching an
// exact method name is walked past by a different spelling of the same method.
func TestSplit_CaseFoldedMethodValueIsAFinding(t *testing.T) {
	ts := caseFoldServer(t)
	defer ts.Close()

	findings, err := runSplitRule(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected the case-folding finding, got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Title, "case-insensitively") {
		t.Errorf("the finding should say the comparison folded case, got %q", findings[0].Title)
	}
}
