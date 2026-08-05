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

func hbsRuleCtx() attack.RuleContext {
	return attack.RuleContext{ID: "mcp-header-body-split-001", Name: "MCP Header/Body Split", Severity: "high", Remediation: "Validate Mcp-Method."}
}

// splitServer models a Streamable HTTP MCP server. mode selects header handling
// for tools/list (initialize always succeeds):
//   - "split":     requires Mcp-Method presence but ignores its VALUE (vulnerable)
//   - "strict":    rejects missing OR mismatched Mcp-Method with 400/-32020
//   - "unaware":   ignores Mcp-Method entirely (not SEP-2243-aware)
func splitServer(mode string) *httptest.Server { return splitServerAt(mode, "2025-06-18") }

// splitServerAt advertises the given protocol revision, which decides whether
// "ignores Mcp-Method" is expected for that wire or a gap on a wire that requires
// the header.
func splitServerAt(mode, version string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		method, _ := req["method"].(string)
		id := req["id"]
		hdr := r.Header.Get("Mcp-Method")
		w.Header().Set("Content-Type", "application/json")

		writeTools := func() {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{"tools": []interface{}{map[string]interface{}{"name": "echo"}}},
			})
		}
		reject := func() {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"error": map[string]interface{}{"code": -32020, "message": "HeaderMismatch"},
			})
		}

		switch method {
		case "initialize":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{
					"protocolVersion": version,
					"serverInfo":      map[string]interface{}{"name": "split-fixture", "version": "1.0"},
					"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
				},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			switch mode {
			case "unaware":
				writeTools() // ignores header entirely
			case "strict":
				if hdr != method { // missing or mismatched
					reject()
					return
				}
				writeTools()
			default: // split: enforce presence, ignore value
				if hdr == "" {
					reject()
					return
				}
				writeTools()
			}
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
}

func runSplit(t *testing.T, ts *httptest.Server) []attack.Finding {
	t.Helper()
	findings, err := mcpattack.NewHeaderBodySplitExecutor(hbsRuleCtx()).Execute(context.Background(), ts.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return findings
}

// TestSplit_Vulnerable: presence enforced, value ignored => confirmed.
func TestSplit_Vulnerable(t *testing.T) {
	ts := splitServer("split")
	defer ts.Close()

	findings := runSplit(t, ts)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Confidence != attack.ConfirmedExploit || findings[0].Severity != "high" {
		t.Errorf("want high/ConfirmedExploit, got %q/%q", findings[0].Severity, findings[0].Confidence)
	}
	if !strings.Contains(findings[0].Title, "SEP-2243") {
		t.Errorf("expected SEP-2243 in title, got %q", findings[0].Title)
	}
}

// TestSplit_Strict: rejects mismatch => secure, no finding.
func TestSplit_Strict(t *testing.T) {
	ts := splitServer("strict")
	defer ts.Close()

	if findings := runSplit(t, ts); len(findings) != 0 {
		t.Errorf("expected zero findings against a strict server, got %d: %+v", len(findings), findings)
	}
}

// TestSplit_UnawareOnALegacyWireIsNotTested: a server that ignores Mcp-Method on a
// pre-2026-07-28 wire has no requirement to violate, so the rule stops at its
// first probe having tested nothing.
//
// This used to report clean, which asserted header/body consistency about a
// server that was never asked, on every scan of every legacy target. Since
// SEP-2243 arrived in 2026-07-28 and these rules negotiate an earlier revision,
// that was the outcome for every server in practice.
func TestSplit_UnawareOnALegacyWireIsNotTested(t *testing.T) {
	ts := splitServer("unaware")
	defer ts.Close()

	findings, err := mcpattack.NewHeaderBodySplitExecutor(hbsRuleCtx()).
		Execute(context.Background(), ts.URL, testOpts())
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected ErrInconclusive on a legacy wire, got err=%v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings, got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(err.Error(), "2026-07-28") {
		t.Errorf("skip reason should name the revision that introduced the requirement, got %q", err)
	}
}

// On a wire that does carry the requirement, a server ignoring the header is a
// real observation rather than an untested one. It is still not this rule's
// subject, which is the mismatch, so the result is clean and not a finding.
func TestSplit_UnawareOnAModernWireIsClean(t *testing.T) {
	ts := splitServerAt("unaware", "2026-07-28")
	defer ts.Close()

	if findings := runSplit(t, ts); len(findings) != 0 {
		t.Errorf("expected zero findings, got %d: %+v", len(findings), findings)
	}
}

// TestSplit_NotMCP: non-MCP server => no finding.
func TestSplit_NotMCP(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	defer ts.Close()

	assertInconclusive(t, mcpattack.NewHeaderBodySplitExecutor(hbsRuleCtx()), ts.URL, attack.Options{TimeoutSeconds: 5})
}

// The case this rule was written for and could never reach until the modern
// transport existed: a server whose 2026-07-28 wire enforces Mcp-Method presence
// but not its value. Until now the rule opened a 2025-era session, where the
// requirement does not exist, and stopped at its first probe.
func TestSplit_VulnerableOnTheModernWire(t *testing.T) {
	ts := modernSplitServer(t, false)
	defer ts.Close()

	findings, err := mcpattack.NewHeaderBodySplitExecutor(hbsRuleCtx()).
		Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding on the modern wire, got %d: %+v", len(findings), findings)
	}
	if findings[0].Confidence != attack.ConfirmedExploit || findings[0].Severity != "high" {
		t.Errorf("want high/ConfirmedExploit, got %q/%q", findings[0].Severity, findings[0].Confidence)
	}
	if !strings.Contains(findings[0].Title, "2026-07-28 wire") {
		t.Errorf("a modern-wire finding should say so: %q", findings[0].Title)
	}
}

// A modern wire that validates the value is secure, and must stay silent.
func TestSplit_StrictOnTheModernWire(t *testing.T) {
	ts := modernSplitServer(t, true)
	defer ts.Close()

	findings, err := mcpattack.NewHeaderBodySplitExecutor(hbsRuleCtx()).
		Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings against a strict modern server, got %d: %+v", len(findings), findings)
	}
}

// modernSplitServer serves only the 2026-07-28 wire. It always rejects a missing
// Mcp-Method, as the SDK does; strict decides whether it also rejects a mismatched
// one, which is the difference between secure and the split-brain.
func modernSplitServer(t *testing.T, strict bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		method, _ := body["method"].(string)
		id := body["id"]
		w.Header().Set("Content-Type", "application/json")

		// No legacy wire here: the handshake is refused, so the rule can only
		// reach this server through server/discover.
		if r.Header.Get("MCP-Protocol-Version") != "2026-07-28" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"error": map[string]interface{}{"code": -32022, "message": "UnsupportedProtocolVersion"},
			})
			return
		}
		hdr := r.Header.Get("Mcp-Method")
		if hdr == "" || (strict && hdr != method) {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"error": map[string]interface{}{"code": -32020, "message": "HeaderMismatch"},
			})
			return
		}
		result := map[string]interface{}{"cacheScope": "private", "resultType": "complete"}
		switch method {
		case "server/discover":
			result["supportedVersions"] = []string{"2026-07-28"}
			result["capabilities"] = map[string]interface{}{"tools": map[string]interface{}{}}
		case "tools/list":
			result["tools"] = []interface{}{map[string]interface{}{"name": "echo"}}
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": id, "result": result,
		})
	}))
}
