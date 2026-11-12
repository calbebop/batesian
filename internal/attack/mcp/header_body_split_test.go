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
	return attack.RuleContext{ID: "mcp-header-body-split-001", Name: "MCP Modern Header/Body Mismatch", Severity: "medium", Remediation: "Validate MCP routing headers against the body."}
}

// splitServer models a legacy wire with varying header handling.
func splitServer(mode string) *httptest.Server { return splitServerAt(mode, "2025-06-18") }

// splitServerAt can report a modern version without advertising a modern wire.
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

func TestSplit_LegacyWireCannotEstablishModernHeaderVerdict(t *testing.T) {
	for _, mode := range []string{"split", "strict", "unaware"} {
		t.Run(mode, func(t *testing.T) {
			ts := splitServer(mode)
			defer ts.Close()
			findings, err := mcpattack.NewHeaderBodySplitExecutor(hbsRuleCtx()).Execute(t.Context(), ts.URL, testOpts())
			if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
				t.Fatalf("legacy wire: findings=%+v err=%v", findings, err)
			}
		})
	}
}

func TestSplit_InitializeVersionDoesNotEstablishModernWire(t *testing.T) {
	for _, version := range []string{"2026-07-28", "unknown-future"} {
		t.Run(version, func(t *testing.T) {
			ts := splitServerAt("unaware", version)
			defer ts.Close()

			findings, err := mcpattack.NewHeaderBodySplitExecutor(hbsRuleCtx()).
				Execute(context.Background(), ts.URL, testOpts())
			if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
				t.Fatalf("initialize-only wire must be untested: findings=%+v err=%v", findings, err)
			}
			if !strings.Contains(err.Error(), "2026-07-28") {
				t.Fatalf("skip reason omits required wire: %v", err)
			}
		})
	}
}

func TestSplit_UnawareOnAModernWireReportsIndicators(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		switch req["method"] {
		case "server/discover":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]interface{}{
					"supportedVersions": []string{"2026-07-28"},
					"capabilities":      map[string]interface{}{"tools": map[string]interface{}{}},
				},
			})
		case "tools/list":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]interface{}{"resultType": "complete", "tools": []interface{}{}},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	findings := runSplit(t, ts)
	if len(findings) != 2 {
		t.Fatalf("expected method and version indicators, got %d: %+v", len(findings), findings)
	}
	for _, finding := range findings {
		if finding.Confidence != attack.RiskIndicator || finding.Severity != "medium" {
			t.Fatalf("unexpected risk rating: %+v", finding)
		}
	}
}

// TestSplit_NotMCP: non-MCP server => no finding.
func TestSplit_NotMCP(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	defer ts.Close()

	assertInconclusive(t, mcpattack.NewHeaderBodySplitExecutor(hbsRuleCtx()), ts.URL, attack.Options{TimeoutSeconds: 5})
}

func TestSplit_MethodMismatchOnModernWireIsIndicator(t *testing.T) {
	ts := modernSplitServer(t, "accept", "reject")
	defer ts.Close()

	findings, err := mcpattack.NewHeaderBodySplitExecutor(hbsRuleCtx()).
		Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding on the modern wire, got %d: %+v", len(findings), findings)
	}
	if findings[0].Confidence != attack.RiskIndicator || findings[0].Severity != "medium" {
		t.Errorf("want medium/RiskIndicator, got %q/%q", findings[0].Severity, findings[0].Confidence)
	}
	if !strings.Contains(findings[0].Title, "2026-07-28 wire") {
		t.Errorf("a modern-wire finding should say so: %q", findings[0].Title)
	}
}

func TestSplit_StrictOnTheModernWire(t *testing.T) {
	ts := modernSplitServer(t, "reject", "reject")
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

func TestSplit_VersionHeaderMismatchIsIndicator(t *testing.T) {
	ts := modernSplitServer(t, "reject", "accept")
	defer ts.Close()
	findings, err := mcpattack.NewHeaderBodySplitExecutor(hbsRuleCtx()).Execute(t.Context(), ts.URL, testOpts())
	if err != nil || len(findings) != 1 {
		t.Fatalf("version mismatch: findings=%+v err=%v", findings, err)
	}
	if !strings.Contains(findings[0].Title, "protocol-version") ||
		findings[0].Confidence != attack.RiskIndicator || findings[0].Severity != "medium" {
		t.Fatalf("version mismatch must be an indicator: %+v", findings[0])
	}
}

func TestSplit_VersionHeaderUnsupportedErrorIsIncomplete(t *testing.T) {
	ts := modernSplitServer(t, "reject", "unsupported")
	defer ts.Close()
	findings, err := mcpattack.NewHeaderBodySplitExecutor(hbsRuleCtx()).Execute(t.Context(), ts.URL, testOpts())
	if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("unsupported version is not a header-mismatch verdict: findings=%+v err=%v", findings, err)
	}
}

// modernSplitServer advertises only 2026-07-28 and varies header validation.
func modernSplitServer(t *testing.T, methodMode, versionMode string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		method, _ := body["method"].(string)
		id := body["id"]
		w.Header().Set("Content-Type", "application/json")

		// No legacy wire here: the handshake is refused, so the rule can only
		// reach this server through server/discover.
		if method == "initialize" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"error": map[string]interface{}{"code": -32022, "message": "UnsupportedProtocolVersion"},
			})
			return
		}
		params, _ := body["params"].(map[string]interface{})
		meta, _ := params["_meta"].(map[string]interface{})
		version, _ := meta["io.modelcontextprotocol/protocolVersion"].(string)
		if r.Header.Get("MCP-Protocol-Version") != version {
			switch versionMode {
			case "accept":
				// Continue to expose the version mismatch.
			case "unsupported":
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0", "id": id,
					"error": map[string]interface{}{"code": -32022, "message": "UnsupportedProtocolVersion"},
				})
				return
			default:
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0", "id": id,
					"error": map[string]interface{}{"code": -32020, "message": "HeaderMismatch"},
				})
				return
			}
		}
		if version != "2026-07-28" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"error": map[string]interface{}{"code": -32022, "message": "UnsupportedProtocolVersion"},
			})
			return
		}
		hdr := r.Header.Get("Mcp-Method")
		if hdr == "" || (methodMode == "reject" && hdr != method) {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"error": map[string]interface{}{"code": -32020, "message": "HeaderMismatch"},
			})
			return
		}
		if methodMode == "unanswered" && method == "tools/list" && hdr != method {
			w.WriteHeader(http.StatusBadGateway)
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
