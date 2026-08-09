package mcp_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

// The 2026-07-28 wire for the four unauthenticated-access rules.
//
// They were ported to run on each wire a server serves, but every one of their own
// test files drives a legacy-only server, so the modern half of that port was
// exercised only indirectly by the shared wire tests. These are the cases the port
// exists for, asserted per rule.
//
// The one that matters is the asymmetry: a server that enforces authorization on one
// wire and not the other. Nothing about the two wires forces them to be gated alike,
// and a rule that probed only the wire that is gated reports the server clean.

// unauthWireServer serves either wire, or both, and gates each independently.
//
// legacy/modern select which wires exist. legacyGated/modernGated select whether that
// wire refuses the listing and completion methods with an auth error. The capabilities
// advertised on each wire are also selectable, since a surface a server exposes on
// only one wire must be probed only there.
type unauthWireServer struct {
	legacy, modern           bool
	legacyGated, modernGated bool
	// When set, the capabilities advertised on that wire; otherwise all four.
	legacyCaps, modernCaps []string
}

const authErrCode = -32001

func (s unauthWireServer) capsFor(modern bool) map[string]interface{} {
	names := s.legacyCaps
	if modern {
		names = s.modernCaps
	}
	if names == nil {
		names = []string{"tools", "resources", "prompts", "completions"}
	}
	caps := map[string]interface{}{}
	for _, n := range names {
		caps[n] = map[string]interface{}{}
	}
	return caps
}

func (s unauthWireServer) start(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		method, _ := body["method"].(string)
		id := body["id"]

		isModern := r.Header.Get("MCP-Protocol-Version") == "2026-07-28"
		gated := s.legacyGated
		if isModern {
			gated = s.modernGated
		}

		w.Header().Set("Content-Type", "application/json")
		rpcErr := func(status, code int, msg string) {
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"error": map[string]interface{}{"code": code, "message": msg},
			})
		}
		result := func(v map[string]interface{}) {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id, "result": v,
			})
		}

		switch method {
		case "server/discover":
			if !s.modern {
				rpcErr(http.StatusBadRequest, -32022, "UnsupportedProtocolVersion")
				return
			}
			result(map[string]interface{}{
				"supportedVersions": []string{"2026-07-28"},
				"capabilities":      s.capsFor(true),
				"serverInfo":        map[string]interface{}{"name": "unauth-wire", "version": "1.0"},
			})
			return
		case "initialize":
			if !s.legacy {
				rpcErr(http.StatusBadRequest, -32022, "UnsupportedProtocolVersion")
				return
			}
			result(map[string]interface{}{
				"protocolVersion": "2025-11-25",
				"capabilities":    s.capsFor(false),
				"serverInfo":      map[string]interface{}{"name": "unauth-wire", "version": "1.0"},
			})
			return
		}
		if strings.HasPrefix(method, "notifications/") {
			w.WriteHeader(http.StatusAccepted)
			return
		}

		if gated {
			rpcErr(http.StatusOK, authErrCode, "Unauthorized")
			return
		}

		switch method {
		case "tools/list":
			result(map[string]interface{}{"tools": []interface{}{
				map[string]interface{}{"name": "echo", "description": "Echo input"},
				map[string]interface{}{"name": "run_query", "description": "Run a database query"},
			}})
		case "resources/list":
			result(map[string]interface{}{"resources": []interface{}{
				map[string]interface{}{"uri": "file:///etc/passwd", "name": "passwd"},
			}})
		case "resources/read":
			result(map[string]interface{}{"contents": []interface{}{
				map[string]interface{}{"uri": "file:///etc/passwd", "text": "root:x:0:0:"},
			}})
		case "prompts/list":
			result(map[string]interface{}{"prompts": []interface{}{
				map[string]interface{}{"name": "summarize", "description": "Summarize text"},
			}})
		case "prompts/get":
			result(map[string]interface{}{"messages": []interface{}{
				map[string]interface{}{"role": "user", "content": map[string]interface{}{
					"type": "text", "text": "internal prompt body",
				}},
			}})
		case "completion/complete":
			result(map[string]interface{}{"completion": map[string]interface{}{
				"values": []interface{}{"alpha", "beta"},
			}})
		default:
			rpcErr(http.StatusOK, -32601, "Method not found")
		}
	}))
}

// unauthRules is the four rules ported in the both-wires change, each with the
// capability its surface is gated on.
var unauthRules = []struct {
	name string
	cap  string
	exec func() attack.Executor
}{
	{"tools", "tools", func() attack.Executor {
		return mcpattack.NewToolsUnauthExecutor(attack.RuleContext{ID: "mcp-tools-unauth-001", Severity: "high"})
	}},
	{"resources", "resources", func() attack.Executor {
		return mcpattack.NewResourcesUnauthExecutor(attack.RuleContext{ID: "mcp-resources-unauth-001", Severity: "high"})
	}},
	{"prompts", "prompts", func() attack.Executor {
		return mcpattack.NewPromptUnauthExecutor(attack.RuleContext{ID: "mcp-prompt-unauth-001", Severity: "medium"})
	}},
	{"completions", "completions", func() attack.Executor {
		return mcpattack.NewCompletionUnauthExecutor(attack.RuleContext{ID: "mcp-completion-unauth-001", Severity: "high"})
	}},
}

// A modern-only server with the surface wide open. Each rule must fire and label the
// wire, since before the port none of them could reach a server with no initialize.
func TestUnauthWires_ModernOnlyOpen(t *testing.T) {
	for _, rule := range unauthRules {
		t.Run(rule.name, func(t *testing.T) {
			ts := unauthWireServer{modern: true}.start(t)
			defer ts.Close()

			findings, err := rule.exec().Execute(t.Context(), ts.URL, testOpts())
			if err != nil {
				t.Fatalf("a modern-only server is testable: %v", err)
			}
			if len(findings) == 0 {
				t.Fatal("an open surface on the modern wire must be reported")
			}
			for _, f := range findings {
				if !strings.Contains(f.Title, "2026-07-28 wire") {
					t.Errorf("a modern-wire finding must be labelled as such, got %q", f.Title)
				}
				if !strings.Contains(f.Evidence, "2026-07-28") {
					t.Errorf("evidence should name the wire; got:\n%s", f.Evidence)
				}
			}
		})
	}
}

// The asymmetry the port exists for: authorization enforced on the handshake wire and
// not on the modern one. Probing only the gated wire reports this server clean.
func TestUnauthWires_LegacyGatedModernOpen(t *testing.T) {
	for _, rule := range unauthRules {
		t.Run(rule.name, func(t *testing.T) {
			ts := unauthWireServer{legacy: true, modern: true, legacyGated: true}.start(t)
			defer ts.Close()

			findings, err := rule.exec().Execute(t.Context(), ts.URL, testOpts())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(findings) == 0 {
				t.Fatal("the modern wire is open and must be reported even though the legacy one is gated")
			}
			for _, f := range findings {
				if !strings.Contains(f.Title, "2026-07-28 wire") {
					t.Errorf("only the modern wire is open here, so every finding must name it: %q", f.Title)
				}
			}
		})
	}
}

// The reverse, so the test above is not passing because the rules only look at the
// modern wire.
func TestUnauthWires_ModernGatedLegacyOpen(t *testing.T) {
	for _, rule := range unauthRules {
		t.Run(rule.name, func(t *testing.T) {
			ts := unauthWireServer{legacy: true, modern: true, modernGated: true}.start(t)
			defer ts.Close()

			findings, err := rule.exec().Execute(t.Context(), ts.URL, testOpts())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(findings) == 0 {
				t.Fatal("the legacy wire is open and must be reported")
			}
			for _, f := range findings {
				if strings.Contains(f.Title, "2026-07-28 wire") {
					t.Errorf("only the legacy wire is open here, so no finding may be labelled "+
						"modern: %q", f.Title)
				}
			}
		})
	}
}

// Both wires gated is a real clean result, not a skip: both were opened and both
// refused.
func TestUnauthWires_BothGatedIsClean(t *testing.T) {
	for _, rule := range unauthRules {
		t.Run(rule.name, func(t *testing.T) {
			ts := unauthWireServer{
				legacy: true, modern: true, legacyGated: true, modernGated: true,
			}.start(t)
			defer ts.Close()

			findings, err := rule.exec().Execute(t.Context(), ts.URL, testOpts())
			if err != nil {
				t.Fatalf("a server that enforces authorization on both wires is a clean result: %v", err)
			}
			if len(findings) != 0 {
				t.Errorf("expected zero findings, got %d: %+v", len(findings), findings)
			}
		})
	}
}

// For the three rules that gate on a capability, the gate is read per wire. A rule
// must not carry one wire's capabilities across to the other: the surface would be
// probed where the server does not expose it, and the -32601 that comes back is not
// evidence about authorization.
//
// mcp-resources-unauth-001 is deliberately absent, and TestUnauthWires_ResourcesDoNotGate
// below is why.
func TestUnauthWires_CapabilityIsPerWire(t *testing.T) {
	for _, rule := range unauthRules {
		if rule.name == "resources" {
			continue
		}
		t.Run(rule.name, func(t *testing.T) {
			// The surface is advertised on the legacy wire only, and BOTH wires would
			// answer it if asked. Any modern-labelled finding means the rule probed a
			// capability that wire never advertised.
			ts := unauthWireServer{
				legacy: true, modern: true,
				legacyCaps: []string{rule.cap},
				modernCaps: []string{},
			}.start(t)
			defer ts.Close()

			findings, err := rule.exec().Execute(t.Context(), ts.URL, testOpts())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(findings) == 0 {
				t.Fatal("the legacy wire advertises the surface and is open, so it must be reported")
			}
			for _, f := range findings {
				if strings.Contains(f.Title, "2026-07-28 wire") {
					t.Errorf("the modern wire advertises no capability, so it must not be probed: %q",
						f.Title)
				}
			}
		})
	}
}

// mcp-resources-unauth-001 probes regardless of what was advertised, on either wire,
// and that is the right behaviour rather than an oversight.
//
// A non-empty resources/list answered without a credential is direct evidence of the
// disclosure. What the server advertised is not evidence about what it serves, so
// gating on the advertisement would drop exactly the case below: a wire that lists
// resources it never declared. The other three probe a second, state-touching method
// (tools/call, prompts/get, completion/complete) and gate to avoid calling a surface
// the server does not implement, which is a different trade.
//
// Written after this test caught the discrepancy: the docs claimed all four gate per
// wire, which was never true of this one.
func TestUnauthWires_ResourcesDoNotGate(t *testing.T) {
	ts := unauthWireServer{
		modern: true,
		// Declares nothing at all, and serves resources anyway.
		modernCaps: []string{},
	}.start(t)
	defer ts.Close()

	exec := mcpattack.NewResourcesUnauthExecutor(
		attack.RuleContext{ID: "mcp-resources-unauth-001", Severity: "high"})
	findings, err := exec.Execute(t.Context(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("a wire that lists resources it never advertised is still disclosing them")
	}
	for _, f := range findings {
		if !strings.Contains(f.Title, "2026-07-28 wire") {
			t.Errorf("the finding is on the modern wire and should say so: %q", f.Title)
		}
	}
}
