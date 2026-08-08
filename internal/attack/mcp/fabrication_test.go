package mcp_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

// dualEraServer serves both wires. legacyList controls how the LEGACY wire answers
// tools/list; the modern wire always answers with a result. Nothing is ever
// authorization-checked, so no wire-gating asymmetry exists to report.
func dualEraServer(t *testing.T, legacyList func(w http.ResponseWriter)) *httptest.Server {
	t.Helper()
	caps := map[string]interface{}{"tools": map[string]interface{}{}}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		method, _ := req["method"].(string)
		id := req["id"]
		modern := r.Header.Get("Mcp-Protocol-Version") == "2026-07-28" ||
			strings.Contains(r.Header.Get("Mcp-Method"), "server/discover") ||
			method == "server/discover"
		w.Header().Set("Content-Type", "application/json")
		result := func(v interface{}) {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": id, "result": v})
		}

		switch method {
		case "server/discover":
			result(map[string]interface{}{
				"supportedVersions": []string{"2025-06-18", "2026-07-28"},
				"capabilities":      caps,
				"serverInfo":        map[string]interface{}{"name": "dual", "version": "1"},
			})
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "dual-session")
			result(map[string]interface{}{
				"protocolVersion": "2025-06-18",
				"serverInfo":      map[string]interface{}{"name": "dual", "version": "1"},
				"capabilities":    caps,
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			if modern {
				result(map[string]interface{}{"tools": []interface{}{map[string]interface{}{"name": "echo"}}})
				return
			}
			legacyList(w)
		default:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": id,
				"error": map[string]interface{}{"code": -32601, "message": "Method not found"}})
		}
	}))
}

// A bare 202 is permitted on the legacy wire: the transport lets a server deliver
// the POST response over the GET stream instead. It is not a refusal.
//
// granted was derived from IsAccepted and everything else counted as refused, so
// this looked like a wire that gated an unauthenticated call while the stateless
// wire answered it, and the rule emitted critical/ConfirmedExploit "authorization
// enforced on the legacy wire but not the modern wire" against a server that
// enforces nothing at all.
func TestEraDowngrade_UndeterminedWireIsNotARefusal(t *testing.T) {
	cases := map[string]func(w http.ResponseWriter){
		"bare 202 accepted":  func(w http.ResponseWriter) { w.WriteHeader(http.StatusAccepted) },
		"429 from a limiter": func(w http.ResponseWriter) { w.WriteHeader(http.StatusTooManyRequests) },
		"502 from a gateway": func(w http.ResponseWriter) { w.WriteHeader(http.StatusBadGateway) },
	}
	for name, legacyList := range cases {
		t.Run(name, func(t *testing.T) {
			srv := dualEraServer(t, legacyList)
			defer srv.Close()

			exec := mcpattack.NewEraDowngradeExecutor(attack.RuleContext{ID: "mcp-era-downgrade-001"})
			findings, err := exec.Execute(context.Background(), srv.URL, testOpts())
			if len(findings) > 0 {
				t.Errorf("FABRICATED: %s is not a refusal, got %q", name, findings[0].Title)
			}
			if !errors.Is(err, attack.ErrInconclusive) {
				t.Errorf("a wire that did not answer must be inconclusive, got err=%v", err)
			}
		})
	}
}

// hbsServer serves one legacy wire whose tools/list answers per the shape function,
// so the header-presence probe can be driven independently of the others.
func hbsServer(t *testing.T, list func(w http.ResponseWriter, hasMethodHeader bool)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		method, _ := req["method"].(string)
		id := req["id"]
		w.Header().Set("Content-Type", "application/json")
		switch method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "hbs")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{
					"protocolVersion": "2025-06-18",
					"serverInfo":      map[string]interface{}{"name": "hbs", "version": "1"},
					"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
				}})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			list(w, r.Header.Get("Mcp-Method") != "")
		default:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": id,
				"error": map[string]interface{}{"code": -32601, "message": "Method not found"}})
		}
	}))
}

// A legacy server has no Mcp-Method requirement, so probes 2 and 3 succeed by
// construction. One transient failure of probe 1 was read as "presence enforced"
// and carried the rule all the way to a high/ConfirmedExploit finding asserting a
// requirement the server does not have.
func TestHeaderBodySplit_TransientProbeIsNotEnforcement(t *testing.T) {
	first := true
	srv := hbsServer(t, func(w http.ResponseWriter, hasMethodHeader bool) {
		if first {
			first = false
			w.WriteHeader(http.StatusBadGateway) // probe 1 fails transiently
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": 2,
			"result": map[string]interface{}{"tools": []interface{}{}}})
	})
	defer srv.Close()

	exec := mcpattack.NewHeaderBodySplitExecutor(attack.RuleContext{ID: "mcp-header-body-split-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, testOpts())
	if len(findings) > 0 {
		t.Errorf("FABRICATED: a 502 on probe 1 is not proof of header-presence enforcement, got %q",
			findings[0].Title)
	}
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Errorf("expected inconclusive after an undetermined presence probe, got err=%v", err)
	}
}

// tools/list gated behind credentials means the mismatch can never be sent, so the
// SEP-2243 surface was never examined. This used to report clean.
func TestHeaderBodySplit_GatedToolsListIsNotClean(t *testing.T) {
	srv := hbsServer(t, func(w http.ResponseWriter, hasMethodHeader bool) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"jsonrpc":"2.0","id":2,"error":{"code":-32001,"message":"Unauthorized"}}`)
	})
	defer srv.Close()

	exec := mcpattack.NewHeaderBodySplitExecutor(attack.RuleContext{ID: "mcp-header-body-split-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, testOpts())
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Errorf("a mismatch that was never sent is not a clean result, got err=%v", err)
	}
}
