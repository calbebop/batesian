package mcp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

const (
	legacyVer = "2024-11-05"
	modernVer = "2025-03-26"
)

// versionAwareServer models a server that tracks each session's negotiated
// protocol version and enforces authorization on resources/list per version.
// legacyAllows/modernAllows control whether resources/list is granted for a
// session that initialized with the legacy/modern version respectively.
func versionAwareServer(t *testing.T, legacyAllows, modernAllows bool) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	sessions := map[string]string{} // sessionID -> protocolVersion
	counter := 0

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		method, _ := req["method"].(string)
		id := req["id"]
		w.Header().Set("Content-Type", "application/json")

		switch method {
		case "initialize":
			params, _ := req["params"].(map[string]interface{})
			version, _ := params["protocolVersion"].(string)
			mu.Lock()
			counter++
			sid := fmt.Sprintf("sess-%d", counter)
			sessions[sid] = version
			mu.Unlock()
			w.Header().Set("Mcp-Session-Id", sid)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{
					"protocolVersion": version,
					"serverInfo":      map[string]interface{}{"name": "ver-aware", "version": "1.0"},
					"capabilities":    map[string]interface{}{"resources": map[string]interface{}{}},
				},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "resources/list":
			mu.Lock()
			version := sessions[r.Header.Get("Mcp-Session-Id")]
			mu.Unlock()
			allow := (version == legacyVer && legacyAllows) || (version == modernVer && modernAllows)
			if !allow {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0", "id": id,
					"error": map[string]interface{}{"code": -32001, "message": "Unauthorized"},
				})
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{
					"resources": []interface{}{
						map[string]interface{}{"uri": "file:///secret.txt", "name": "secret"},
					},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// TestInitDowngrade_ConfirmedBypass: modern session is auth-gated, legacy session
// is granted access => confirmed downgrade auth bypass (critical).
func TestInitDowngrade_ConfirmedBypass(t *testing.T) {
	srv := versionAwareServer(t, true /*legacyAllows*/, false /*modernAllows*/)
	defer srv.Close()

	exec := mcpattack.NewInitDowngradeExecutor(attack.RuleContext{ID: "mcp-init-downgrade-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %v", len(findings), findings)
	}
	if findings[0].Severity != "critical" || findings[0].Confidence != attack.ConfirmedExploit {
		t.Errorf("expected critical/ConfirmedExploit, got %q/%q", findings[0].Severity, findings[0].Confidence)
	}
}

// TestInitDowngrade_NoAuthAtAll: BOTH versions are granted access. This is an
// open server (mcp-resources-unauth's job), NOT a downgrade bypass => silent.
func TestInitDowngrade_NoAuthAtAll(t *testing.T) {
	srv := versionAwareServer(t, true, true)
	defer srv.Close()

	exec := mcpattack.NewInitDowngradeExecutor(attack.RuleContext{ID: "mcp-init-downgrade-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for fully-open server (not a downgrade), got %d: %v", len(findings), findings)
	}
}

// TestInitDowngrade_AuthEnforcedBothVersions: accepting the legacy version is
// spec-compliant; auth is enforced regardless of version => silent.
func TestInitDowngrade_AuthEnforcedBothVersions(t *testing.T) {
	srv := versionAwareServer(t, false, false)
	defer srv.Close()

	exec := mcpattack.NewInitDowngradeExecutor(attack.RuleContext{ID: "mcp-init-downgrade-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when auth is enforced under both versions, got %d: %v", len(findings), findings)
	}
}

// TestInitDowngrade_VersionRejected: the server rejects the legacy version
// outright at initialize => silent.
func TestInitDowngrade_VersionRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": req["id"],
			"error": map[string]interface{}{"code": -32600, "message": "Unsupported protocol version"},
		})
	}))
	defer srv.Close()

	exec := mcpattack.NewInitDowngradeExecutor(attack.RuleContext{ID: "mcp-init-downgrade-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for server that rejects legacy version, got %d", len(findings))
	}
}

// TestInitDowngrade_NotMCPServer: a non-MCP server yields no findings.
func TestInitDowngrade_NotMCPServer(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()

	exec := mcpattack.NewInitDowngradeExecutor(attack.RuleContext{ID: "mcp-init-downgrade-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings on non-MCP server, got %d", len(findings))
	}
}
