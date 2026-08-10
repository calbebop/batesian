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
)

// versionAwareServer models a server that tracks each session's negotiated
// protocol version and enforces authorization on resources/list per version.
// legacyAllows/modernAllows control whether resources/list is granted for a
// session that initialized with the legacy/modern version respectively.
// versionAwareServer gates resources/list on the protocol version the session
// negotiated. Any version other than the pre-auth revision counts as modern, rather
// than one hardcoded string: pinning the version the rule offers made a fully-open
// server look like a critical downgrade bypass the moment that version was updated.
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
			allow := (version == legacyVer && legacyAllows) || (version != legacyVer && modernAllows)
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

// tokenGatedDowngradeServer models a REALISTIC downgrade bug: the modern-version
// path enforces bearer-token auth on resources/list, but the legacy-version path
// skips that check entirely. A server like this is the whole point of the rule,
// and it is the case the old (authenticated) probe silently missed: if the rule
// attached the caller's --token, the modern path would be granted and the
// discriminator could never fire. The probe must run unauthenticated.
func tokenGatedDowngradeServer(t *testing.T, validToken string) *httptest.Server {
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
					"serverInfo":      map[string]interface{}{"name": "token-gated", "version": "1.0"},
					"capabilities":    map[string]interface{}{"resources": map[string]interface{}{}},
				},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "resources/list":
			mu.Lock()
			version := sessions[r.Header.Get("Mcp-Session-Id")]
			mu.Unlock()
			hasValidToken := r.Header.Get("Authorization") == "Bearer "+validToken
			// Legacy path skips auth (the bug); modern path requires the token.
			allow := version == legacyVer || hasValidToken
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

// TestInitDowngrade_TokenDoesNotMaskBypass is the regression guard for the
// authenticated-client bug: even when the caller supplies a valid --token, the
// rule must still confirm the downgrade by probing the legacy path WITHOUT
// credentials. With the old NewHTTPClient(opts,...) the token rode on the modern
// probe, the modern path was granted, and this returned 0 findings.
func TestInitDowngrade_TokenDoesNotMaskBypass(t *testing.T) {
	srv := tokenGatedDowngradeServer(t, "valid-user-token")
	defer srv.Close()

	exec := mcpattack.NewInitDowngradeExecutor(attack.RuleContext{ID: "mcp-init-downgrade-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5, Token: "valid-user-token"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding despite --token (probe must run unauthenticated), got %d: %v", len(findings), findings)
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
	assertInconclusive(t, exec, srv.URL, attack.Options{TimeoutSeconds: 5})
}

// An OLD server: it supports the pre-auth revision and nothing newer, and it enforces
// no authorization at all. Offering a current revision means the modern probe is
// refused at initialize while the legacy one succeeds, which is the exact shape of a
// downgrade bypass without being one.
//
// This matters more the further the offered version moves ahead: every server that
// predates it answers this way. The rule is safe because it requires the modern
// handshake to SUCCEED before comparing the two paths, and this pins that.
func TestInitDowngrade_OldServerRejectingModernIsNotABypass(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		method, _ := req["method"].(string)
		params, _ := req["params"].(map[string]interface{})
		version, _ := params["protocolVersion"].(string)
		w.Header().Set("Content-Type", "application/json")
		switch method {
		case "initialize":
			if version != legacyVer {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0", "id": req["id"],
					"error": map[string]interface{}{"code": -32602, "message": "Unsupported protocol version"},
				})
				return
			}
			w.Header().Set("Mcp-Session-Id", "s1")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]interface{}{
					"protocolVersion": legacyVer,
					"serverInfo":      map[string]interface{}{"name": "old", "version": "1"},
					"capabilities":    map[string]interface{}{"resources": map[string]interface{}{}},
				},
			})
		case "resources/list":
			// Wide open, which is what makes this a false-positive risk rather than a
			// missed finding: the legacy path returns data.
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]interface{}{"resources": []interface{}{
					map[string]interface{}{"uri": "file:///x", "name": "x"}}},
			})
		default:
			w.WriteHeader(http.StatusAccepted)
		}
	}))
	defer srv.Close()

	exec := mcpattack.NewInitDowngradeExecutor(attack.RuleContext{ID: "mcp-init-downgrade-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("a server that simply does not support the offered revision is not a "+
			"downgrade bypass; got %d finding(s): %v", len(findings), findings)
	}
}

// toolsOnlyDowngradeServer advertises ONLY tools (no resources capability) and
// gates tools/list under the modern version while leaving it open under the
// legacy version. This is the false negative the hardcoded resources/list probe
// caused: resources/list returned method-not-found under both versions, so the
// rule reported clean against a server with a real downgrade bypass on its tools
// surface. Picking the probe method from advertised capabilities surfaces it.
func toolsOnlyDowngradeServer(t *testing.T) *httptest.Server {
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
					"serverInfo":      map[string]interface{}{"name": "tools-only", "version": "1.0"},
					"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
				},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			mu.Lock()
			version := sessions[r.Header.Get("Mcp-Session-Id")]
			mu.Unlock()
			if version != legacyVer {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0", "id": id,
					"error": map[string]interface{}{"code": -32001, "message": "Unauthorized"},
				})
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{"tools": []interface{}{
					map[string]interface{}{"name": "search", "description": "internal search"},
				}},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// TestInitDowngrade_ToolsOnlyServer: a tools-only server with a real downgrade
// bypass on tools/list must be reported, not silently cleaned. Under the old
// hardcoded resources/list probe this returned no finding.
func TestInitDowngrade_ToolsOnlyServer(t *testing.T) {
	srv := toolsOnlyDowngradeServer(t)
	defer srv.Close()

	exec := mcpattack.NewInitDowngradeExecutor(attack.RuleContext{ID: "mcp-init-downgrade-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for a tools-only downgrade bypass (resources/list probe "+
			"silently missed it), got %d: %v", len(findings), findings)
	}
	if findings[0].Severity != "critical" || findings[0].Confidence != attack.ConfirmedExploit {
		t.Errorf("expected critical/ConfirmedExploit, got %q/%q", findings[0].Severity, findings[0].Confidence)
	}
}
