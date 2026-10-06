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

const modernVersion = "2026-07-28"

func modernAuthServer(t *testing.T, accept func(string) bool) *httptest.Server {
	return modernAuthServerWithDiscovery(t, accept, false)
}

func modernAuthServerWithDiscovery(t *testing.T, accept func(string) bool, openDiscovery bool) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"issuer": srv.URL, "token_endpoint": srv.URL + "/token"})
			return
		case "/metadata":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"resource": testExpectedAud})
			return
		case "/mcp":
		default:
			http.NotFound(w, r)
			return
		}
		var call struct {
			Method string `json:"method"`
			Params struct {
				Meta map[string]interface{} `json:"_meta"`
			} `json:"params"`
		}
		if json.NewDecoder(r.Body).Decode(&call) != nil ||
			r.Header.Get("MCP-Protocol-Version") != modernVersion ||
			r.Header.Get("Mcp-Method") != call.Method ||
			call.Params.Meta["io.modelcontextprotocol/protocolVersion"] != modernVersion {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": 1,
				"error": map[string]interface{}{"code": -32602, "message": "invalid protocol request"},
			})
			return
		}
		if !(openDiscovery && call.Method == "server/discover") && !accept(r.Header.Get("Authorization")) {
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+srv.URL+`/metadata"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if openDiscovery && call.Method == "tools/list" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": 1, "result": map[string]interface{}{"tools": []interface{}{}},
			})
			return
		}
		if call.Method != "server/discover" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": 1,
			"result": map[string]interface{}{
				"resultType": "complete", "supportedVersions": []string{modernVersion},
				"capabilities": map[string]interface{}{},
			},
		})
	}))
	return srv
}

func TestTokenReplay_ModernOnlyVulnerable(t *testing.T) {
	srv := modernAuthServer(t, func(auth string) bool { return strings.HasPrefix(auth, "Bearer ") })
	defer srv.Close()
	findings, err := mcpattack.NewTokenReplayExecutor(tokenReplayRC()).Execute(context.Background(), srv.URL, testOpts())
	if err != nil || len(findings) != 3 {
		t.Fatalf("modern forged tokens: findings=%d, err=%v", len(findings), err)
	}
	for _, finding := range findings {
		if !strings.Contains(finding.Title, modernVersion) || !strings.Contains(finding.Evidence, "server/discover") {
			t.Errorf("finding lacks modern gate evidence: %+v", finding)
		}
	}
}

func TestTokenReplay_ModernOnlySecure(t *testing.T) {
	srv := modernAuthServer(t, func(string) bool { return false })
	defer srv.Close()
	findings, err := mcpattack.NewTokenReplayExecutor(tokenReplayRC()).Execute(context.Background(), srv.URL, testOpts())
	if err != nil || len(findings) != 0 {
		t.Fatalf("secure modern server: findings=%d, err=%v", len(findings), err)
	}
}

func TestTokenReplay_ModernListingGate(t *testing.T) {
	srv := modernAuthServerWithDiscovery(t, func(auth string) bool { return strings.HasPrefix(auth, "Bearer ") }, true)
	defer srv.Close()
	findings, err := mcpattack.NewTokenReplayExecutor(tokenReplayRC()).Execute(context.Background(), srv.URL, testOpts())
	if err != nil || len(findings) != 3 {
		t.Fatalf("modern listing gate: findings=%d, err=%v", len(findings), err)
	}
	if !strings.Contains(findings[0].Evidence, "tools/list") {
		t.Errorf("finding was not judged at the gated listing: %+v", findings[0])
	}
}

func TestOAuthAudience_ModernOnlySubstringTrap(t *testing.T) {
	srv := modernAuthServer(t, func(auth string) bool {
		value, _ := decodeJWTAud(t, auth).(string)
		return strings.Contains(value, testExpectedAud)
	})
	defer srv.Close()
	findings, err := mcpattack.NewOAuthAudienceExecutor(oauthAudienceRC()).Execute(context.Background(), srv.URL, optsWithAudience(testExpectedAud))
	if err != nil || len(findings) != 1 {
		t.Fatalf("modern audience trap: findings=%d, err=%v", len(findings), err)
	}
	if !strings.Contains(findings[0].Title, modernVersion) {
		t.Errorf("finding lacks modern wire label: %+v", findings[0])
	}
}

func TestOAuthAudience_ModernOnlySecure(t *testing.T) {
	srv := modernAuthServer(t, func(string) bool { return false })
	defer srv.Close()
	findings, err := mcpattack.NewOAuthAudienceExecutor(oauthAudienceRC()).Execute(context.Background(), srv.URL, optsWithAudience(testExpectedAud))
	if err != nil || len(findings) != 0 {
		t.Fatalf("secure modern audience: findings=%d, err=%v", len(findings), err)
	}
}

func TestOAuthAudience_ModernChallengeDiscovery(t *testing.T) {
	srv := modernAuthServer(t, func(auth string) bool {
		value, _ := decodeJWTAud(t, auth).(string)
		return strings.Contains(value, testExpectedAud)
	})
	defer srv.Close()
	findings, err := mcpattack.NewOAuthAudienceExecutor(oauthAudienceRC()).Execute(context.Background(), srv.URL, testOpts())
	if err != nil || len(findings) != 1 {
		t.Fatalf("modern challenge discovery: findings=%d, err=%v", len(findings), err)
	}
}

func TestOAuthAudience_ModernListingChallengeDiscovery(t *testing.T) {
	srv := modernAuthServerWithDiscovery(t, func(auth string) bool {
		value, _ := decodeJWTAud(t, auth).(string)
		return strings.Contains(value, testExpectedAud)
	}, true)
	defer srv.Close()
	findings, err := mcpattack.NewOAuthAudienceExecutor(oauthAudienceRC()).Execute(context.Background(), srv.URL, testOpts())
	if err != nil || len(findings) != 1 {
		t.Fatalf("modern listing challenge: findings=%d, err=%v", len(findings), err)
	}
	if !strings.Contains(findings[0].Evidence, "tools/list") {
		t.Errorf("finding was not judged at the gated listing: %+v", findings[0])
	}
}

func TestModernAuth_ProtocolErrorsAreNotTokenVerdicts(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/.well-known/") {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/.well-known/oauth-protected-resource" {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"resource": testExpectedAud})
			} else {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"issuer": srv.URL, "token_endpoint": srv.URL + "/token"})
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": 1,
			"error": map[string]interface{}{"code": -32602, "message": "invalid protocol request"},
		})
	}))
	defer srv.Close()
	if _, err := mcpattack.NewTokenReplayExecutor(tokenReplayRC()).Execute(context.Background(), srv.URL, testOpts()); !errors.Is(err, attack.ErrInconclusive) {
		t.Errorf("token replay protocol-only replies: want inconclusive, got %v", err)
	}
	if _, err := mcpattack.NewOAuthAudienceExecutor(oauthAudienceRC()).Execute(context.Background(), srv.URL, optsWithAudience(testExpectedAud)); !errors.Is(err, attack.ErrInconclusive) {
		t.Errorf("audience protocol-only replies: want inconclusive, got %v", err)
	}
}

func TestModernAuth_Unchallenged401DoesNotProveModernWire(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/.well-known/oauth-protected-resource" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"resource": testExpectedAud})
			return
		}
		if r.URL.Path == "/mcp" && r.Header.Get("MCP-Protocol-Version") == modernVersion {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": 1,
			"error": map[string]interface{}{"code": -32602, "message": "invalid protocol request"},
		})
	}))
	defer srv.Close()
	if _, err := mcpattack.NewTokenReplayExecutor(tokenReplayRC()).Execute(context.Background(), srv.URL, testOpts()); !errors.Is(err, attack.ErrInconclusive) {
		t.Errorf("token replay without modern challenge: want inconclusive, got %v", err)
	}
	if _, err := mcpattack.NewOAuthAudienceExecutor(oauthAudienceRC()).Execute(context.Background(), srv.URL, optsWithAudience(testExpectedAud)); !errors.Is(err, attack.ErrInconclusive) {
		t.Errorf("audience without modern challenge: want inconclusive, got %v", err)
	}
}
