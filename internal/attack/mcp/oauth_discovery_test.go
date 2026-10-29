package mcp_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

func oauthDiscoveryServer(primaryStatus int, primaryBody string, fallbackStatus int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-protected-resource":
			http.NotFound(w, r)
		case "/.well-known/oauth-authorization-server":
			w.WriteHeader(primaryStatus)
			_, _ = w.Write([]byte(primaryBody))
		case "/.well-known/openid-configuration":
			if fallbackStatus != http.StatusOK {
				w.WriteHeader(fallbackStatus)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":                 "http://" + r.Host,
				"registration_endpoint":  "http://" + r.Host + "/register",
				"authorization_endpoint": "http://" + r.Host + "/authorize",
			})
		case "/register":
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_redirect_uri"}`))
		case "/mcp":
			if r.Header.Get("Authorization") != "" {
				w.Header().Set("WWW-Authenticate", `Bearer realm="mcp"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			var req struct {
				ID     any    `json:"id"`
				Method string `json:"method"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req.Method != "initialize" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": req.ID,
				"result": map[string]any{
					"protocolVersion": "2025-11-25",
					"serverInfo":      map[string]string{"name": "test", "version": "1"},
					"capabilities":    map[string]any{},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
}

func oauthDiscoveryRules() []struct {
	name string
	exec attack.Executor
} {
	return []struct {
		name string
		exec attack.Executor
	}{
		{"DCR", mcpattack.NewOAuthDCRExecutor(oauthRC())},
		{"metadata SSRF", mcpattack.NewOAuthMetadataSSRFExecutor(omRuleCtx())},
		{"confused deputy", mcpattack.NewConfusedDeputyExecutor(confusedDeputyRC())},
		{"token replay", mcpattack.NewTokenReplayExecutor(tokenReplayRC())},
	}
}

func TestOAuthDiscovery_UnreadableMetadataIsIncomplete(t *testing.T) {
	for _, tc := range []struct {
		name           string
		status         int
		body           string
		fallbackStatus int
		wantPath       string
	}{
		{"gateway error", http.StatusBadGateway, "", http.StatusNotFound, "/.well-known/oauth-authorization-server"},
		{"authentication required", http.StatusUnauthorized, "", http.StatusNotFound, "/.well-known/oauth-authorization-server"},
		{"invalid document", http.StatusOK, "<html>unavailable</html>", http.StatusNotFound, "/.well-known/oauth-authorization-server"},
		{"unreadable fallback", http.StatusOK, `{"issuer":"https://issuer.example"}`, http.StatusBadGateway, "/.well-known/openid-configuration"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := oauthDiscoveryServer(tc.status, tc.body, tc.fallbackStatus)
			defer srv.Close()
			for _, rule := range oauthDiscoveryRules() {
				if tc.name == "unreadable fallback" && rule.name == "token replay" {
					continue
				}
				t.Run(rule.name, func(t *testing.T) {
					findings, err := rule.exec.Execute(t.Context(), srv.URL, testOpts())
					if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) ||
						!strings.Contains(err.Error(), tc.wantPath) {
						t.Fatalf("unreadable metadata must remain incomplete: findings=%+v err=%v", findings, err)
					}
				})
			}
		})
	}
}

func TestOAuthDiscovery_AbsentMetadataIsNotApplicable(t *testing.T) {
	srv := oauthDiscoveryServer(http.StatusNotFound, "", http.StatusNotFound)
	defer srv.Close()
	for _, rule := range oauthDiscoveryRules() {
		t.Run(rule.name, func(t *testing.T) {
			findings, err := rule.exec.Execute(t.Context(), srv.URL, testOpts())
			if len(findings) != 0 || err != nil {
				t.Fatalf("absent metadata on a reachable MCP server is not applicable: findings=%+v err=%v", findings, err)
			}
		})
	}
}

func TestOAuthDiscovery_UsesReadableFallback(t *testing.T) {
	srv := oauthDiscoveryServer(http.StatusBadGateway, "", http.StatusOK)
	defer srv.Close()
	for _, rule := range oauthDiscoveryRules() {
		t.Run(rule.name, func(t *testing.T) {
			opts := testOpts()
			opts.OOBListenerURL = "http://oob.batesian.invalid"
			findings, err := rule.exec.Execute(t.Context(), srv.URL, opts)
			if len(findings) != 0 {
				t.Fatalf("unexpected findings: %+v", findings)
			}
			if errors.Is(err, attack.ErrInconclusive) && strings.Contains(err.Error(), "OAuth metadata") {
				t.Fatalf("readable fallback was discarded: %v", err)
			}
			if rule.name == "metadata SSRF" {
				if !errors.Is(err, attack.ErrInconclusive) || !strings.Contains(err.Error(), "registration") {
					t.Fatalf("fallback must reach registration before reporting incomplete: %v", err)
				}
			} else if err != nil {
				t.Fatalf("readable fallback should reach the rule's probe: %v", err)
			}
		})
	}
}

func TestOAuthDiscovery_RejectsMismatchedFallbackIssuer(t *testing.T) {
	var registrations atomic.Int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer": srv.URL + "/other", "registration_endpoint": srv.URL + "/register",
				"authorization_endpoint": srv.URL + "/authorize",
			})
		case "/register":
			registrations.Add(1)
			w.WriteHeader(http.StatusBadRequest)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	for _, rule := range oauthDiscoveryRules() {
		if rule.name == "token replay" {
			continue
		}
		t.Run(rule.name, func(t *testing.T) {
			findings, err := rule.exec.Execute(t.Context(), srv.URL, testOpts())
			if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) || !strings.Contains(err.Error(), "issuer") {
				t.Fatalf("mismatched issuer was accepted: findings=%+v err=%v", findings, err)
			}
		})
	}
	if registrations.Load() != 0 {
		t.Fatalf("untrusted metadata reached registration %d times", registrations.Load())
	}
}

func TestOAuthDiscovery_UsesRootAfterInvalidPathIssuer(t *testing.T) {
	var registrations atomic.Int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server/mcp":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer": srv.URL + "/wrong", "registration_endpoint": srv.URL + "/register",
				"authorization_endpoint": srv.URL + "/authorize",
			})
		case "/.well-known/oauth-authorization-server":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer": srv.URL, "registration_endpoint": srv.URL + "/register",
				"authorization_endpoint": srv.URL + "/authorize",
			})
		case "/register":
			registrations.Add(1)
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_redirect_uri"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	findings, err := mcpattack.NewConfusedDeputyExecutor(confusedDeputyRC()).Execute(t.Context(), srv.URL+"/mcp", testOpts())
	if len(findings) != 0 || err != nil || registrations.Load() != 1 {
		t.Fatalf("valid root issuer was not reached: findings=%+v registrations=%d err=%v", findings, registrations.Load(), err)
	}
}

func TestOAuthDiscovery_PathIssuerDoesNotUseRootMetadata(t *testing.T) {
	var rootReads atomic.Int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/oauth-protected-resource/mcp" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"resource": srv.URL + "/mcp", "authorization_servers": []string{srv.URL + "/issuer"},
			})
			return
		}
		if r.URL.Path == "/.well-known/oauth-authorization-server" {
			rootReads.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer": srv.URL + "/issuer", "registration_endpoint": srv.URL + "/register",
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	findings, err := mcpattack.NewConfusedDeputyExecutor(confusedDeputyRC()).Execute(t.Context(), srv.URL+"/mcp", testOpts())
	if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) || rootReads.Load() != 0 {
		t.Fatalf("path issuer used root metadata: findings=%+v rootReads=%d err=%v", findings, rootReads.Load(), err)
	}
}
