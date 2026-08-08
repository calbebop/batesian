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

// oauthOnlyServer publishes OAuth metadata but mounts its MCP handler nowhere the
// candidate walk looks. The pre-2025-03-26 HTTP+SSE transport (/sse + /messages) is
// still widely deployed, and /v1/mcp is a common choice too.
func oauthOnlyServer(t *testing.T, dcrStatus int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"resource":"http://%s/v1/mcp","authorization_servers":["http://%s"]}`, r.Host, r.Host)
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"issuer":"http://%s","authorization_endpoint":"http://%s/authorize",`+
			`"token_endpoint":"http://%s/token","registration_endpoint":"http://%s/register"}`,
			r.Host, r.Host, r.Host, r.Host)
	})
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(dcrStatus)
		if dcrStatus == http.StatusUnauthorized {
			fmt.Fprint(w, `{"error":"invalid_token","error_description":"initial access token required"}`)
			return
		}
		fmt.Fprint(w, `{"client_id":"c1"}`)
	})
	// The MCP handler lives here, which the candidate walk never tries.
	mux.HandleFunc("/v1/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": 1,
			"result": map[string]interface{}{"protocolVersion": "2025-06-18",
				"serverInfo": map[string]interface{}{"name": "s", "version": "1"}, "capabilities": map[string]interface{}{}}})
	})
	return httptest.NewServer(mux)
}

// token_replay had no endpoint gate at all: it POSTed forged tokens to the
// candidate paths, treated every 404 as a rejection, and returned clean. So a
// server whose MCP handler is mounted elsewhere was reported as rejecting alg:none
// and forged-signature JWTs without one having been examined.
func TestTokenReplay_NoMCPEndpointIsNotClean(t *testing.T) {
	srv := oauthOnlyServer(t, http.StatusCreated)
	defer srv.Close()

	exec := mcpattack.NewTokenReplayExecutor(attack.RuleContext{ID: "mcp-token-replay-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, testOpts())
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Errorf("no MCP endpoint answered, so no token was examined; want inconclusive, got err=%v", err)
	}
}

// A DCR that requires an initial access token says nothing about whether
// /authorize validates redirect_uri, which is this rule's subject.
func TestConfusedDeputy_CredentialGatedDCRIsNotClean(t *testing.T) {
	srv := oauthOnlyServer(t, http.StatusUnauthorized)
	defer srv.Close()

	exec := mcpattack.NewConfusedDeputyExecutor(attack.RuleContext{ID: "mcp-confused-deputy-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, testOpts())
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("a credential-gated DCR leaves /authorize unprobed; want inconclusive, got err=%v", err)
	}
	if !strings.Contains(err.Error(), "credentials") {
		t.Errorf("the reason should name the credential requirement, got: %v", err)
	}
}

// The mirror case, which must stay clean: refusing to REGISTER an off-origin
// redirect_uri is the mitigation this rule looks for, since the confused-deputy
// chain needs that redirect registered. Distinguishing this from the case above is
// the whole point; an earlier version of this fix reported both as inconclusive and
// broke the existing dcr-restricted test.
func TestConfusedDeputy_RedirectRefusedAtRegistrationStaysClean(t *testing.T) {
	srv := oauthOnlyServer(t, http.StatusBadRequest)
	defer srv.Close()

	exec := mcpattack.NewConfusedDeputyExecutor(attack.RuleContext{ID: "mcp-confused-deputy-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, testOpts())
	if err != nil {
		t.Fatalf("an allowlist refusing our redirect is a tested, clean result: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}

// oauth_metadata_ssrf waited for an OOB callback without checking that the
// registration carrying the seeded URLs had been accepted, so a DCR answering 401
// produced a clean "no metadata-fetch SSRF" verdict.
func TestOAuthMetadataSSRF_RefusedRegistrationIsNotClean(t *testing.T) {
	srv := oauthOnlyServer(t, http.StatusUnauthorized)
	defer srv.Close()

	exec := mcpattack.NewOAuthMetadataSSRFExecutor(attack.RuleContext{ID: "mcp-oauth-metadata-ssrf-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, testOpts())
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Errorf("a refused registration stored no URLs, so no fetch could occur; want inconclusive, got err=%v", err)
	}
}
