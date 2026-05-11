package mcp_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

const testExpectedAud = "https://api.acme.com/mcp"

func oauthAudienceRC() attack.RuleContext {
	return attack.RuleContext{
		ID:          "mcp-oauth-audience-002",
		Name:        "MCP OAuth Audience Matching Bug Probes",
		Severity:    "high",
		Remediation: "Compare aud strictly per RFC 7519 §4.1.3.",
	}
}

func optsWithAudience(aud string) attack.Options {
	return attack.Options{TimeoutSeconds: 5, AudienceClaim: aud}
}

// decodeJWTAud reads the `aud` claim from a Bearer token. Signature is
// intentionally ignored: each test handler decides for itself whether the
// audience-matching policy under test should accept the token.
func decodeJWTAud(t *testing.T, authz string) interface{} {
	t.Helper()
	if !strings.HasPrefix(authz, "Bearer ") {
		return nil
	}
	tok := strings.TrimPrefix(authz, "Bearer ")
	parts := strings.Split(tok, ".")
	if len(parts) < 2 {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil
	}
	return claims["aud"]
}

// initializeOK is the JSON-RPC envelope returned for accepted tokens.
func initializeOK(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"result": map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"serverInfo":      map[string]interface{}{"name": "ok", "version": "1.0"},
		},
	})
}

func challenge401(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "invalid_token"})
}

// audienceServer is a configurable httptest server whose /mcp handler applies
// `acceptFn` to the decoded `aud` claim. Tests construct one with the
// matching-bug variant they want to exercise.
type audienceServer struct {
	*httptest.Server
}

func newAudienceServer(t *testing.T, acceptFn func(aud interface{}) bool) audienceServer {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		aud := decodeJWTAud(t, r.Header.Get("Authorization"))
		if acceptFn(aud) {
			initializeOK(w)
			return
		}
		challenge401(w)
	})
	return audienceServer{httptest.NewServer(mux)}
}

func TestOAuthAudience_VulnerableServer_SubstringMatch(t *testing.T) {
	srv := newAudienceServer(t, func(aud interface{}) bool {
		s, ok := aud.(string)
		return ok && strings.Contains(s, testExpectedAud)
	})
	defer srv.Close()

	exec := mcpattack.NewOAuthAudienceExecutor(oauthAudienceRC())
	findings, err := exec.Execute(context.Background(), srv.URL, optsWithAudience(testExpectedAud))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 coalesced finding, got %d", len(findings))
	}
	if findings[0].Confidence != attack.ConfirmedExploit {
		t.Errorf("expected ConfirmedExploit, got %q", findings[0].Confidence)
	}
	if !strings.Contains(findings[0].Evidence, "aud-substring-trap") {
		t.Errorf("evidence missing substring-trap probe name: %s", findings[0].Evidence)
	}
}

func TestOAuthAudience_VulnerableServer_CaseFold(t *testing.T) {
	srv := newAudienceServer(t, func(aud interface{}) bool {
		s, ok := aud.(string)
		return ok && strings.EqualFold(s, testExpectedAud)
	})
	defer srv.Close()

	exec := mcpattack.NewOAuthAudienceExecutor(oauthAudienceRC())
	// Mixed-case expected value forces the executor to emit a lowercased trap
	// probe, which is the variant a case-folding validator would accept.
	mixedCase := "https://API.acme.com/mcp"
	findings, err := exec.Execute(context.Background(), srv.URL, optsWithAudience(mixedCase))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 coalesced finding, got %d", len(findings))
	}
	if findings[0].Confidence != attack.ConfirmedExploit {
		t.Errorf("expected ConfirmedExploit, got %q", findings[0].Confidence)
	}
	if !strings.Contains(findings[0].Evidence, "aud-case-canonicalization-trap") {
		t.Errorf("evidence missing case-canonicalization probe name: %s", findings[0].Evidence)
	}
}

func TestOAuthAudience_VulnerableServer_ArrayBranchSkip(t *testing.T) {
	srv := newAudienceServer(t, func(aud interface{}) bool {
		// Validator only handles string-form aud; array-form is treated as
		// already validated and accepted.
		if _, ok := aud.([]interface{}); ok {
			return true
		}
		s, ok := aud.(string)
		return ok && s == testExpectedAud
	})
	defer srv.Close()

	exec := mcpattack.NewOAuthAudienceExecutor(oauthAudienceRC())
	findings, err := exec.Execute(context.Background(), srv.URL, optsWithAudience(testExpectedAud))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 coalesced finding, got %d", len(findings))
	}
	if findings[0].Confidence != attack.ConfirmedExploit {
		t.Errorf("expected ConfirmedExploit, got %q", findings[0].Confidence)
	}
	if !strings.Contains(findings[0].Evidence, "aud-array-canary-only") {
		t.Errorf("evidence missing array-canary probe name: %s", findings[0].Evidence)
	}
}

func TestOAuthAudience_SecureServer_AllRejected(t *testing.T) {
	srv := newAudienceServer(t, func(aud interface{}) bool {
		// Strict, case-sensitive, exact compare of string-form aud.
		s, ok := aud.(string)
		return ok && s == testExpectedAud
	})
	defer srv.Close()

	exec := mcpattack.NewOAuthAudienceExecutor(oauthAudienceRC())
	findings, err := exec.Execute(context.Background(), srv.URL, optsWithAudience(testExpectedAud))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings on secure server, got %d: %+v", len(findings), findings)
	}
}

func TestOAuthAudience_PreconditionNotMet_NoAudience(t *testing.T) {
	// Server responds 404 to everything: no advertisement, no metadata,
	// no operator input. Rule must skip silently.
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()

	exec := mcpattack.NewOAuthAudienceExecutor(oauthAudienceRC())
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings when audience cannot be resolved, got %d", len(findings))
	}
}

func TestOAuthAudience_AutoDiscovery_FromResourceMetadata(t *testing.T) {
	// Server advertises the resource via /.well-known/oauth-protected-resource
	// and is vulnerable to substring matching. The executor should pick up
	// the resource value via discovery (no AudienceClaim provided) and still
	// produce a finding.
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"resource":              testExpectedAud,
			"authorization_servers": []string{"https://issuer.acme.com"},
		})
	})
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		aud := decodeJWTAud(t, r.Header.Get("Authorization"))
		s, ok := aud.(string)
		if ok && strings.Contains(s, testExpectedAud) {
			initializeOK(w)
			return
		}
		challenge401(w)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	exec := mcpattack.NewOAuthAudienceExecutor(oauthAudienceRC())
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 coalesced finding via auto-discovery, got %d", len(findings))
	}
	if findings[0].Confidence != attack.ConfirmedExploit {
		t.Errorf("expected ConfirmedExploit, got %q", findings[0].Confidence)
	}
}

func TestOAuthAudience_Ambiguous200(t *testing.T) {
	// Server returns 200 with no JSON-RPC envelope to every probe. This is
	// signal-poor: cannot conclude exploit, but also cannot dismiss. The
	// rule must downgrade to RiskIndicator.
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	exec := mcpattack.NewOAuthAudienceExecutor(oauthAudienceRC())
	findings, err := exec.Execute(context.Background(), srv.URL, optsWithAudience(testExpectedAud))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 coalesced finding for ambiguous 200, got %d", len(findings))
	}
	if findings[0].Confidence != attack.RiskIndicator {
		t.Errorf("expected RiskIndicator for ambiguous 200, got %q", findings[0].Confidence)
	}
}

func TestOAuthAudience_EvidenceRedaction(t *testing.T) {
	// The operator-supplied audience must not appear verbatim in finding
	// evidence: only a length-tagged summary is allowed. This protects
	// production identifiers when reports are shared across teams.
	const sensitive = "https://internal-prod-mcp.acme-corp-confidential.example.com/mcp"
	srv := newAudienceServer(t, func(aud interface{}) bool {
		s, ok := aud.(string)
		return ok && strings.Contains(s, sensitive)
	})
	defer srv.Close()

	exec := mcpattack.NewOAuthAudienceExecutor(oauthAudienceRC())
	findings, err := exec.Execute(context.Background(), srv.URL, optsWithAudience(sensitive))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if strings.Contains(findings[0].Evidence, sensitive) {
		t.Errorf("evidence leaked operator audience %q: %s", sensitive, findings[0].Evidence)
	}
	// The evidence still needs to identify *this* run by length so the
	// operator can correlate without the full string being present.
	wantLenTag := fmt.Sprintf("host len=%d", len("internal-prod-mcp.acme-corp-confidential.example.com"))
	if !strings.Contains(findings[0].Evidence, wantLenTag) {
		t.Errorf("evidence missing length-tagged audience summary %q: %s", wantLenTag, findings[0].Evidence)
	}
}
