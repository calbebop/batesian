package mcp_test

import (
	"context"
	"encoding/base64"
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

const testExpectedAud = "https://api.acme.com/mcp"

func oauthAudienceRC() attack.RuleContext {
	return attack.RuleContext{
		ID:          "mcp-oauth-audience-002",
		Name:        "MCP OAuth Audience Matching Bug Probes",
		Severity:    "high",
		Remediation: "Compare aud strictly per RFC 7519 section 4.1.3.",
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

// TestOAuthAudience_BlanketForgedAcceptance: the server demands a bearer on
// every call but accepts ANY token regardless of audience (no signature or
// audience validation behind a presence-only gate). The negative control
// fires, so the rule must report blanket acceptance - NOT misattribute it to a
// specific aud-matching bug.
func TestOAuthAudience_BlanketForgedAcceptance(t *testing.T) {
	srv := newAudienceServer(t, func(aud interface{}) bool { return aud != nil })
	defer srv.Close()

	exec := mcpattack.NewOAuthAudienceExecutor(oauthAudienceRC())
	findings, err := exec.Execute(context.Background(), srv.URL, optsWithAudience(testExpectedAud))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 coalesced finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Confidence != attack.ConfirmedExploit {
		t.Errorf("expected ConfirmedExploit, got %q", findings[0].Confidence)
	}
	// Must be attributed to the control (unrelated audience), not a trap.
	if !strings.Contains(findings[0].Evidence, "aud-control-unrelated") {
		t.Errorf("expected control probe in evidence, got: %s", findings[0].Evidence)
	}
	if strings.Contains(findings[0].Evidence, "aud-substring-trap") {
		t.Errorf("blanket acceptance must not be attributed to substring-trap: %s", findings[0].Evidence)
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

// "The precondition is not met" covers two different situations, and they are not
// reported the same way.
//
// An MCP server that answers the handshake but advertises no resource metadata is
// genuinely not applicable: there is no audience to check against, and a clean
// result is honest.
func TestOAuthAudience_PreconditionNotMet_MCPServerWithoutMetadata(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		initializeOK(w) // no WWW-Authenticate challenge, no metadata anywhere
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	exec := mcpattack.NewOAuthAudienceExecutor(oauthAudienceRC())
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("expected a clean result for an MCP server with no metadata, got err=%v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings when audience cannot be resolved, got %d", len(findings))
	}
}

// A target where nothing answers was never exercised. Reporting clean there says
// the audience handling is sound about a host the rule never reached.
func TestOAuthAudience_NothingReachableIsNotTested(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()

	exec := mcpattack.NewOAuthAudienceExecutor(oauthAudienceRC())
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected ErrInconclusive against a 404-everything target, got err=%v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings, got %d", len(findings))
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
	// Server returns 200 with no JSON-RPC envelope to every probe (e.g. a
	// non-MCP endpoint or a generic 2xx ack). That is not evidence that any
	// forged token was accepted, so the rule must produce no finding rather
	// than a downgraded indicator. (Previously a 200 non-result was treated as
	// "ambiguous acceptance" and emitted a RiskIndicator, which false-positived
	// non-MCP targets whose /mcp fell through to a 200 page.)
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
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for a 200 non-result target, got %d: %+v", len(findings), findings)
	}
}

// TestOAuthAudience_TrapAcceptedControlNonResult covers the rewritten
// coalesceOutcomes path where a trap probe returns a clear result envelope
// (accepted) but the negative control returns a 200 body with no result
// envelope (inconclusive, not a clear rejection). The trap must still be
// reported, downgraded to RiskIndicator (not confirmed, and not dropped).
func TestOAuthAudience_TrapAcceptedControlNonResult(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			// The gate: initialize itself demands a bearer, so the probes'
			// initialize verdicts stand.
			challenge401(w)
			return
		}
		aud := decodeJWTAud(t, r.Header.Get("Authorization"))
		if s, ok := aud.(string); ok && strings.HasPrefix(s, "https://batesian-control") {
			// negative control: 200 with no JSON-RPC result envelope
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
			return
		}
		// every trap probe is accepted with a clean result envelope
		initializeOK(w)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	exec := mcpattack.NewOAuthAudienceExecutor(oauthAudienceRC())
	findings, err := exec.Execute(context.Background(), srv.URL, optsWithAudience(testExpectedAud))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 downgraded finding (trap accepted, control inconclusive), got %d: %+v", len(findings), findings)
	}
	if findings[0].Confidence != attack.RiskIndicator {
		t.Errorf("expected RiskIndicator (control not clearly rejected), got %q", findings[0].Confidence)
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

// TestOAuthAudience_UnreachableHost: when no candidate endpoint can be reached
// (every probe transport-errors - no endpoint produced any response),
// runProbesAgainstEndpoint returns an empty endpoint and the rule reports
// ErrInconclusive rather than a clean pass. (A server that merely 404s the
// probes is "reached, all rejected" = clean; this is the distinct unreachable
// case, exercised by tearing the server down so the port refuses connections.)
func TestOAuthAudience_UnreachableHost(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	addr := srv.URL
	srv.Close() // refuse all further connections to this address

	assertInconclusive(t, mcpattack.NewOAuthAudienceExecutor(oauthAudienceRC()), addr, optsWithAudience(testExpectedAud))
}

// unroutedThenVulnerableServer serves the vulnerable substring matcher at
// /sub/mcp and 404s everything else, including /sub itself. Scanned at
// srv.URL+"/sub", the first candidate is the base path, which is unrouted.
//
// The base is only a candidate when the target carries a path, which is why a
// root-targeted test cannot reproduce this: there the walk starts at /mcp and
// finds the endpoint immediately.
//
// The walk used to stop at the first path returning any response that was not a
// transport error, so the 404 at /sub ended it and /sub/mcp was never probed.
// Worse, a 404 classified as a rejected token, so four requests to a path that
// did not exist read as evidence that audience matching worked.
func unroutedThenVulnerableServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sub/mcp" {
			// Unrouted, exactly as a real server answers a path it does not serve.
			w.WriteHeader(http.StatusNotFound)
			return
		}
		aud := decodeJWTAud(t, r.Header.Get("Authorization"))
		if str, ok := aud.(string); ok && strings.Contains(str, testExpectedAud) {
			initializeOK(w)
			return
		}
		challenge401(w)
	}))
}

// A 404 at one candidate must not end the walk, and must not read as the server
// rejecting the token.
func TestOAuthAudience_UnroutedCandidateDoesNotHideFinding(t *testing.T) {
	srv := unroutedThenVulnerableServer(t)
	defer srv.Close()

	exec := mcpattack.NewOAuthAudienceExecutor(oauthAudienceRC())
	findings, err := exec.Execute(context.Background(), srv.URL+"/sub", optsWithAudience(testExpectedAud))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected the finding at /sub/mcp to survive the 404 at /sub, got %d", len(findings))
	}
	if !strings.Contains(findings[0].TargetURL, "/sub/mcp") {
		t.Errorf("finding should name the endpoint that answered, got %q", findings[0].TargetURL)
	}
}

// A target that 404s every candidate has said nothing about audience matching, so
// the rule must report that it could not test rather than that the server is
// secure. This is the shape that produced a false clean.
func TestOAuthAudience_AllCandidatesUnroutedIsNotTested(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	exec := mcpattack.NewOAuthAudienceExecutor(oauthAudienceRC())
	findings, err := exec.Execute(context.Background(), srv.URL, optsWithAudience(testExpectedAud))
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Errorf("404s everywhere are not evidence of a secure audience check; want ErrInconclusive, got %v", err)
	}
}

// 405 is the same class: the path exists but does not take the POST an MCP call
// needs, so it is not an MCP endpoint and says nothing about the token.
func TestOAuthAudience_MethodNotAllowedIsNotARejection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	defer srv.Close()

	exec := mcpattack.NewOAuthAudienceExecutor(oauthAudienceRC())
	_, err := exec.Execute(context.Background(), srv.URL, optsWithAudience(testExpectedAud))
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Errorf("want ErrInconclusive for a target answering 405 everywhere, got %v", err)
	}
}

// audienceServerAdvertising is an audienceServer that also serves RFC 9728
// resource metadata naming `advertised`, so a test can put the operator's
// --audience-claim and the server's own audience in disagreement.
func audienceServerAdvertising(t *testing.T, advertised string, acceptFn func(aud interface{}) bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"resource":              advertised,
			"authorization_servers": []string{"https://issuer.acme.com"},
		})
	})
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		aud := decodeJWTAud(t, r.Header.Get("Authorization"))
		if acceptFn(aud) {
			initializeOK(w)
			return
		}
		challenge401(w)
	})
	return httptest.NewServer(mux)
}

// Every probe is derived from the expected audience, and RFC 7519 compares the
// claim exactly, so a --audience-claim that does not byte-match what the server
// uses turns all four probes into plain mismatches. The server refuses them
// whether or not its matching logic is sound, and reporting that as clean claims
// coverage the scan does not have.
//
// This server has the substring bug and would be caught with the right value.
// Hostname case is the whole difference, which is the realistic mistake: DNS is
// case-insensitive, audience comparison is not.
func TestOAuthAudience_ClaimDisagreesWithAdvertisedIsNotTested(t *testing.T) {
	const advertised = "https://API.acme.com/mcp"
	srv := audienceServerAdvertising(t, advertised, func(aud interface{}) bool {
		s, ok := aud.(string)
		return ok && strings.Contains(s, advertised)
	})
	defer srv.Close()

	exec := mcpattack.NewOAuthAudienceExecutor(oauthAudienceRC())
	findings, err := exec.Execute(context.Background(), srv.URL, optsWithAudience("https://api.acme.com/mcp"))
	if len(findings) != 0 {
		t.Fatalf("expected no findings from probes built on the wrong audience, got %d", len(findings))
	}
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected ErrInconclusive, got %v", err)
	}
	// The operator cannot act on this without both values.
	for _, want := range []string{"https://api.acme.com/mcp", advertised} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("reason should name %q; got: %v", want, err)
		}
	}
}

// A disagreement is not a reason to withhold a finding the server demonstrated.
// This one accepts any presented bearer token, which the control probe catches
// regardless of which audience the traps were built from.
func TestOAuthAudience_ClaimDisagreesButFindingStillReported(t *testing.T) {
	srv := audienceServerAdvertising(t, "https://API.acme.com/mcp", func(aud interface{}) bool {
		return aud != nil // accepts every forged token, audience irrelevant
	})
	defer srv.Close()

	exec := mcpattack.NewOAuthAudienceExecutor(oauthAudienceRC())
	findings, err := exec.Execute(context.Background(), srv.URL, optsWithAudience("https://api.acme.com/mcp"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected the finding to survive the disagreement, got %d", len(findings))
	}
}

// The premise check must not turn a genuine clean result into not tested. Same
// server, same advertised audience, and the operator passed exactly that value.
func TestOAuthAudience_ClaimMatchesAdvertisedStaysClean(t *testing.T) {
	const advertised = "https://API.acme.com/mcp"
	srv := audienceServerAdvertising(t, advertised, func(aud interface{}) bool {
		s, ok := aud.(string)
		return ok && s == advertised // strict, exact, case-sensitive
	})
	defer srv.Close()

	exec := mcpattack.NewOAuthAudienceExecutor(oauthAudienceRC())
	findings, err := exec.Execute(context.Background(), srv.URL, optsWithAudience(advertised))
	if err != nil {
		t.Fatalf("expected a clean result, got %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings on a strict server, got %d", len(findings))
	}
}

// The ungated-initialize posture, from the audience rule's side. The
// ungatedInitServer fixture is defined in token_replay_test.go (same package).

// initialize answers anyone and the gate validates tokens: no finding. The
// rule used to report blanket forged-token acceptance here, because the
// control probe (forged unrelated audience) was accepted by a method that
// never looked at it.
func TestOAuthAudience_UngatedInitValidatingGateStaysSilent(t *testing.T) {
	srv := ungatedInitServer(t, "validate")
	defer srv.Close()

	findings, err := mcpattack.NewOAuthAudienceExecutor(oauthAudienceRC()).Execute(context.Background(), srv.URL, optsWithAudience(testExpectedAud))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings against an ungated-initialize server that validates tokens at the gate, got %d: %+v", len(findings), findings)
	}
}

// initialize answers anyone, the gate checks bearer presence only: the blanket
// acceptance finding still fires, judged at the gated method.
func TestOAuthAudience_UngatedInitPresenceOnlyGateFiresAtMethod(t *testing.T) {
	srv := ungatedInitServer(t, "presence")
	defer srv.Close()

	findings, err := mcpattack.NewOAuthAudienceExecutor(oauthAudienceRC()).Execute(context.Background(), srv.URL, optsWithAudience(testExpectedAud))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 coalesced finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Confidence != attack.ConfirmedExploit {
		t.Errorf("expected ConfirmedExploit, got %q", findings[0].Confidence)
	}
	if !strings.Contains(findings[0].Evidence, "judged at: tools/list") {
		t.Errorf("evidence must name the gated method the token was judged at: %s", findings[0].Evidence)
	}
}

// No gate anywhere: the unauth rules own the surface, this rule reports not
// tested instead of blanket forged-token acceptance.
func TestOAuthAudience_FullyOpenServerIsNotTested(t *testing.T) {
	srv := ungatedInitServer(t, "open")
	defer srv.Close()

	findings, err := mcpattack.NewOAuthAudienceExecutor(oauthAudienceRC()).Execute(context.Background(), srv.URL, optsWithAudience(testExpectedAud))
	if len(findings) != 0 {
		t.Fatalf("expected no findings against a fully open server, got %d: %+v", len(findings), findings)
	}
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected ErrInconclusive, got %v", err)
	}
	if !strings.Contains(err.Error(), "no credential-gated surface") {
		t.Errorf("reason should explain the open surface: %v", err)
	}
}
