package a2a_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/attack/a2a"
)

func protectedHeader(alg string, exp *int64) string {
	m := map[string]interface{}{"alg": alg, "typ": "JOSE", "kid": "key-1", "jku": "https://agent.example/jwks.json"}
	if exp != nil {
		m["exp"] = *exp
	}
	b, _ := json.Marshal(m)
	return base64.RawURLEncoding.EncodeToString(b)
}

func signedCard(url string, exp *int64) map[string]interface{} {
	return map[string]interface{}{
		"name": "Test Agent",
		"url":  url,
		"signatures": []interface{}{
			map[string]interface{}{"protected": protectedHeader("RS256", exp), "signature": "c2ln"},
		},
	}
}

func unsignedCard() map[string]interface{} {
	return map[string]interface{}{"name": "Test Agent", "url": "https://agent.example/"}
}

// cardServer serves the given cards at the two well-known paths (nil => 404) and
// sets the given Cache-Control header (empty => none).
func cardServer(primary, legacy interface{}, cacheControl string) *httptest.Server {
	return cardServerWithCachePolicies(primary, legacy, cacheControl, cacheControl)
}

func cardServerWithCachePolicies(primary, legacy interface{}, primaryCache, legacyCache string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var card interface{}
		var cacheControl string
		switch r.URL.Path {
		case "/.well-known/agent-card.json":
			card = primary
			cacheControl = primaryCache
		case "/.well-known/agent.json":
			card = legacy
			cacheControl = legacyCache
		default:
			http.NotFound(w, r)
			return
		}
		if card == nil {
			http.NotFound(w, r)
			return
		}
		if cacheControl != "" {
			w.Header().Set("Cache-Control", cacheControl)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(card)
	}))
}

func future() *int64 { v := time.Now().Add(time.Hour).Unix(); return &v }
func past() *int64   { v := time.Now().Add(-time.Hour).Unix(); return &v }

func runCardTrust(t *testing.T, ts *httptest.Server) []attack.Finding {
	t.Helper()
	findings, err := a2a.NewCardTrustExecutor(testRuleCtx()).Execute(context.Background(), ts.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return findings
}

func onlyFinding(t *testing.T, findings []attack.Finding) attack.Finding {
	t.Helper()
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	return findings[0]
}

// TestCardTrust_SignatureStripping: signed on primary path, unsigned on legacy.
// MUST fire indicator/high (a read-only analyzer observes the unsigned path but
// cannot prove a verifier is bypassed).
func TestCardTrust_SignatureStripping(t *testing.T) {
	ts := cardServer(signedCard("https://agent.example/", future()), unsignedCard(), "no-store")
	defer ts.Close()

	f := onlyFinding(t, runCardTrust(t, ts))
	if f.Confidence != attack.RiskIndicator || f.Severity != "high" {
		t.Errorf("want high/RiskIndicator, got %q/%q", f.Severity, f.Confidence)
	}
}

// TestCardTrust_UrlMismatch: both signed, different url. MUST fire indicator/medium.
func TestCardTrust_UrlMismatch(t *testing.T) {
	ts := cardServer(signedCard("https://agent.example/", future()), signedCard("https://other.example/", future()), "no-store")
	defer ts.Close()

	f := onlyFinding(t, runCardTrust(t, ts))
	if f.Confidence != attack.RiskIndicator || f.Severity != "medium" {
		t.Errorf("want medium/RiskIndicator, got %q/%q", f.Severity, f.Confidence)
	}
}

// TestCardTrust_StaleCache: consistent unsigned card with a long max-age.
// MUST fire a single medium cache indicator.
func TestCardTrust_StaleCache(t *testing.T) {
	card := unsignedCard()
	ts := cardServer(card, card, "public, max-age=86400")
	defer ts.Close()

	f := onlyFinding(t, runCardTrust(t, ts))
	if f.Confidence != attack.RiskIndicator || f.Severity != "medium" {
		t.Errorf("want medium/RiskIndicator, got %q/%q", f.Severity, f.Confidence)
	}
}

func TestCardTrust_MustRevalidateDoesNotShortenFreshness(t *testing.T) {
	card := unsignedCard()
	for _, policy := range []string{
		"public, max-age=86400, must-revalidate",
		"public, max-age=86400, immutable, must-revalidate",
	} {
		t.Run(policy, func(t *testing.T) {
			ts := cardServer(card, card, policy)
			defer ts.Close()

			f := onlyFinding(t, runCardTrust(t, ts))
			if f.Confidence != attack.RiskIndicator || f.Severity != "medium" {
				t.Errorf("want medium/RiskIndicator, got %q/%q", f.Severity, f.Confidence)
			}
		})
	}
}

func TestCardTrust_ShortFreshnessWithMustRevalidate(t *testing.T) {
	card := unsignedCard()
	ts := cardServer(card, card, "public, max-age=300, must-revalidate")
	defer ts.Close()

	if findings := runCardTrust(t, ts); len(findings) != 0 {
		t.Errorf("expected no long-cache finding, got %+v", findings)
	}
}

// TestCardTrust_MissingCache: consistent unsigned card, no Cache-Control header.
// MUST fire a single low cache indicator.
func TestCardTrust_MissingCache(t *testing.T) {
	card := unsignedCard()
	ts := cardServer(card, card, "")
	defer ts.Close()

	f := onlyFinding(t, runCardTrust(t, ts))
	if f.Severity != "low" || f.Confidence != attack.RiskIndicator {
		t.Errorf("want low/RiskIndicator, got %q/%q", f.Severity, f.Confidence)
	}
}

func TestCardTrust_CachePoliciesAcrossPaths(t *testing.T) {
	card := unsignedCard()
	for _, tc := range []struct {
		name         string
		primaryCard  interface{}
		legacyCard   interface{}
		primaryCache string
		legacyCache  string
		severity     string
		path         string
	}{
		{"stale legacy", card, card, "no-cache", "public, max-age=86400", "medium", "/.well-known/agent.json"},
		{"stale primary", card, card, "public, max-age=86400", "no-cache", "medium", "/.well-known/agent-card.json"},
		{"stale over missing", card, card, "", "public, max-age=86400", "medium", "/.well-known/agent.json"},
		{"stale primary over missing legacy", card, card, "public, max-age=86400", "", "medium", "/.well-known/agent-card.json"},
		{"same risk on both paths", card, card, "public, max-age=86400", "public, max-age=86400", "medium", "/.well-known/agent-card.json"},
		{"primary on severity tie", card, card, "max-age=3600", "max-age=31536000", "medium", "/.well-known/agent-card.json"},
		{"missing legacy", card, card, "no-cache", "", "low", "/.well-known/agent.json"},
		{"legacy only", nil, card, "", "public, max-age=86400", "medium", "/.well-known/agent.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := cardServerWithCachePolicies(tc.primaryCard, tc.legacyCard, tc.primaryCache, tc.legacyCache)
			defer ts.Close()

			f := onlyFinding(t, runCardTrust(t, ts))
			if f.Severity != tc.severity || f.TargetURL != ts.URL+tc.path {
				t.Errorf("want %s finding for %s, got %s for %s", tc.severity, tc.path, f.Severity, f.TargetURL)
			}
		})
	}
}

func TestCardTrust_CacheFindingWithSignatureMismatch(t *testing.T) {
	ts := cardServerWithCachePolicies(signedCard("https://agent.example/", nil), unsignedCard(), "no-cache", "max-age=86400")
	defer ts.Close()

	findings := runCardTrust(t, ts)
	if len(findings) != 2 {
		t.Fatalf("want signature and cache findings, got %+v", findings)
	}
	if findings[0].Severity != "high" || findings[1].Severity != "medium" ||
		findings[1].TargetURL != ts.URL+"/.well-known/agent.json" {
		t.Errorf("unexpected findings: %+v", findings)
	}
}

// The documented A2A protected header has no exp claim.
func TestCardTrust_StandardSignatureNoExpiry(t *testing.T) {
	card := signedCard("https://agent.example/", nil)
	ts := cardServer(card, card, "no-cache")
	defer ts.Close()

	if findings := runCardTrust(t, ts); len(findings) != 0 {
		t.Errorf("expected no expiry finding for a standard protected header, got %+v", findings)
	}
}

// A custom exp field does not establish how consuming clients treat the card.
func TestCardTrust_CustomExpiredHeader(t *testing.T) {
	card := signedCard("https://agent.example/", past())
	ts := cardServer(card, card, "no-store")
	defer ts.Close()

	if findings := runCardTrust(t, ts); len(findings) != 0 {
		t.Errorf("expected no expiry finding for a custom header, got %+v", findings)
	}
}

// Consistent cards with a revalidating cache policy stay silent.
func TestCardTrust_Clean(t *testing.T) {
	card := signedCard("https://agent.example/", future())
	ts := cardServer(card, card, "no-cache")
	defer ts.Close()

	if findings := runCardTrust(t, ts); len(findings) != 0 {
		t.Errorf("expected zero findings against a well-configured card, got %d: %+v", len(findings), findings)
	}
}

// TestCardTrust_UnsignedCardStaysSilent: a uniformly unsigned card is
// spec-compliant. The A2A spec makes signatures optional, so an agent whose
// card carries no signatures field at all is not a defect this rule reports;
// the actionable case, signed on one well-known path and unsigned on the
// other, is the canonicalization check above.
func TestCardTrust_UnsignedCardStaysSilent(t *testing.T) {
	card := map[string]interface{}{
		"name": "Test Agent",
		"url":  "https://agent.example/",
		"capabilities": map[string]interface{}{
			"streaming":         true,
			"pushNotifications": true,
		},
		"skills": []interface{}{
			map[string]interface{}{"id": "echo", "name": "Echo", "description": "Echo", "tags": []string{"echo"}},
		},
	}
	ts := cardServer(card, card, "no-store")
	defer ts.Close()

	if findings := runCardTrust(t, ts); len(findings) != 0 {
		t.Errorf("expected zero findings for a uniformly unsigned (spec-compliant) card, got %d: %+v", len(findings), findings)
	}
}

// TestCardTrust_NotACardServer: no well-known card means the rule was never
// exercised, not that the card is sound. It used to report clean here, which is
// indistinguishable from a target whose card passed every check.
func TestCardTrust_NotACardServer(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	defer ts.Close()

	findings, err := a2a.NewCardTrustExecutor(testRuleCtx()).Execute(context.Background(), ts.URL, attack.Options{TimeoutSeconds: 5})
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected ErrInconclusive against a non-card server, got err=%v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings against a non-card server, got %d", len(findings))
	}
}
