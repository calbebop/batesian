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
	m := map[string]interface{}{"alg": alg}
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
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var card interface{}
		switch r.URL.Path {
		case "/.well-known/agent-card.json":
			card = primary
		case "/.well-known/agent.json":
			card = legacy
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

// TestCardTrust_NoExpirySignature: consistent signed card whose signature has no
// exp. MUST fire a single medium freshness indicator.
func TestCardTrust_NoExpirySignature(t *testing.T) {
	card := signedCard("https://agent.example/", nil)
	ts := cardServer(card, card, "no-cache")
	defer ts.Close()

	f := onlyFinding(t, runCardTrust(t, ts))
	if f.Confidence != attack.RiskIndicator || f.Severity != "medium" {
		t.Errorf("want medium/RiskIndicator, got %q/%q", f.Severity, f.Confidence)
	}
}

// TestCardTrust_ExpiredSignature: consistent signed card whose signature exp is
// in the past. MUST fire indicator/medium (a compliant verifier rejects it; the
// scanner cannot prove the target's verifier ignores exp).
func TestCardTrust_ExpiredSignature(t *testing.T) {
	card := signedCard("https://agent.example/", past())
	ts := cardServer(card, card, "no-store")
	defer ts.Close()

	f := onlyFinding(t, runCardTrust(t, ts))
	if f.Confidence != attack.RiskIndicator || f.Severity != "medium" {
		t.Errorf("want medium/RiskIndicator, got %q/%q", f.Severity, f.Confidence)
	}
}

// TestCardTrust_Clean: identical signed (future-exp) card on both paths with a
// revalidating cache policy. MUST stay silent.
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
			"streaming":          true,
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
