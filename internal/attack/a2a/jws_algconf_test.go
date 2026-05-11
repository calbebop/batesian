package a2a_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/attack/a2a"
)

// buildProtectedHeader base64url-encodes a JSON protected header for use in
// a synthetic JWS signature entry.
func buildProtectedHeader(header map[string]interface{}) string {
	b, _ := json.Marshal(header)
	return base64.RawURLEncoding.EncodeToString(b)
}

// TestJWSAlgConfExecutor_AlgNone verifies that a card with a JWS signature
// whose protected header specifies alg:"none" produces a critical finding.
func TestJWSAlgConfExecutor_AlgNone(t *testing.T) {
	protected := buildProtectedHeader(map[string]interface{}{
		"alg": "none",
		"kid": "test-key-1",
	})

	card := map[string]interface{}{
		"name":         "Test Agent",
		"description":  "Agent with weak JWS",
		"version":      "1.0",
		"capabilities": map[string]interface{}{},
		"skills":       []interface{}{},
		"signatures": []interface{}{
			map[string]interface{}{
				"protected": protected,
				"signature": "",
			},
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/agent-card.json" {
			writeJSON(w, card)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	ex := a2a.NewJWSAlgConfExecutor(testRuleCtx())
	findings, err := ex.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for alg:none, got zero")
	}
	var hasCritical bool
	for _, f := range findings {
		if f.Severity == "critical" {
			hasCritical = true
			break
		}
	}
	if !hasCritical {
		t.Errorf("expected a critical finding for alg:none, got: %+v", findings)
	}
	rc := testRuleCtx()
	for _, f := range findings {
		if f.RuleID != rc.ID {
			t.Errorf("finding RuleID = %q, want %q", f.RuleID, rc.ID)
		}
		if f.Confidence == "" {
			t.Errorf("finding missing Confidence field (RuleID=%s, Title=%q)", f.RuleID, f.Title)
		}
	}
}

// TestJWSAlgConfExecutor_NoSignatures verifies that a card advertising
// supportsAuthenticatedExtendedCard without any JWS signatures produces an
// info-level finding.
func TestJWSAlgConfExecutor_NoSignatures(t *testing.T) {
	card := map[string]interface{}{
		"name":                              "Test Agent",
		"description":                       "Agent with no signatures",
		"version":                           "1.0",
		"capabilities":                      map[string]interface{}{},
		"skills":                            []interface{}{},
		"defaultInputModes":                 []string{"text"},
		"supportsAuthenticatedExtendedCard": true,
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/agent-card.json" {
			writeJSON(w, card)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	ex := a2a.NewJWSAlgConfExecutor(testRuleCtx())
	findings, err := ex.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one info finding for missing signatures, got zero")
	}
	var hasInfo bool
	for _, f := range findings {
		if f.Severity == "info" {
			hasInfo = true
			break
		}
	}
	if !hasInfo {
		t.Errorf("expected an info finding for missing JWS signatures, got: %+v", findings)
	}
	for _, f := range findings {
		if f.Confidence == "" {
			t.Errorf("finding missing Confidence field (Title=%q)", f.Title)
		}
		if f.Confidence != attack.ConfirmedExploit && f.Confidence != attack.RiskIndicator {
			t.Errorf("unexpected Confidence %q for finding %q", f.Confidence, f.Title)
		}
	}
}

// TestJWSAlgConfExecutor_NotFound verifies that a 404 response from the card
// endpoint produces zero findings and a nil error.
func TestJWSAlgConfExecutor_NotFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer ts.Close()

	ex := a2a.NewJWSAlgConfExecutor(testRuleCtx())
	findings, err := ex.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("expected nil error for 404, got: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings for 404, got %d: %+v", len(findings), findings)
	}
}
