package a2a_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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
		// This is a static analyzer: it observes a weak config but does not prove
		// a verifier accepts a forged card, so confidence must be an indicator.
		if f.Confidence != attack.RiskIndicator {
			t.Errorf("finding %q: want RiskIndicator (static analysis), got %q", f.Title, f.Confidence)
		}
	}
}

// TestJWSAlgConfExecutor_WellFormedSignature verifies that a card with a sound
// signature config (asymmetric alg, non-empty signature, no jku) produces zero
// findings - the secure/patched case.
func TestJWSAlgConfExecutor_WellFormedSignature(t *testing.T) {
	protected := buildProtectedHeader(map[string]interface{}{
		"alg": "ES256",
		"kid": "prod-key-1",
	})
	card := map[string]interface{}{
		"name":         "Test Agent",
		"version":      "1.0",
		"capabilities": map[string]interface{}{},
		"skills":       []interface{}{},
		"signatures": []interface{}{
			map[string]interface{}{
				"protected": protected,
				"signature": "c2lnbmF0dXJlLWJ5dGVz", // non-empty
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

	findings, err := a2a.NewJWSAlgConfExecutor(testRuleCtx()).Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings for a well-formed signature, got %d: %+v", len(findings), findings)
	}
}

func TestJWSAlgConfExecutor_KeySourceAssessment(t *testing.T) {
	for _, tc := range []struct {
		name           string
		protectedJKU   string
		unprotectedJKU string
		wantSeverity   string
	}{
		{"cross-host HTTPS", "https://keys.example/jwks.json", "", "info"},
		{"cross-host HTTP", "http://keys.example/jwks.json", "", "high"},
		{"same host different port", "https://127.0.0.1:9443/jwks.json", "", ""},
		{"plaintext HTTP", "http://127.0.0.1/jwks.json", "", "high"},
		{"unprotected key URL", "", "https://keys.example/jwks.json", "medium"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			header := map[string]interface{}{"alg": "ES256", "kid": "key-1"}
			if tc.protectedJKU != "" {
				header["jku"] = tc.protectedJKU
			}
			signature := map[string]interface{}{
				"protected": buildProtectedHeader(header),
				"signature": "c2ln",
			}
			if tc.unprotectedJKU != "" {
				signature["header"] = map[string]interface{}{"jku": tc.unprotectedJKU}
			}
			card := map[string]interface{}{
				"name": "", "signatures": []interface{}{signature},
			}
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, card)
			}))
			defer ts.Close()

			findings, err := a2a.NewJWSAlgConfExecutor(testRuleCtx()).Execute(t.Context(), ts.URL, testOpts())
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantSeverity == "" {
				if len(findings) != 0 {
					t.Fatalf("unexpected findings: %+v", findings)
				}
				return
			}
			if len(findings) != 1 || findings[0].Severity != tc.wantSeverity {
				t.Fatalf("findings = %+v, want one %s finding", findings, tc.wantSeverity)
			}
		})
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

// TestJWSAlgConfExecutor_NotFound verifies that a 404 from the card endpoint is
// reported as not tested rather than as clean. The rule analyses signatures on
// the card; with no card there is nothing to analyse, and a clean result would
// read as "the signatures are sound".
func TestJWSAlgConfExecutor_NotFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer ts.Close()

	ex := a2a.NewJWSAlgConfExecutor(testRuleCtx())
	findings, err := ex.Execute(context.Background(), ts.URL, testOpts())
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected ErrInconclusive for a 404 card path, got: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings for 404, got %d: %+v", len(findings), findings)
	}
}

func TestJWSAlgConfExecutor_CanonicalVersionFallback(t *testing.T) {
	weakCard := map[string]interface{}{
		"name": "Test Agent",
		"signatures": []interface{}{
			map[string]interface{}{"protected": buildProtectedHeader(map[string]interface{}{"alg": "none"}), "signature": ""},
		},
	}
	strongCard := map[string]interface{}{
		"name": "Test Agent",
		"signatures": []interface{}{
			map[string]interface{}{"protected": buildProtectedHeader(map[string]interface{}{"alg": "ES256"}), "signature": "c2ln"},
		},
	}
	for _, tc := range []struct {
		name         string
		status       int
		card         map[string]interface{}
		wantFindings int
		incomplete   bool
		wantReason   string
	}{
		{"legacy weak card", http.StatusNotFound, weakCard, 1, false, ""},
		{"legacy sound card", http.StatusNotFound, strongCard, 0, false, ""},
		{"failed version, weak card", http.StatusServiceUnavailable, weakCard, 1, true, "HTTP 503"},
		{"failed version, sound card", http.StatusServiceUnavailable, strongCard, 0, true, "HTTP 503"},
		{"failed version, no fallback card", http.StatusServiceUnavailable, nil, 0, true, "HTTP 503"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/.well-known/agent-card.json" {
					http.NotFound(w, r)
					return
				}
				if r.Header.Get("A2A-Version") == "1.0" {
					w.WriteHeader(tc.status)
					return
				}
				if tc.card == nil {
					http.NotFound(w, r)
					return
				}
				writeJSON(w, tc.card)
			}))
			defer ts.Close()

			findings, err := a2a.NewJWSAlgConfExecutor(testRuleCtx()).Execute(t.Context(), ts.URL, testOpts())
			if len(findings) != tc.wantFindings || errors.Is(err, attack.ErrInconclusive) != tc.incomplete {
				t.Fatalf("want %d findings, incomplete=%v; got findings=%v err=%v", tc.wantFindings, tc.incomplete, findings, err)
			}
			if tc.wantReason != "" && !strings.Contains(err.Error(), tc.wantReason) {
				t.Fatalf("missing failed card read %q: %v", tc.wantReason, err)
			}
			if tc.wantReason != "" && len(findings) > 0 && !strings.Contains(findings[0].Evidence, tc.wantReason) {
				t.Fatalf("finding omitted failed card read: %q", findings[0].Evidence)
			}
		})
	}
}

func TestJWSAlgConfExecutor_MalformedSignaturesIncomplete(t *testing.T) {
	validHeader := buildProtectedHeader(map[string]interface{}{"alg": "ES256"})
	tests := []struct {
		name       string
		signatures interface{}
	}{
		{"non-array", "invalid"},
		{"null-array", nil},
		{"non-object-entry", []interface{}{"invalid"}},
		{"invalid-protected-encoding", []interface{}{map[string]interface{}{"protected": "%%%", "signature": "c2ln"}}},
		{"non-object-protected", []interface{}{map[string]interface{}{"protected": base64.RawURLEncoding.EncodeToString([]byte("null")), "signature": "c2ln"}}},
		{"non-string-signature", []interface{}{map[string]interface{}{"protected": validHeader, "signature": 7}}},
		{"invalid-signature-encoding", []interface{}{map[string]interface{}{"protected": validHeader, "signature": "%%%"}}},
		{"non-object-header", []interface{}{map[string]interface{}{"protected": validHeader, "signature": "c2ln", "header": "invalid"}}},
		{"non-string-alg", []interface{}{map[string]interface{}{"protected": buildProtectedHeader(map[string]interface{}{"alg": 7}), "signature": "c2ln"}}},
		{"non-string-jku", []interface{}{map[string]interface{}{"protected": buildProtectedHeader(map[string]interface{}{"alg": "ES256", "jku": 7}), "signature": "c2ln"}}},
		{"mixed-clean-malformed", []interface{}{
			map[string]interface{}{"protected": validHeader, "signature": "c2ln"},
			map[string]interface{}{"protected": "%%%", "signature": "c2ln"},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/.well-known/agent-card.json" {
					writeJSON(w, map[string]interface{}{"name": "Test Agent", "signatures": tt.signatures})
					return
				}
				http.NotFound(w, r)
			}))
			defer ts.Close()

			findings, err := a2a.NewJWSAlgConfExecutor(testRuleCtx()).Execute(context.Background(), ts.URL, testOpts())
			if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
				t.Fatalf("expected an incomplete result, got %d findings, err=%v", len(findings), err)
			}
		})
	}
}

func TestJWSAlgConfExecutor_NullCardIncomplete(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/agent-card.json" {
			writeJSON(w, nil)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	findings, err := a2a.NewJWSAlgConfExecutor(testRuleCtx()).Execute(context.Background(), ts.URL, testOpts())
	if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected an incomplete result, got %d findings, err=%v", len(findings), err)
	}
}

func TestJWSAlgConfExecutor_NamelessCardIncomplete(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/agent-card.json" {
			writeJSON(w, map[string]interface{}{})
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	findings, err := a2a.NewJWSAlgConfExecutor(testRuleCtx()).Execute(context.Background(), ts.URL, testOpts())
	if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected an incomplete result, got %d findings, err=%v", len(findings), err)
	}
}

func TestJWSAlgConfExecutor_RetainsFindingsWithMalformedEntry(t *testing.T) {
	card := map[string]interface{}{
		"name": "Test Agent",
		"signatures": []interface{}{
			map[string]interface{}{"protected": buildProtectedHeader(map[string]interface{}{"alg": "none"}), "signature": ""},
			map[string]interface{}{"protected": "%%%", "signature": "c2ln"},
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

	findings, err := a2a.NewJWSAlgConfExecutor(testRuleCtx()).Execute(context.Background(), ts.URL, testOpts())
	if !errors.Is(err, attack.ErrInconclusive) || len(findings) == 0 {
		t.Fatalf("expected the valid signature's finding, got %d findings, err=%v", len(findings), err)
	}
	if !strings.Contains(err.Error(), "signature entries [1]") {
		t.Errorf("missing partial-coverage outcome: %v", err)
	}
}
