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

func v1Card(url string) map[string]interface{} {
	return map[string]interface{}{
		"name": "Test Agent",
		"supportedInterfaces": []interface{}{
			map[string]interface{}{"url": url, "protocolBinding": "JSONRPC", "protocolVersion": "1.0"},
		},
	}
}

func signedV1Card(url string) map[string]interface{} {
	card := v1Card(url)
	card["signatures"] = signedCard(url, nil)["signatures"]
	return card
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

func TestCardTrust_V1PreferredEndpointMismatch(t *testing.T) {
	ts := cardServer(signedV1Card("https://agent.example/a2a"), signedV1Card("https://other.example/a2a"), "no-store")
	defer ts.Close()

	f := onlyFinding(t, runCardTrust(t, ts))
	if f.Severity != "medium" || f.Confidence != attack.RiskIndicator {
		t.Errorf("want medium/RiskIndicator, got %q/%q", f.Severity, f.Confidence)
	}
}

func TestCardTrust_MixedVersionEndpointsAreNotCompared(t *testing.T) {
	ts := cardServer(signedV1Card("https://agent.example/a2a"), signedCard("https://other.example/a2a", nil), "no-store")
	defer ts.Close()

	if findings := runCardTrust(t, ts); len(findings) != 0 {
		t.Errorf("expected no cross-version endpoint finding, got %+v", findings)
	}
}

func TestCardTrust_DifferentPreferredInterfacesAreNotCompared(t *testing.T) {
	for _, tc := range []struct {
		name  string
		field string
		value string
	}{
		{"version", "protocolVersion", "0.3"},
		{"binding", "protocolBinding", "HTTP+JSON"},
		{"tenant", "tenant", "tenant-b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			primary := signedV1Card("https://agent.example/v1")
			legacy := signedV1Card("https://agent.example/other")
			legacy["supportedInterfaces"].([]interface{})[0].(map[string]interface{})[tc.field] = tc.value
			ts := cardServer(primary, legacy, "no-store")
			defer ts.Close()

			if findings := runCardTrust(t, ts); len(findings) != 0 {
				t.Errorf("expected no finding for different %s, got %+v", tc.field, findings)
			}
		})
	}
}

func TestCardTrust_EquivalentPreferredEndpoints(t *testing.T) {
	for _, tc := range []struct {
		name    string
		primary map[string]interface{}
		legacy  map[string]interface{}
	}{
		{"v1", v1Card("https://agent.example/a2a"), v1Card("https://agent.example/a2a")},
		{"mixed versions", signedV1Card("https://agent.example/a2a"), signedCard("https://agent.example/a2a", nil)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := cardServer(tc.primary, tc.legacy, "no-store")
			defer ts.Close()

			if findings := runCardTrust(t, ts); len(findings) != 0 {
				t.Errorf("expected matching preferred endpoints, got %+v", findings)
			}
		})
	}
}

func TestCardTrust_V1PreferredEndpointOverridesLegacyURL(t *testing.T) {
	primary := v1Card("https://agent.example/a2a")
	primary["url"] = "https://old.example/a2a"
	ts := cardServer(primary, v1Card("https://agent.example/a2a"), "no-store")
	defer ts.Close()

	if findings := runCardTrust(t, ts); len(findings) != 0 {
		t.Errorf("expected v1 interface to take precedence, got %+v", findings)
	}
}

func TestCardTrust_MissingPreferredEndpoint(t *testing.T) {
	for _, tc := range []struct {
		name    string
		primary map[string]interface{}
		legacy  map[string]interface{}
		path    string
	}{
		{"empty v1 interfaces", v1Card("https://agent.example/a2a"), map[string]interface{}{"name": "Test Agent", "supportedInterfaces": []interface{}{}}, "/.well-known/agent.json"},
		{"missing legacy url", v1Card("https://agent.example/a2a"), map[string]interface{}{"name": "Test Agent"}, "/.well-known/agent.json"},
		{"both missing", map[string]interface{}{"name": "Test Agent"}, map[string]interface{}{"name": "Test Agent"}, "/.well-known/agent-card.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := cardServer(tc.primary, tc.legacy, "no-store")
			defer ts.Close()

			f := onlyFinding(t, runCardTrust(t, ts))
			if f.Severity != "medium" || f.TargetURL != ts.URL+tc.path {
				t.Errorf("want medium finding for %s, got %s for %s", tc.path, f.Severity, f.TargetURL)
			}
		})
	}
}

func TestCardTrust_IncompleteV1PreferredInterface(t *testing.T) {
	for _, field := range []string{"url", "protocolBinding", "protocolVersion"} {
		t.Run(field, func(t *testing.T) {
			legacy := v1Card("https://agent.example/a2a")
			delete(legacy["supportedInterfaces"].([]interface{})[0].(map[string]interface{}), field)
			ts := cardServer(v1Card("https://agent.example/a2a"), legacy, "no-store")
			defer ts.Close()

			f := onlyFinding(t, runCardTrust(t, ts))
			if f.Severity != "medium" || f.TargetURL != ts.URL+"/.well-known/agent.json" {
				t.Errorf("want medium finding for incomplete legacy path, got %+v", f)
			}
		})
	}
}

func TestCardTrust_LegacyDefaultTransport(t *testing.T) {
	primary := signedCard("https://agent.example/a2a", nil)
	legacy := signedCard("https://agent.example/a2a", nil)
	legacy["preferredTransport"] = "JSONRPC"
	ts := cardServer(primary, legacy, "no-store")
	defer ts.Close()

	if findings := runCardTrust(t, ts); len(findings) != 0 {
		t.Errorf("expected omitted legacy transport to default to JSONRPC, got %+v", findings)
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

func TestCardTrust_ImmutableFreshness(t *testing.T) {
	card := unsignedCard()
	for _, tc := range []struct {
		name     string
		policy   string
		severity string
	}{
		{"no max-age", "public, immutable", "low"},
		{"short max-age", "public, immutable, max-age=300", ""},
		{"long max-age", "public, immutable, max-age=86400", "medium"},
		{"zero max-age", "public, immutable, max-age=0", ""},
		{"long shared max-age", "public, immutable, s-maxage=86400", "medium"},
		{"shared max-age overrides zero", "public, immutable, max-age=0, s-maxage=86400", "medium"},
		{"short shared max-age", "public, immutable, s-maxage=300", "low"},
		{"private shared max-age", "private, immutable, s-maxage=86400", "low"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := cardServer(card, card, tc.policy)
			defer ts.Close()

			findings := runCardTrust(t, ts)
			if tc.severity == "" {
				if len(findings) != 0 {
					t.Errorf("expected no cache finding, got %+v", findings)
				}
				return
			}
			f := onlyFinding(t, findings)
			if f.Severity != tc.severity || f.Confidence != attack.RiskIndicator {
				t.Errorf("want %s/RiskIndicator, got %q/%q", tc.severity, f.Severity, f.Confidence)
			}
		})
	}
}

func TestCardTrust_CacheDirectiveBoundaries(t *testing.T) {
	card := unsignedCard()
	for _, tc := range []struct {
		name     string
		policy   string
		severity string
	}{
		{"unqualified no-cache", "public, max-age=86400, No-Cache", ""},
		{"unqualified no-store", "public, max-age=86400, no-store", ""},
		{"qualified no-cache", `public, max-age=86400, no-cache="Set-Cookie"`, "medium"},
		{"qualified no-cache list", `public, no-cache="Set-Cookie, Authorization", max-age=86400`, "medium"},
		{"extension no-cache", "public, max-age=86400, x-no-cache", "medium"},
		{"extension no-store", "public, max-age=86400, x-no-store", "medium"},
		{"extension immutable", "public, x-immutable", ""},
		{"quoted immutable", `public, x-note="immutable"`, ""},
		{"quoted no-store", `public, max-age=86400, x-note="a, no-store"`, "medium"},
		{"escaped quote", `public, max-age=86400, x-note="a\", no-store"`, "medium"},
		{"quoted extension max-age", `public, x-note="a, max-age=86400"`, ""},
		{"quoted private", `private="Set-Cookie, private", s-maxage=86400`, "medium"},
		{"quoted max-age", `public, max-age="86400"`, "medium"},
		{"quoted s-maxage", `public, s-maxage="86400"`, "medium"},
		{"signed max-age", "public, max-age=+86400", ""},
		{"immutable", "public, immutable", "low"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := cardServer(card, card, tc.policy)
			defer ts.Close()

			findings := runCardTrust(t, ts)
			if tc.severity == "" {
				if len(findings) != 0 {
					t.Errorf("expected no cache finding, got %+v", findings)
				}
				return
			}
			f := onlyFinding(t, findings)
			if f.Severity != tc.severity || f.Confidence != attack.RiskIndicator {
				t.Errorf("want %s/RiskIndicator, got %q/%q", tc.severity, f.Severity, f.Confidence)
			}
		})
	}
}

func TestCardTrust_RepeatedCacheControlFields(t *testing.T) {
	card := unsignedCard()
	for _, tc := range []struct {
		name     string
		policies []string
		severity string
	}{
		{"no-cache second", []string{"max-age=86400", "no-cache"}, ""},
		{"long freshness second", []string{"public", "max-age=86400"}, "medium"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for _, policy := range tc.policies {
					w.Header().Add("Cache-Control", policy)
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(card)
			}))
			defer ts.Close()

			findings := runCardTrust(t, ts)
			if tc.severity == "" {
				if len(findings) != 0 {
					t.Errorf("expected no cache finding, got %+v", findings)
				}
				return
			}
			f := onlyFinding(t, findings)
			if f.Severity != tc.severity || f.Confidence != attack.RiskIndicator {
				t.Errorf("want %s/RiskIndicator, got %q/%q", tc.severity, f.Severity, f.Confidence)
			}
		})
	}
}

func TestCardTrust_ExpiresFreshness(t *testing.T) {
	card := unsignedCard()
	now := time.Now().UTC().Truncate(time.Second)
	date := now.Format(http.TimeFormat)
	longExpiry := now.Add(24 * time.Hour).Format(http.TimeFormat)
	shortExpiry := now.Add(5 * time.Minute).Format(http.TimeFormat)
	pastExpiry := now.Add(-time.Hour).Format(http.TimeFormat)
	for _, tc := range []struct {
		name     string
		control  string
		date     string
		expires  string
		severity string
		source   string
	}{
		{"long without Cache-Control", "", date, longExpiry, "medium", "Expires"},
		{"long with public", "public", date, longExpiry, "medium", "Expires"},
		{"short without Cache-Control", "", date, shortExpiry, "", ""},
		{"past without Cache-Control", "", date, pastExpiry, "", ""},
		{"invalid without Cache-Control", "", date, "0", "", ""},
		{"absent Date fallback", "public", "", longExpiry, "medium", "Received"},
		{"invalid Date fallback", "public", "invalid", longExpiry, "medium", "Received"},
		{"max-age overrides Expires", "max-age=0", date, longExpiry, "", ""},
		{"invalid max-age overrides Expires", "max-age=bogus", date, longExpiry, "", ""},
		{"invalid quoted max-age overrides Expires", `max-age="bad"`, date, longExpiry, "", ""},
		{"no-cache overrides Expires", "no-cache", date, longExpiry, "", ""},
		{"short immutable Expires", "immutable", date, shortExpiry, "", ""},
		{"long immutable Expires", "immutable", date, longExpiry, "medium", "Expires"},
		{"shared age leaves private Expires", "s-maxage=0", date, longExpiry, "medium", "Expires"},
		{"long max-age overrides short Expires", "max-age=86400", date, shortExpiry, "medium", "max-age"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.control != "" {
					w.Header().Set("Cache-Control", tc.control)
				}
				if tc.date == "" {
					w.Header()["Date"] = nil
				} else {
					w.Header().Set("Date", tc.date)
				}
				w.Header().Set("Expires", tc.expires)
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(card)
			}))
			defer ts.Close()

			findings := runCardTrust(t, ts)
			if tc.severity == "" {
				if len(findings) != 0 {
					t.Errorf("expected no cache finding, got %+v", findings)
				}
				return
			}
			f := onlyFinding(t, findings)
			if f.Severity != tc.severity || f.Confidence != attack.RiskIndicator || !strings.Contains(f.Evidence, tc.source) {
				t.Errorf("want %s/RiskIndicator from %s, got %+v", tc.severity, tc.source, f)
			}
		})
	}
}

func TestCardTrust_ExpiresAcrossPaths(t *testing.T) {
	card := unsignedCard()
	expires := time.Now().Add(24 * time.Hour).UTC().Format(http.TimeFormat)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/agent.json" {
			w.Header().Set("Expires", expires)
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(card)
	}))
	defer ts.Close()

	f := onlyFinding(t, runCardTrust(t, ts))
	if f.Severity != "medium" || f.TargetURL != ts.URL+"/.well-known/agent.json" {
		t.Errorf("want medium finding on legacy path, got %+v", f)
	}
}

func TestCardTrust_SharedCacheFreshness(t *testing.T) {
	card := unsignedCard()
	for _, policy := range []string{
		"public, s-maxage=86400",
		"public, max-age=86400, s-maxage=0",
		"private, max-age=86400, s-maxage=0",
		`private="Set-Cookie", s-maxage=86400`,
	} {
		t.Run(policy, func(t *testing.T) {
			ts := cardServer(card, card, policy)
			defer ts.Close()

			f := onlyFinding(t, runCardTrust(t, ts))
			if f.Severity != "medium" || f.Confidence != attack.RiskIndicator {
				t.Errorf("want medium/RiskIndicator, got %q/%q", f.Severity, f.Confidence)
			}
		})
	}
}

func TestCardTrust_PrivateDoesNotUseSharedFreshness(t *testing.T) {
	card := unsignedCard()
	ts := cardServer(card, card, "private, s-maxage=86400")
	defer ts.Close()

	if findings := runCardTrust(t, ts); len(findings) != 0 {
		t.Errorf("expected no shared-cache finding for private card, got %+v", findings)
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
