package a2a

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/calbebop/batesian/internal/attack"
)

const (
	cardPathPrimary = "/.well-known/agent-card.json"
	cardPathLegacy  = "/.well-known/agent.json"
	// staleCacheThreshold is the max-age (seconds) at or above which caching a
	// security-critical trust anchor is treated as a stale-trust risk (1 hour).
	staleCacheThreshold = 3600
)

// CardTrustExecutor inspects the durability and consistency of an A2A agent
// card's trust properties (rule a2a-card-trust-001): canonicalization across
// well-known paths, cache/TTL of the trust anchor, and signature freshness.
//
// It only reads what the server exposes (it does not forge or verify
// signatures), so every finding is a RiskIndicator: it observes a weak or
// inconsistent trust posture (a signed-vs-unsigned path split, an already-expired
// signature still being served, long-lived caching) but cannot demonstrate that
// a verifier is actually bypassed. Each finding recommends manual verification.
type CardTrustExecutor struct {
	rule attack.RuleContext
}

func init() {
	attack.Register("a2a-card-trust", func(rc attack.RuleContext) attack.Executor { return NewCardTrustExecutor(rc) })
}

func NewCardTrustExecutor(r attack.RuleContext) *CardTrustExecutor {
	return &CardTrustExecutor{rule: r}
}

func (e *CardTrustExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)

	primaryURL := vars.BaseURL + cardPathPrimary
	legacyURL := vars.BaseURL + cardPathLegacy

	primaryBody, primaryCacheControl, primaryOK := fetchCard(ctx, client, primaryURL)
	legacyBody, _, legacyOK := fetchCard(ctx, client, legacyURL)
	if !primaryOK && !legacyOK {
		return nil, nil // not a responsive A2A card server
	}

	// Use whichever path actually served a card as the basis for the cache and
	// signature checks.
	cardURL, cardBody, cacheControl := primaryURL, primaryBody, primaryCacheControl
	if !primaryOK {
		cardURL, cardBody = legacyURL, legacyBody
		_, cacheControl, _ = fetchCard(ctx, client, legacyURL)
	}

	var findings []attack.Finding
	findings = append(findings, e.checkCanonicalization(primaryURL, primaryBody, primaryOK, legacyURL, legacyBody, legacyOK)...)
	findings = append(findings, e.checkCache(cardURL, cacheControl)...)
	findings = append(findings, e.checkSignatureFreshness(cardURL, cardBody)...)
	return findings, nil
}

// checkCanonicalization compares the cards served at the two well-known paths.
func (e *CardTrustExecutor) checkCanonicalization(primaryURL string, primaryBody []byte, primaryOK bool, legacyURL string, legacyBody []byte, legacyOK bool) []attack.Finding {
	if !primaryOK || !legacyOK {
		return nil // only one path serves a card - nothing to compare
	}
	primaryCard, ok1 := parseCard(primaryBody)
	legacyCard, ok2 := parseCard(legacyBody)
	if !ok1 || !ok2 {
		return nil
	}

	primarySigned := cardHasSignatures(primaryCard)
	legacySigned := cardHasSignatures(legacyCard)
	if primarySigned != legacySigned {
		signedURL, unsignedURL := primaryURL, legacyURL
		if legacySigned {
			signedURL, unsignedURL = legacyURL, primaryURL
		}
		return []attack.Finding{{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "high",
			Confidence: attack.RiskIndicator,
			Title:      "A2A agent card is signed on one well-known path but unsigned on the other (signature stripping)",
			Description: fmt.Sprintf(
				"%s serves a card WITH JWS signatures while %s serves the same agent's card WITHOUT "+
					"signatures. An attacker or MITM who can steer a client to the unsigned path could "+
					"bypass signature verification entirely, then substitute forged routing, capability, or "+
					"security-scheme fields. Manually verify whether clients resolve the unsigned path and "+
					"skip signature verification.", signedURL, unsignedURL),
			Evidence:    fmt.Sprintf("signed path: %s\nunsigned path: %s", signedURL, unsignedURL),
			Remediation: e.rule.Remediation,
			TargetURL:   unsignedURL,
		}}
	}

	if primaryURLField(primaryCard) != primaryURLField(legacyCard) {
		return []attack.Finding{{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "medium",
			Confidence: attack.RiskIndicator,
			Title:      "A2A agent card advertises a different url across well-known paths (canonicalization ambiguity)",
			Description: fmt.Sprintf(
				"The cards at %s and %s declare different `url` values. A client that canonicalizes to "+
					"one path may route or verify against an endpoint the other path does not point to; "+
					"verify which card is authoritative and make them consistent.", primaryURL, legacyURL),
			Evidence:    fmt.Sprintf("%s url: %q\n%s url: %q", primaryURL, primaryURLField(primaryCard), legacyURL, primaryURLField(legacyCard)),
			Remediation: e.rule.Remediation,
			TargetURL:   primaryURL,
		}}
	}
	return nil
}

// checkCache evaluates the Cache-Control on the trust anchor.
func (e *CardTrustExecutor) checkCache(cardURL, cacheControl string) []attack.Finding {
	cc := strings.ToLower(strings.TrimSpace(cacheControl))
	if cc == "" {
		return []attack.Finding{{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "low",
			Confidence: attack.RiskIndicator,
			Title:      "A2A agent card served without Cache-Control (heuristic caching of trust anchor)",
			Description: "The agent card response carries no Cache-Control header. Intermediaries and " +
				"clients may heuristically cache this security-critical trust anchor, so a rotated or " +
				"revoked card can keep being served from cache. Set an explicit revalidation policy.",
			Evidence:    fmt.Sprintf("GET %s returned no Cache-Control header", cardURL),
			Remediation: e.rule.Remediation,
			TargetURL:   cardURL,
		}}
	}
	// Explicit revalidation / no-store policies are safe.
	if strings.Contains(cc, "no-store") || strings.Contains(cc, "no-cache") || strings.Contains(cc, "must-revalidate") {
		return nil
	}
	maxAge, hasMaxAge := cacheMaxAge(cc)
	if hasMaxAge && maxAge == 0 {
		return nil
	}
	if strings.Contains(cc, "immutable") || (hasMaxAge && maxAge >= staleCacheThreshold) {
		detail := "marked immutable"
		if hasMaxAge {
			detail = fmt.Sprintf("max-age=%d (%.1fh)", maxAge, float64(maxAge)/3600)
		}
		return []attack.Finding{{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "medium",
			Confidence: attack.RiskIndicator,
			Title:      "A2A agent card cached long-term without revalidation (stale-trust risk)",
			Description: fmt.Sprintf(
				"The agent card is served with Cache-Control %q, instructing clients and intermediaries "+
					"to keep the trust anchor cached without revalidation. After key rotation or a "+
					"compromise, a stale card (old keys, routing, or security schemes) remains trusted "+
					"until the cache expires.", cacheControl),
			Evidence:    fmt.Sprintf("GET %s\nCache-Control: %s (%s, no revalidation)", cardURL, cacheControl, detail),
			Remediation: e.rule.Remediation,
			TargetURL:   cardURL,
		}}
	}
	return nil
}

// checkSignatureFreshness decodes each JWS protected header and flags signatures
// that never expire or whose expiry has already passed.
func (e *CardTrustExecutor) checkSignatureFreshness(cardURL string, cardBody []byte) []attack.Finding {
	card, ok := parseCard(cardBody)
	if !ok {
		return nil
	}
	sigs, _ := card["signatures"].([]interface{})
	if len(sigs) == 0 {
		return nil // signature presence/config is a2a-jws-algconf-001's domain
	}

	now := time.Now().Unix()
	anyExpiry := false
	for i, sigRaw := range sigs {
		sig, ok := sigRaw.(map[string]interface{})
		if !ok {
			continue
		}
		protected, _ := sig["protected"].(string)
		headerJSON, err := base64.RawURLEncoding.DecodeString(protected)
		if err != nil {
			continue
		}
		var header map[string]interface{}
		if err := json.Unmarshal(headerJSON, &header); err != nil {
			continue
		}
		exp, hasExp := numericClaim(header["exp"])
		if !hasExp {
			continue
		}
		anyExpiry = true
		if exp < now {
			return []attack.Finding{{
				RuleID:     e.rule.ID,
				RuleName:   e.rule.Name,
				Severity:   "medium",
				Confidence: attack.RiskIndicator,
				Title:      fmt.Sprintf("A2A agent card signatures[%d] is expired but still served", i),
				Description: fmt.Sprintf(
					"The card signature's protected header declares exp=%d, which is in the past, yet the "+
						"server still serves this signature as the live card. A compliant verifier rejects an "+
						"expired signature; this is exploitable only against a verifier that ignores exp. "+
						"Manually verify whether the target's clients enforce signature expiry.", exp),
				Evidence:    fmt.Sprintf("signatures[%d].protected exp=%d (now=%d, expired %ds ago)", i, exp, now, now-exp),
				Remediation: e.rule.Remediation,
				TargetURL:   cardURL,
			}}
		}
	}

	if !anyExpiry {
		return []attack.Finding{{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "medium",
			Confidence: attack.RiskIndicator,
			Title:      "A2A agent card signatures have no expiry (exp)",
			Description: "The card's JWS signature protected header(s) declare no `exp`. A signature that " +
				"never expires means a card captured once stays cryptographically valid forever, so " +
				"rotating keys or revoking a card cannot bound the trust window.",
			Evidence:    fmt.Sprintf("GET %s: %d signature(s), none declare exp", cardURL, len(sigs)),
			Remediation: e.rule.Remediation,
			TargetURL:   cardURL,
		}}
	}
	return nil
}

// fetchCard GETs an agent card and returns its body, Cache-Control header, and
// whether a JSON card was served.
func fetchCard(ctx context.Context, client *attack.HTTPClient, url string) (body []byte, cacheControl string, ok bool) {
	resp, err := client.GET(ctx, url, nil)
	if err != nil || !resp.IsSuccess() {
		return nil, "", false
	}
	if _, parsed := parseCard(resp.Body); !parsed {
		return nil, "", false
	}
	return resp.Body, resp.Headers.Get("Cache-Control"), true
}

func parseCard(body []byte) (map[string]interface{}, bool) {
	var card map[string]interface{}
	if err := json.Unmarshal(body, &card); err != nil {
		return nil, false
	}
	// A minimal sanity check that this looks like an agent card.
	if _, hasName := card["name"]; !hasName {
		if _, hasURL := card["url"]; !hasURL {
			return nil, false
		}
	}
	return card, true
}

func cardHasSignatures(card map[string]interface{}) bool {
	sigs, _ := card["signatures"].([]interface{})
	return len(sigs) > 0
}

func primaryURLField(card map[string]interface{}) string {
	u, _ := card["url"].(string)
	return u
}

// cacheMaxAge extracts the max-age directive (seconds) from a lowercased
// Cache-Control value.
func cacheMaxAge(cc string) (int, bool) {
	for _, part := range strings.Split(cc, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "max-age=") {
			if n, err := strconv.Atoi(strings.TrimPrefix(part, "max-age=")); err == nil {
				return n, true
			}
		}
	}
	return 0, false
}

// numericClaim coerces a JSON claim value (number or numeric string) to int64.
func numericClaim(v interface{}) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return i, true
		}
	case string:
		if i, err := strconv.ParseInt(n, 10, 64); err == nil {
			return i, true
		}
	}
	return 0, false
}
