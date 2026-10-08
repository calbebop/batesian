package a2a

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/endpoint"
)

const (
	cardPathPrimary = "/.well-known/agent-card.json"
	cardPathLegacy  = "/.well-known/agent.json"
	// staleCacheThreshold is the max-age (seconds) at or above which caching a
	// security-critical trust anchor is treated as a stale-trust risk (1 hour).
	staleCacheThreshold = 3600
)

// CardTrustExecutor checks card consistency across well-known paths and cache policy.
//
// It only reads what the server exposes (it does not forge or verify
// signatures), so every finding is a RiskIndicator rather than a demonstrated
// verifier bypass.
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

	primaryURL := endpoint.AppendPath(vars.BaseURL, cardPathPrimary)
	legacyURL := endpoint.AppendPath(vars.BaseURL, cardPathLegacy)

	primaryBody, primaryCache, primaryOK := fetchCard(ctx, client, primaryURL)
	legacyBody, legacyCache, legacyOK := fetchCard(ctx, client, legacyURL)
	if !primaryOK && !legacyOK {
		// This rule analyses the card, so no card means it was not exercised.
		// It used to return clean here, which reads as "the card is fine" for a
		// target that served none.
		return nil, fmt.Errorf("%w: no agent card was served at %s or %s, and this rule analyses "+
			"the card's transport and caching headers", attack.ErrInconclusive, primaryURL, legacyURL)
	}

	var cacheFindings []attack.Finding
	if primaryOK {
		cacheFindings = e.checkCache(primaryURL, primaryCache)
	}
	if legacyOK {
		legacyFindings := e.checkCache(legacyURL, legacyCache)
		// Report the highest severity; prefer the primary path on ties.
		if len(legacyFindings) > 0 && (len(cacheFindings) == 0 ||
			cacheFindings[0].Severity == "low" && legacyFindings[0].Severity == "medium") {
			cacheFindings = legacyFindings
		}
	}

	var findings []attack.Finding
	findings = append(findings, e.checkCanonicalization(primaryURL, primaryBody, primaryOK, legacyURL, legacyBody, legacyOK)...)
	findings = append(findings, cacheFindings...)
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

	primaryEndpoint, primaryHasEndpoint := preferredCardEndpoint(primaryCard)
	legacyEndpoint, legacyHasEndpoint := preferredCardEndpoint(legacyCard)
	if !primaryHasEndpoint || !legacyHasEndpoint {
		missingURL := primaryURL
		if primaryHasEndpoint {
			missingURL = legacyURL
		}
		return []attack.Finding{{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "medium",
			Confidence: attack.RiskIndicator,
			Title:      "A2A agent card has incomplete preferred endpoint fields",
			Description: "One or both well-known agent cards omit a preferred endpoint URL or required v1 interface fields. " +
				"Clients may fail to route requests, and the two cards' preferred endpoints cannot be compared.",
			Evidence: fmt.Sprintf("%s preferred interface: url=%q binding=%q version=%q\n"+
				"%s preferred interface: url=%q binding=%q version=%q",
				primaryURL, primaryEndpoint.url, primaryEndpoint.binding, primaryEndpoint.version,
				legacyURL, legacyEndpoint.url, legacyEndpoint.binding, legacyEndpoint.version),
			Remediation: e.rule.Remediation,
			TargetURL:   missingURL,
		}}
	}
	if primaryEndpoint.comparableTo(legacyEndpoint) && primaryEndpoint.url != legacyEndpoint.url {
		return []attack.Finding{{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "medium",
			Confidence: attack.RiskIndicator,
			Title:      "A2A agent cards prefer different endpoints across well-known paths (canonicalization ambiguity)",
			Description: fmt.Sprintf(
				"The cards at %s and %s declare different preferred endpoint URLs. A client that selects "+
					"one path may route or verify against an endpoint the other path does not point to; "+
					"verify which card is authoritative and make them consistent.", primaryURL, legacyURL),
			Evidence:    fmt.Sprintf("%s preferred endpoint: %q\n%s preferred endpoint: %q", primaryURL, primaryEndpoint.url, legacyURL, legacyEndpoint.url),
			Remediation: e.rule.Remediation,
			TargetURL:   primaryURL,
		}}
	}
	return nil
}

type cardCacheHeaders struct {
	control    string
	expires    string
	date       string
	receivedAt time.Time
}

// checkCache evaluates the freshness policy on the trust anchor.
func (e *CardTrustExecutor) checkCache(cardURL string, cache cardCacheHeaders) []attack.Finding {
	cc := strings.ToLower(strings.TrimSpace(cache.control))
	if cc == "" && cache.expires == "" {
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
	// These directives prevent unvalidated reuse of the card.
	if hasUnqualifiedDirective(cc, "no-store") || hasUnqualifiedDirective(cc, "no-cache") {
		return nil
	}
	maxAge, hasMaxAge := cacheAgeDirective(cc, "max-age")
	sharedMaxAge, hasSharedMaxAge := cacheAgeDirective(cc, "s-maxage")
	if hasUnqualifiedDirective(cc, "private") {
		hasSharedMaxAge = false
	}
	freshness, directive := maxAge, "max-age"
	if hasSharedMaxAge && (!hasMaxAge || sharedMaxAge > maxAge) {
		freshness, directive = sharedMaxAge, "s-maxage"
	}
	dateSource := "Date: " + cache.date
	if cache.expires != "" && !hasCacheDirective(cc, "max-age") {
		if expires, err := http.ParseTime(cache.expires); err == nil {
			date, err := http.ParseTime(cache.date)
			if err != nil {
				date = cache.receivedAt
				dateSource = "Received: " + date.UTC().Format(http.TimeFormat)
			}
			if lifetime := int(expires.Sub(date).Seconds()); lifetime > freshness {
				freshness, directive = lifetime, "Expires"
			}
		}
	}
	if freshness >= staleCacheThreshold {
		policy := fmt.Sprintf("Cache-Control %q", cache.control)
		evidence := fmt.Sprintf("GET %s\nCache-Control: %s (%s=%d, %.1fh)", cardURL, cache.control, directive, freshness, float64(freshness)/3600)
		if directive == "Expires" {
			policy = fmt.Sprintf("Expires %q", cache.expires)
			evidence = fmt.Sprintf("GET %s\n%s\nExpires: %s (%.1fh)", cardURL, dateSource, cache.expires, float64(freshness)/3600)
		}
		return []attack.Finding{{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "medium",
			Confidence: attack.RiskIndicator,
			Title:      "A2A agent card cache policy may delay trust updates",
			Description: fmt.Sprintf(
				"The agent card is served with %s. Caches can reuse it without "+
					"contacting the origin while it is fresh, so old keys, routing, or security "+
					"schemes may remain in use after a change.", policy),
			Evidence:    evidence,
			Remediation: e.rule.Remediation,
			TargetURL:   cardURL,
		}}
	}
	if !hasMaxAge && cache.expires == "" && hasUnqualifiedDirective(cc, "immutable") {
		return []attack.Finding{{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "low",
			Confidence: attack.RiskIndicator,
			Title:      "A2A agent card marked immutable without max-age",
			Description: "The card is marked immutable but Cache-Control gives no max-age. " +
				"Immutable does not set a freshness lifetime; caches without an applicable explicit " +
				"lifetime may derive one from Expires or heuristics. " +
				"Verify how long clients can reuse the card before checking for updates.",
			Evidence:    fmt.Sprintf("GET %s\nCache-Control: %s", cardURL, cache.control),
			Remediation: e.rule.Remediation,
			TargetURL:   cardURL,
		}}
	}
	return nil
}

// fetchCard GETs an agent card and returns its body and freshness headers.
func fetchCard(ctx context.Context, client *attack.HTTPClient, url string) (body []byte, cache cardCacheHeaders, ok bool) {
	resp, err := client.GET(ctx, url, cardVersionHeaders(url))
	if err != nil || !resp.IsSuccess() {
		return nil, cardCacheHeaders{}, false
	}
	if _, parsed := parseCard(resp.Body); !parsed {
		return nil, cardCacheHeaders{}, false
	}
	return resp.Body, cardCacheHeaders{
		control:    strings.Join(resp.Headers.Values("Cache-Control"), ","),
		expires:    resp.Headers.Get("Expires"),
		date:       resp.Headers.Get("Date"),
		receivedAt: time.Now(),
	}, true
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

type cardEndpoint struct {
	url       string
	binding   string
	version   string
	tenant    string
	cardShape string
}

func (e cardEndpoint) comparableTo(other cardEndpoint) bool {
	return e.cardShape == other.cardShape && e.binding == other.binding &&
		e.version == other.version && e.tenant == other.tenant
}

func preferredCardEndpoint(card map[string]interface{}) (cardEndpoint, bool) {
	if raw, present := card["supportedInterfaces"]; present {
		endpoint := cardEndpoint{cardShape: "v1"}
		interfaces, ok := raw.([]interface{})
		if !ok || len(interfaces) == 0 {
			return endpoint, false
		}
		preferred, ok := interfaces[0].(map[string]interface{})
		if !ok {
			return endpoint, false
		}
		endpoint.url, _ = preferred["url"].(string)
		endpoint.binding, _ = preferred["protocolBinding"].(string)
		endpoint.version, _ = preferred["protocolVersion"].(string)
		endpoint.tenant, _ = preferred["tenant"].(string)
		return endpoint, endpoint.url != "" && endpoint.binding != "" && endpoint.version != ""
	}
	// The v0.3 card field definition defaults an omitted transport to JSONRPC.
	endpoint := cardEndpoint{cardShape: "legacy", binding: "JSONRPC"}
	endpoint.url, _ = card["url"].(string)
	if binding, ok := card["preferredTransport"].(string); ok && binding != "" {
		endpoint.binding = binding
	}
	endpoint.version, _ = card["protocolVersion"].(string)
	return endpoint, endpoint.url != ""
}

// cacheAgeDirective extracts a delta-seconds value from lowercased Cache-Control.
func cacheAgeDirective(cc, directive string) (int, bool) {
	for _, part := range splitCacheDirectives(cc) {
		if strings.HasPrefix(part, directive+"=") {
			value := strings.TrimPrefix(part, directive+"=")
			if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
				value = value[1 : len(value)-1]
			}
			if value == "" {
				continue
			}
			valid := true
			for i := 0; i < len(value); i++ {
				if value[i] < '0' || value[i] > '9' {
					valid = false
					break
				}
			}
			if !valid {
				continue
			}
			if n, err := strconv.Atoi(value); err == nil {
				return n, true
			}
		}
	}
	return 0, false
}

func hasUnqualifiedDirective(cc, directive string) bool {
	for _, part := range splitCacheDirectives(cc) {
		if part == directive {
			return true
		}
	}
	return false
}

func hasCacheDirective(cc, directive string) bool {
	for _, part := range splitCacheDirectives(cc) {
		name, _, _ := strings.Cut(part, "=")
		if name == directive {
			return true
		}
	}
	return false
}

func splitCacheDirectives(cc string) []string {
	var parts []string
	start := 0
	quoted, escaped := false, false
	for i := 0; i < len(cc); i++ {
		switch {
		case escaped:
			escaped = false
		case quoted && cc[i] == '\\':
			escaped = true
		case cc[i] == '"':
			quoted = !quoted
		case cc[i] == ',' && !quoted:
			parts = append(parts, strings.TrimSpace(cc[start:i]))
			start = i + 1
		}
	}
	return append(parts, strings.TrimSpace(cc[start:]))
}
