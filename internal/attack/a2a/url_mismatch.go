package a2a

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// URLMismatchExecutor checks whether the A2A Agent Card url field points to
// a different domain than the host that served the card (rule a2a-url-mismatch-001).
type URLMismatchExecutor struct {
	rule attack.RuleContext
}

// NewURLMismatchExecutor creates an executor for a2a-url-mismatch.
func NewURLMismatchExecutor(r attack.RuleContext) *URLMismatchExecutor {
	return &URLMismatchExecutor{rule: r}
}

func (e *URLMismatchExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)

	// Derive the origin host from the target URL for comparison.
	originHost, err := extractHost(vars.BaseURL)
	if err != nil {
		return nil, nil
	}

	cardPaths := []string{
		"/.well-known/agent.json",
		"/.well-known/agent-card.json",
	}

	for _, path := range cardPaths {
		cardURL := vars.BaseURL + path
		resp, err := client.GET(ctx, cardURL, nil)
		if err != nil || !resp.IsSuccess() {
			continue
		}

		var card map[string]interface{}
		if err := json.Unmarshal(resp.Body, &card); err != nil {
			continue
		}

		findings := e.evaluateCard(card, originHost, cardURL)
		if len(findings) > 0 {
			return findings, nil
		}
		// Card found but no mismatch -- no need to try more paths.
		if len(card) > 0 {
			return nil, nil
		}
	}

	return nil, nil
}

func (e *URLMismatchExecutor) evaluateCard(card map[string]interface{}, originHost, cardURL string) []attack.Finding {
	var findings []attack.Finding

	// Check the top-level url field
	if cardURLField, ok := card["url"].(string); ok && cardURLField != "" {
		if h, err := extractHost(cardURLField); err == nil && !hostsMatch(originHost, h) {
			findings = append(findings, attack.Finding{
				RuleID:     e.rule.ID,
				RuleName:   e.rule.Name,
				Severity:   "medium",
				Confidence: attack.ConfirmedExploit,
				Title: fmt.Sprintf(
					"A2A Agent Card url field points to different domain: card served from %q but url=%q",
					originHost, h),
				Description: fmt.Sprintf(
					"The Agent Card served at %s has its url field set to %q, which resolves to "+
						"host %q. The card was fetched from host %q. Any agent or orchestrator "+
						"that trusts this card will route JSON-RPC task requests to the url domain "+
						"rather than the domain it fetched the card from. This mismatch may indicate "+
						"typosquatting, supply chain compromise, or a misconfigured deployment.",
					cardURL, cardURLField, h, originHost),
				Evidence:    fmt.Sprintf("card_url: %s\ncard.url field: %s\norigin_host: %s\ncard_host: %s", cardURL, cardURLField, originHost, h),
				Remediation: e.rule.Remediation,
				TargetURL:   cardURL,
			})
		}
	}

	// Check provider.url if present
	if provider, ok := card["provider"].(map[string]interface{}); ok {
		if provURL, ok := provider["url"].(string); ok && provURL != "" {
			if h, err := extractHost(provURL); err == nil && !hostsMatch(originHost, h) {
				findings = append(findings, attack.Finding{
					RuleID:     e.rule.ID,
					RuleName:   e.rule.Name,
					Severity:   "low",
					Confidence: attack.RiskIndicator,
					Title: fmt.Sprintf(
						"A2A Agent Card provider.url points to different domain than card host (%q vs %q)",
						h, originHost),
					Description: fmt.Sprintf(
						"The provider.url in the Agent Card at %s is %q (host: %q) while the "+
							"card is served from %q. While provider URL is informational, a mismatch "+
							"warrants review.",
						cardURL, provURL, h, originHost),
					Evidence:    fmt.Sprintf("card_url: %s\nprovider.url: %s\norigin_host: %s", cardURL, provURL, originHost),
					Remediation: e.rule.Remediation,
					TargetURL:   cardURL,
				})
			}
		}
	}

	return findings
}

// extractHost returns the hostname (without port) from a URL string.
func extractHost(rawURL string) (string, error) {
	if !strings.HasPrefix(rawURL, "http") {
		rawURL = "https://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	return strings.ToLower(u.Hostname()), nil
}

// hostsMatch returns true if both hosts are the same or one is a subdomain of
// the other (e.g., "api.example.com" matches "example.com").
func hostsMatch(a, b string) bool {
	if a == b {
		return true
	}
	// Check subdomain relationship
	return strings.HasSuffix(a, "."+b) || strings.HasSuffix(b, "."+a)
}
