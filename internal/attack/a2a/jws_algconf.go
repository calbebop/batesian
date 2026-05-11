package a2a

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// JWSAlgConfExecutor inspects A2A AgentCard JWS signatures for algorithm
// confusion vulnerabilities and structural weaknesses (rule a2a-jws-algconf-001).
//
// The A2A v0.3.0 spec added an optional signatures field (RFC 7515 JWS) to
// AgentCards for cryptographic integrity. Common implementation mistakes:
//
//   - alg:none — any verifier reading alg from the header is trivially bypassed
//   - HS256/384/512 — symmetric key unsuitable for public card verification;
//     enables RS256->HS256 confusion attack using the exposed public key
//   - empty signature value — passes broken verifiers that skip bytes check
//   - jku in unprotected header — key URL is outside signature coverage
//   - cross-domain jku — external key server enables key substitution
//   - plain HTTP jku — MITM can substitute malicious keys in transit
//
// This executor only READS the published card and decodes headers — it does not
// forge or attempt to verify any signature.
type JWSAlgConfExecutor struct {
	rule attack.RuleContext
}

// NewJWSAlgConfExecutor creates an executor for the agent-card-jws-algconf attack type.
func NewJWSAlgConfExecutor(r attack.RuleContext) *JWSAlgConfExecutor {
	return &JWSAlgConfExecutor{rule: r}
}

func (e *JWSAlgConfExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)

	cardURL := vars.BaseURL + "/.well-known/agent-card.json"
	resp, err := client.GET(ctx, cardURL, nil)
	if err != nil || !resp.IsSuccess() {
		return nil, nil
	}

	var card map[string]interface{}
	if err := json.Unmarshal(resp.Body, &card); err != nil {
		return nil, nil
	}

	var findings []attack.Finding
	agentHost := hostOnly(vars.BaseURL)

	sigsRaw, _ := card["signatures"].([]interface{})

	// If no signatures are present but the card advertises extended card support,
	// emit an informational finding — no cryptographic integrity guarantee exists.
	if len(sigsRaw) == 0 {
		if card["supportsAuthenticatedExtendedCard"] == true {
			findings = append(findings, attack.Finding{
				RuleID:     e.rule.ID,
				RuleName:   e.rule.Name,
				Severity:   "info",
				Confidence: attack.RiskIndicator,
				Title:      "A2A agent card has no JWS signatures despite advertising authenticated extended card",
				Description: "The agent card advertises supportsAuthenticatedExtendedCard but publishes " +
					"no JWS signatures. Without signatures, agent cards can be spoofed by DNS hijacking " +
					"or MITM. Clients have no cryptographic basis for trusting card contents.",
				Evidence:    fmt.Sprintf("GET %s → HTTP %d, no signatures field", cardURL, resp.StatusCode),
				Remediation: e.rule.Remediation,
				TargetURL:   cardURL,
			})
		}
		return findings, nil
	}

	for i, sigRaw := range sigsRaw {
		sig, ok := sigRaw.(map[string]interface{})
		if !ok {
			continue
		}

		protected, _ := sig["protected"].(string)
		header, _ := sig["header"].(map[string]interface{})
		signature, _ := sig["signature"].(string)

		headerJSON, err := base64.RawURLEncoding.DecodeString(protected)
		if err != nil {
			continue
		}

		var protectedHeader map[string]interface{}
		if err := json.Unmarshal(headerJSON, &protectedHeader); err != nil {
			continue
		}

		alg, _ := protectedHeader["alg"].(string)
		jku, _ := protectedHeader["jku"].(string)

		// Check 1: alg:none or missing alg
		switch strings.ToLower(alg) {
		case "none", "":
			findings = append(findings, attack.Finding{
				RuleID:     e.rule.ID,
				RuleName:   e.rule.Name,
				Severity:   "critical",
				Confidence: attack.ConfirmedExploit,
				Title:      fmt.Sprintf("A2A agent card signatures[%d] uses alg:%q — trivially forgeable", i, alg),
				Description: "The JWS protected header specifies alg:\"none\", meaning no signature " +
					"material protects the card. Any attacker can serve a forged card that passes " +
					"verification in any library that reads the algorithm from the token header.",
				Evidence:    fmt.Sprintf("signatures[%d].protected decodes to: %s", i, string(headerJSON)),
				Remediation: e.rule.Remediation,
				TargetURL:   cardURL,
			})
		}

		// Check 2: symmetric algorithms unsuitable for public card verification
		if strings.HasPrefix(strings.ToUpper(alg), "HS") {
			findings = append(findings, attack.Finding{
				RuleID:     e.rule.ID,
				RuleName:   e.rule.Name,
				Severity:   "high",
				Confidence: attack.RiskIndicator,
				Title:      fmt.Sprintf("A2A agent card signatures[%d] uses symmetric algorithm %s", i, alg),
				Description: fmt.Sprintf("Symmetric algorithm %s requires the verifier to hold the same "+
					"key as the signer. For a public agent card, every verifying client must share the "+
					"signing secret — defeating the purpose of signatures. Also enables RS256->HS256 "+
					"confusion attacks using the exposed public key as the HMAC secret.", alg),
				Evidence:    fmt.Sprintf("signatures[%d].protected: %s", i, string(headerJSON)),
				Remediation: e.rule.Remediation,
				TargetURL:   cardURL,
			})
		}

		// Check 3: empty signature value with non-none alg
		if signature == "" && strings.ToLower(alg) != "none" {
			findings = append(findings, attack.Finding{
				RuleID:     e.rule.ID,
				RuleName:   e.rule.Name,
				Severity:   "critical",
				Confidence: attack.ConfirmedExploit,
				Title:      fmt.Sprintf("A2A agent card signatures[%d] has empty signature value", i),
				Description: "The signature field is empty but alg is not \"none\". This card will " +
					"fail verification in correct implementations but may silently pass broken ones " +
					"that skip the signature bytes check.",
				Evidence:    fmt.Sprintf("signatures[%d]: alg=%s, signature=\"\"", i, alg),
				Remediation: e.rule.Remediation,
				TargetURL:   cardURL,
			})
		}

		// Check 4: jku in protected header but pointing cross-domain
		if jku != "" && agentHost != "" {
			jkuHost := hostOnly(jku)
			if jkuHost != "" && jkuHost != agentHost {
				findings = append(findings, attack.Finding{
					RuleID:     e.rule.ID,
					RuleName:   e.rule.Name,
					Severity:   "medium",
					Confidence: attack.RiskIndicator,
					Title:      fmt.Sprintf("A2A agent card signatures[%d] jku points to external domain %s", i, jkuHost),
					Description: fmt.Sprintf("The jku field (%s) references a JWKS on a different domain than the agent (%s). "+
						"If the external domain is compromised, attackers can replace the keys and forge cards "+
						"that pass verification.", jku, agentHost),
					Evidence:    fmt.Sprintf("agent host: %s, jku host: %s", agentHost, jkuHost),
					Remediation: e.rule.Remediation,
					TargetURL:   cardURL,
				})
			}
			if strings.HasPrefix(jku, "http://") {
				findings = append(findings, attack.Finding{
					RuleID:     e.rule.ID,
					RuleName:   e.rule.Name,
					Severity:   "high",
					Confidence: attack.ConfirmedExploit,
					Title:      fmt.Sprintf("A2A agent card signatures[%d] jku uses plaintext HTTP", i),
					Description: "The jku URL uses HTTP instead of HTTPS. An attacker with network access " +
						"can intercept the JWKS fetch and substitute malicious keys.",
					Evidence:    fmt.Sprintf("jku: %s", jku),
					Remediation: e.rule.Remediation,
					TargetURL:   cardURL,
				})
			}
		}

		// Check 5: jku in the unprotected header — outside signature coverage
		if header != nil {
			if unprotectedJKU, ok := header["jku"].(string); ok && unprotectedJKU != "" {
				findings = append(findings, attack.Finding{
					RuleID:     e.rule.ID,
					RuleName:   e.rule.Name,
					Severity:   "high",
					Confidence: attack.ConfirmedExploit,
					Title:      fmt.Sprintf("A2A agent card signatures[%d] jku is in unprotected header", i),
					Description: "The jku field is in the unprotected JWS header, which is NOT covered by " +
						"the signature. An attacker can modify this field in transit to redirect key lookup " +
						"to an attacker-controlled JWKS endpoint without invalidating the signature.",
					Evidence:    fmt.Sprintf("header.jku: %s (unprotected, not covered by signature)", unprotectedJKU),
					Remediation: e.rule.Remediation,
					TargetURL:   cardURL,
				})
			}
		}
	}

	return findings, nil
}

// hostOnly returns the host component of a URL (host:port or just host).
func hostOnly(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Host
}
