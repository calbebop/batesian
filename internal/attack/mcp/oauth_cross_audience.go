package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/calbebop/batesian/internal/attack"
)

type audienceJWT struct {
	issuer    string
	audiences []string
}

func parseAudienceJWT(token string, now time.Time) (audienceJWT, error) {
	parts := strings.Split(token, ".")
	if len(token) > 16<<10 || len(parts) != 3 || parts[2] == "" {
		return audienceJWT{}, errors.New("credential must be a compact signed JWT of at most 16 KiB")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return audienceJWT{}, errors.New("credential has an invalid JWT header")
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if json.Unmarshal(headerBytes, &header) != nil || header.Alg == "" || strings.EqualFold(header.Alg, "none") {
		return audienceJWT{}, errors.New("credential needs a signed JWT algorithm")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return audienceJWT{}, errors.New("credential has an invalid JWT payload")
	}
	var claims struct {
		Issuer    string          `json:"iss"`
		Audience  json.RawMessage `json:"aud"`
		Expires   *int64          `json:"exp"`
		NotBefore *int64          `json:"nbf"`
	}
	if json.Unmarshal(payloadBytes, &claims) != nil || claims.Issuer == "" || claims.Expires == nil {
		return audienceJWT{}, errors.New("credential needs an issuer and expiry")
	}
	if *claims.Expires <= now.Add(time.Minute).Unix() ||
		(claims.NotBefore != nil && *claims.NotBefore > now.Unix()) {
		return audienceJWT{}, errors.New("credential is expired or not yet valid")
	}
	var audiences []string
	if len(claims.Audience) > 0 && claims.Audience[0] == '[' {
		if json.Unmarshal(claims.Audience, &audiences) != nil {
			return audienceJWT{}, errors.New("credential has an invalid audience array")
		}
	} else {
		var audience string
		if json.Unmarshal(claims.Audience, &audience) != nil {
			return audienceJWT{}, errors.New("credential needs an audience")
		}
		audiences = []string{audience}
	}
	if len(audiences) == 0 {
		return audienceJWT{}, errors.New("credential needs an audience")
	}
	for _, audience := range audiences {
		if audience == "" {
			return audienceJWT{}, errors.New("credential has an empty audience")
		}
	}
	return audienceJWT{issuer: claims.Issuer, audiences: audiences}, nil
}

func hasAudience(audiences []string, expected string) bool {
	for _, audience := range audiences {
		if audience == expected {
			return true
		}
	}
	return false
}

func (e *OAuthAudienceExecutor) probeCrossAudience(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	if opts.Token == "" {
		return nil, fmt.Errorf("%w: the cross-audience probe requires a working target bearer token", attack.ErrInconclusive)
	}
	otherToken := opts.MCPCrossAudienceToken
	if otherToken == "" || otherToken == opts.Token {
		return nil, fmt.Errorf("%w: the cross-audience probe needs a distinct bearer token", attack.ErrInconclusive)
	}

	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewUnauthHTTPClient(opts, vars)
	expected := strings.TrimSpace(opts.AudienceClaim)
	advertised, _, _, discoveryErr := discoverExpectedAudience(ctx, client, client, vars.BaseURL)
	if discoveryErr != nil {
		return nil, fmt.Errorf("%w: protected-resource metadata could not be verified: %v", attack.ErrInconclusive, discoveryErr)
	}
	if expected == "" {
		expected = advertised
	} else if advertised != "" && advertised != expected {
		return nil, fmt.Errorf("%w: the configured audience differs from protected-resource metadata", attack.ErrInconclusive)
	}
	if expected == "" {
		return nil, fmt.Errorf("%w: the cross-audience probe needs --audience-claim or protected-resource metadata", attack.ErrInconclusive)
	}

	now := time.Now()
	targetJWT, err := parseAudienceJWT(opts.Token, now)
	if err != nil {
		return nil, fmt.Errorf("%w: target token: %v", attack.ErrInconclusive, err)
	}
	otherJWT, err := parseAudienceJWT(otherToken, now)
	if err != nil {
		return nil, fmt.Errorf("%w: other-resource token: %v", attack.ErrInconclusive, err)
	}
	if targetJWT.issuer != otherJWT.issuer || !hasAudience(targetJWT.audiences, expected) ||
		hasAudience(otherJWT.audiences, expected) {
		return nil, fmt.Errorf("%w: tokens need the same issuer, a target audience on the working token, and no target audience on the other token", attack.ErrInconclusive)
	}

	var findings []attack.Finding
	var legacyDone, modernDone bool
	var incomplete error
	for _, endpoint := range endpointCandidates(vars.BaseURL) {
		if !legacyDone {
			gate := probeInitGate(ctx, client, endpoint)
			if gate.gate == gateOnInit || gate.gate == gateAfterInit {
				targetVerdict := crossLegacyBearer(ctx, client, endpoint, gate, opts.Token)
				switch targetVerdict {
				case accessGranted:
					legacyDone = true
					otherVerdict := crossLegacyBearer(ctx, client, endpoint, gate, otherToken)
					if otherVerdict == accessGranted {
						findings = append(findings, e.crossAudienceFinding(endpoint, gate.method, EraLegacy))
					} else {
						incomplete = errors.Join(incomplete, fmt.Errorf("%w: the other-resource token was not accepted on the legacy wire; its validity at its own resource was not independently verified", attack.ErrInconclusive))
					}
				case accessUndetermined:
					incomplete = errors.Join(incomplete, fmt.Errorf("%w: the target token could not establish a legacy MCP control", attack.ErrInconclusive))
				}
			}
			if gate.gate == gateAfterInit {
				closeLegacySessions(ctx, client, []mcpSession{gate.session})
			}
		}
		if !modernDone {
			gate := probeModernAuthGate(ctx, client, endpoint)
			if gate.ready {
				_, targetVerdict := probeModernBearer(ctx, client, endpoint, gate.method, opts.Token)
				switch targetVerdict {
				case accessGranted:
					modernDone = true
					_, otherVerdict := probeModernBearer(ctx, client, endpoint, gate.method, otherToken)
					if otherVerdict == accessGranted {
						findings = append(findings, e.crossAudienceFinding(endpoint, gate.method, EraModern))
					} else {
						incomplete = errors.Join(incomplete, fmt.Errorf("%w: the other-resource token was not accepted on the modern wire; its validity at its own resource was not independently verified", attack.ErrInconclusive))
					}
				case accessUndetermined:
					incomplete = errors.Join(incomplete, fmt.Errorf("%w: the target token could not establish a modern MCP control", attack.ErrInconclusive))
				}
			}
		}
		if legacyDone && modernDone {
			break
		}
	}
	if len(findings) > 0 {
		return findings, incomplete
	}
	if incomplete != nil {
		return nil, incomplete
	}
	return nil, fmt.Errorf("%w: no credential-gated MCP method accepted the target token for a cross-audience comparison", attack.ErrInconclusive)
}

func crossLegacyBearer(ctx context.Context, client *attack.HTTPClient, endpoint string, gate gateProbe, token string) accessVerdict {
	headers := map[string]string{"Authorization": "Bearer " + token}
	resp, err := client.POST(ctx, endpoint, headers, json.RawMessage(mcpInitBody))
	verdict := classifyAuthAccess(resp, err, 1)
	if verdict != accessGranted || !initializeSucceeded(resp.Body) {
		if verdict == accessGranted {
			return accessUndetermined
		}
		return verdict
	}
	session := mcpSession{
		Endpoint: endpoint, SessionID: resp.Headers.Get("Mcp-Session-Id"),
		ProtocolVersion: negotiatedVersion(resp.Body), RawInit: resp.Body, Era: EraLegacy,
	}
	defer closeLegacySessionsWith(ctx, client, []mcpSession{session}, func(h map[string]string) {
		h["Authorization"] = "Bearer " + token
	})
	if gate.gate == gateOnInit {
		return accessGranted
	}
	initialized, initErr := client.POST(ctx, endpoint, map[string]string{
		"Authorization":        "Bearer " + token,
		"Mcp-Session-Id":       session.SessionID,
		"Mcp-Protocol-Version": session.ProtocolVersion,
	}, map[string]interface{}{"jsonrpc": "2.0", "method": "notifications/initialized"})
	if !initializedNotificationOK(initialized, initErr) {
		return accessUndetermined
	}
	methodResp, methodErr := session.postShaping(ctx, client, 10, gate.method, nil, func(h map[string]string) {
		h["Authorization"] = "Bearer " + token
	})
	return classifyAuthAccess(methodResp, methodErr, 10)
}

func (e *OAuthAudienceExecutor) crossAudienceFinding(endpoint, method string, era Era) attack.Finding {
	judgedAt := method
	if judgedAt == "" {
		judgedAt = "initialize"
	}
	finding := attack.Finding{
		RuleID: e.rule.ID, RuleName: e.rule.Name, Severity: "high",
		Confidence: attack.RiskIndicator,
		Title:      "MCP accepts a bearer token with another resource's audience",
		Description: "The target accepted a bearer token whose JWT audience excludes its resource identifier. " +
			"A token for the target succeeded and an anonymous request was refused at the same method. " +
			"The operator supplied the other token as valid for another resource; Batesian did not verify its signature at that resource. " +
			"Confirm the token's provenance before attributing this behavior to an SDK audience check.",
		Evidence: fmt.Sprintf("endpoint: %s\nmethod: %s\nanonymous: refused\ntarget token: accepted\nother-audience token: accepted\nJWT issuer: matched; JWT audiences: disjoint",
			endpoint, judgedAt),
		Remediation: e.rule.Remediation, TargetURL: endpoint,
	}
	if era == EraModern {
		return labelEra(mcpSession{Era: EraModern}, []attack.Finding{finding})[0]
	}
	return finding
}
