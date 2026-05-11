// Package mcp contains attack executors for the MCP (Model Context Protocol).
package mcp

import (
	"context"
	"fmt"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// OAuthDCRExecutor tests whether an MCP server's OAuth 2.1 dynamic client
// registration (DCR) endpoint enforces scope restrictions (rule mcp-oauth-dcr-001).
//
// Attack sequence:
//  1. Discover the DCR endpoint via /.well-known/oauth-authorization-server.
//  2. Register a minimal client with only read scopes.
//  3. Register a client requesting admin/write scopes.
//  4. Probe redirect URI validation with localhost and open-redirect URIs.
type OAuthDCRExecutor struct {
	rule attack.RuleContext
}

// NewOAuthDCRExecutor creates an executor for the oauth-dcr-scope-escalation attack type.
func NewOAuthDCRExecutor(r attack.RuleContext) *OAuthDCRExecutor {
	return &OAuthDCRExecutor{rule: r}
}

var (
	// adminScopes are MCP-specific high-privilege scopes that should not be granted to
	// a read-only client. Standard OIDC scopes (openid, profile, email) are intentionally
	// excluded because many authorization servers grant them by default and they do not
	// imply privilege escalation in the MCP context.
	adminScopes = []string{"admin", "tools:write", "resources:write", "prompts:write", "write", "superuser", "root"}

	// maliciousRedirects are redirect URIs that should be rejected by a compliant server.
	maliciousRedirects = []string{
		"http://localhost/steal",
		"http://127.0.0.1/steal",
		"https://evil.example.com/callback",
	}
)

// Execute runs the DCR scope escalation test.
func (e *OAuthDCRExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	// metadata discovery may use any configured token; DCR registrations must
	// be unauthenticated to correctly test for missing Initial Access Token (IAT).
	client := attack.NewHTTPClient(opts, vars)
	unauthClient := attack.NewUnauthHTTPClient(opts, vars)

	// Step 1: Discover the OAuth metadata endpoint to find the registration endpoint.
	registrationEndpoint, err := e.discoverRegistrationEndpoint(ctx, client, vars.BaseURL)
	if err != nil {
		// Not a finding — this MCP server may not use OAuth 2.1.
		return nil, nil //nolint:nilerr
	}

	var findings []attack.Finding

	// Step 2: Baseline registration — minimal read-only client.
	baselineBody := map[string]interface{}{
		"client_name":    "batesian-probe-" + vars.RandID,
		"redirect_uris":  []string{"https://batesian.invalid/callback"},
		"grant_types":    []string{"authorization_code"},
		"response_types": []string{"code"},
		"scope":          "tools:read",
	}
	baselineResp, err := unauthClient.POST(ctx, registrationEndpoint, nil, baselineBody)
	if err != nil {
		return nil, fmt.Errorf("DCR baseline registration failed: %w", err)
	}

	// A successful DCR returns HTTP 201 Created.
	if baselineResp.StatusCode == 200 || baselineResp.StatusCode == 201 {
		findings = append(findings, attack.Finding{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "medium",
			Confidence: attack.ConfirmedExploit,
			Title:      "MCP OAuth DCR endpoint accepts unauthenticated client registration",
			Description: fmt.Sprintf("The OAuth 2.1 dynamic client registration endpoint at %s accepted a new client "+
				"registration without any Initial Access Token (IAT) or other authentication. "+
				"Per RFC 7591, unauthenticated DCR allows any party to register OAuth clients.", registrationEndpoint),
			Evidence:    fmt.Sprintf("HTTP %d from %s\n%s", baselineResp.StatusCode, registrationEndpoint, snippetMCP(baselineResp.Body)),
			Remediation: e.rule.Remediation,
			TargetURL:   registrationEndpoint,
		})
	}

	// Step 3: Escalated registration — request admin/write scopes.
	escalatedScope := "tools:read tools:write resources:write prompts:write admin superuser"
	escalatedBody := map[string]interface{}{
		"client_name":    "batesian-probe-" + vars.RandID + "-esc",
		"redirect_uris":  []string{"https://batesian.invalid/callback"},
		"grant_types":    []string{"authorization_code"},
		"response_types": []string{"code"},
		"scope":          escalatedScope,
	}
	escalatedResp, err := unauthClient.POST(ctx, registrationEndpoint, nil, escalatedBody)
	if err == nil && (escalatedResp.StatusCode == 200 || escalatedResp.StatusCode == 201) {
		grantedScope := escalatedResp.JSONField("scope")
		if hasAdminScope(grantedScope) {
			findings = append(findings, attack.Finding{
				RuleID:     e.rule.ID,
				RuleName:   e.rule.Name,
				Severity:   "critical",
				Confidence: attack.ConfirmedExploit,
				Title:      "MCP OAuth DCR granted admin/write scopes to unauthenticated client",
				Description: fmt.Sprintf("The DCR endpoint granted the following scopes to an unauthenticated client: %q. "+
					"Admin and write scopes should require explicit approval and should not be granted via DCR without "+
					"an Initial Access Token. An attacker can use this to obtain tokens with full write access.", grantedScope),
				Evidence:    fmt.Sprintf("Requested: %q\nGranted: %q\nHTTP %d from %s\n%s", escalatedScope, grantedScope, escalatedResp.StatusCode, registrationEndpoint, snippetMCP(escalatedResp.Body)),
				Remediation: e.rule.Remediation,
				TargetURL:   registrationEndpoint,
			})
		}
	}

	// Step 4: Redirect URI validation.
	redirectBody := map[string]interface{}{
		"client_name": "batesian-redirect-probe-" + vars.RandID,
		"redirect_uris": append([]string{"https://batesian.invalid/callback"},
			maliciousRedirects...),
		"grant_types":    []string{"authorization_code"},
		"response_types": []string{"code"},
		"scope":          "tools:read",
	}
	redirectResp, err := unauthClient.POST(ctx, registrationEndpoint, nil, redirectBody)
	if err == nil && (redirectResp.StatusCode == 200 || redirectResp.StatusCode == 201) {
		findings = append(findings, attack.Finding{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "high",
			Confidence: attack.ConfirmedExploit,
			Title:      "MCP OAuth DCR accepted localhost and open-redirect URIs",
			Description: fmt.Sprintf("The DCR endpoint accepted redirect URIs including localhost (%s) and external domains (%s). "+
				"Accepting localhost redirect URIs enables token theft on multi-user systems. "+
				"Accepting arbitrary external domains enables open-redirect attacks in OAuth flows.",
				"http://localhost/steal", "https://evil.example.com/callback"),
			Evidence:    fmt.Sprintf("Submitted redirect_uris: %v\nHTTP %d\n%s", append([]string{"https://batesian.invalid/callback"}, maliciousRedirects...), redirectResp.StatusCode, snippetMCP(redirectResp.Body)),
			Remediation: e.rule.Remediation,
			TargetURL:   registrationEndpoint,
		})
	}

	return findings, nil
}

// discoverRegistrationEndpoint fetches the OAuth server metadata to find the
// registration_endpoint. Tries /.well-known/oauth-authorization-server first,
// then /.well-known/openid-configuration.
func (e *OAuthDCRExecutor) discoverRegistrationEndpoint(ctx context.Context, client *attack.HTTPClient, baseURL string) (string, error) {
	endpoints := []string{
		baseURL + "/.well-known/oauth-authorization-server",
		baseURL + "/.well-known/openid-configuration",
	}
	for _, ep := range endpoints {
		resp, err := client.GET(ctx, ep, nil)
		if err != nil || !resp.IsSuccess() {
			continue
		}
		regEP := resp.JSONField("registration_endpoint")
		if regEP != "" {
			return regEP, nil
		}
	}
	return "", fmt.Errorf("no OAuth authorization server metadata found at %s", baseURL)
}

// hasAdminScope returns true if grantedScope contains any high-privilege scope.
func hasAdminScope(grantedScope string) bool {
	for _, s := range adminScopes {
		if strings.Contains(grantedScope, s) {
			return true
		}
	}
	return false
}

func snippetMCP(body []byte) string {
	const maxLen = 300
	if len(body) > maxLen {
		return string(body[:maxLen]) + "..."
	}
	return string(body)
}
