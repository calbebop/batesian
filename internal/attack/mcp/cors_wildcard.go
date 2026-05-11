package mcp

import (
	"context"
	"fmt"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// corsProbeOrigin is the attacker-controlled origin sent in CORS probes.
// Using a clearly synthetic domain avoids false positives from real allowlists.
const corsProbeOrigin = "https://evil.batesian.invalid"

// CORSWildcardExecutor checks whether an MCP server reflects arbitrary origins
// or returns Access-Control-Allow-Origin: * in combination with
// Access-Control-Allow-Credentials: true (rule mcp-cors-wildcard-001).
type CORSWildcardExecutor struct {
	rule attack.RuleContext
}

// NewCORSWildcardExecutor creates an executor for mcp-cors-wildcard.
func NewCORSWildcardExecutor(r attack.RuleContext) *CORSWildcardExecutor {
	return &CORSWildcardExecutor{rule: r}
}

func (e *CORSWildcardExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)

	// Probe the MCP endpoint and its root path.
	candidates := []string{
		vars.BaseURL + "/mcp",
		vars.BaseURL + "/",
	}

	var findings []attack.Finding
	seen := map[string]bool{}

	for _, ep := range candidates {
		// OPTIONS preflight
		optResp, err := client.OPTIONS(ctx, ep, map[string]string{
			"Origin":                         corsProbeOrigin,
			"Access-Control-Request-Method":  "POST",
			"Access-Control-Request-Headers": "Content-Type, Authorization",
		})
		if err == nil {
			if f := e.evaluateCORS(optResp, ep, "OPTIONS preflight"); f != nil && !seen[f.Title] {
				seen[f.Title] = true
				findings = append(findings, *f)
			}
		}

		// POST with Origin header — some servers only set CORS headers on non-preflight requests.
		postResp, err := client.POST(ctx, ep, map[string]string{
			"Origin": corsProbeOrigin,
		}, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      99,
			"method":  "initialize",
			"params": map[string]interface{}{
				"protocolVersion": "2025-03-26",
				"capabilities":    map[string]interface{}{},
				"clientInfo":      map[string]interface{}{"name": "batesian", "version": "1.0"},
			},
		})
		if err == nil {
			if f := e.evaluateCORS(postResp, ep, "POST with Origin"); f != nil && !seen[f.Title] {
				seen[f.Title] = true
				findings = append(findings, *f)
			}
		}
	}

	return findings, nil
}

// evaluateCORS inspects a response's CORS headers and returns a Finding if misconfigured.
func (e *CORSWildcardExecutor) evaluateCORS(resp *attack.Response, ep, method string) *attack.Finding {
	acao := resp.Headers.Get("Access-Control-Allow-Origin")
	acac := strings.EqualFold(resp.Headers.Get("Access-Control-Allow-Credentials"), "true")

	if acao == "" {
		return nil
	}

	reflectsAttacker := acao == corsProbeOrigin
	isWildcard := acao == "*"

	switch {
	case (reflectsAttacker || isWildcard) && acac:
		origin := "wildcard (*)"
		if reflectsAttacker {
			origin = "attacker origin"
		}
		return &attack.Finding{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "high",
			Confidence: attack.ConfirmedExploit,
			Title: fmt.Sprintf(
				"MCP CORS policy reflects %s and sets Allow-Credentials: true", origin),
			Description: fmt.Sprintf(
				"The MCP server at %s returned Access-Control-Allow-Origin: %q and "+
					"Access-Control-Allow-Credentials: true in response to a %s from origin %q. "+
					"This allows a malicious web page to make credentialed cross-origin requests "+
					"to the MCP server, invoking tools, reading resources, and listing prompts "+
					"on behalf of any victim whose browser is authenticated to this server.",
				ep, acao, method, corsProbeOrigin),
			Evidence: fmt.Sprintf(
				"%s %s\nOrigin: %s\nAccess-Control-Allow-Origin: %s\nAccess-Control-Allow-Credentials: %s",
				method, ep, corsProbeOrigin, acao, resp.Headers.Get("Access-Control-Allow-Credentials")),
			Remediation: e.rule.Remediation,
			TargetURL:   ep,
		}

	case reflectsAttacker && !acac:
		return &attack.Finding{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "medium",
			Confidence: attack.ConfirmedExploit,
			Title:      "MCP CORS policy reflects arbitrary Origin header (no credentials)",
			Description: fmt.Sprintf(
				"The server at %s reflects the request Origin verbatim in Access-Control-Allow-Origin "+
					"without credentials. While cross-origin reads of unauthenticated responses are "+
					"possible, credentialed attacks are blocked because Allow-Credentials is not set.",
				ep),
			Evidence: fmt.Sprintf(
				"%s %s\nOrigin: %s\nAccess-Control-Allow-Origin: %s",
				method, ep, corsProbeOrigin, acao),
			Remediation: e.rule.Remediation,
			TargetURL:   ep,
		}

	case isWildcard && !acac:
		return &attack.Finding{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "low",
			Confidence: attack.ConfirmedExploit,
			Title:      "MCP CORS policy uses wildcard origin (no credentials)",
			Description: fmt.Sprintf(
				"The server at %s returns Access-Control-Allow-Origin: * without credentials. "+
					"Unauthenticated cross-origin reads of MCP responses are possible from any "+
					"browser-hosted page.", ep),
			Evidence: fmt.Sprintf(
				"%s %s\nAccess-Control-Allow-Origin: *",
				method, ep),
			Remediation: e.rule.Remediation,
			TargetURL:   ep,
		}
	}

	return nil
}
