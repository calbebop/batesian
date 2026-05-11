package mcp

import (
	"context"
	"fmt"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// mcpSecurityHeader describes one HTTP security header check for MCP endpoints.
type mcpSecurityHeader struct {
	name        string
	check       func(headers map[string]string) bool
	description string
	severity    string
}

// requiredMCPHeaders is the set of security headers checked on MCP endpoints.
var requiredMCPHeaders = []mcpSecurityHeader{
	{
		name: "Strict-Transport-Security",
		check: func(h map[string]string) bool {
			v := h["strict-transport-security"]
			return strings.Contains(v, "max-age") && !strings.Contains(v, "max-age=0")
		},
		description: "Strict-Transport-Security header absent or max-age=0",
		severity:    "low",
	},
	{
		name: "X-Content-Type-Options",
		check: func(h map[string]string) bool {
			return strings.EqualFold(strings.TrimSpace(h["x-content-type-options"]), "nosniff")
		},
		description: "X-Content-Type-Options: nosniff header absent",
		severity:    "low",
	},
	{
		name: "Frame protection",
		check: func(h map[string]string) bool {
			return h["x-frame-options"] != "" ||
				strings.Contains(strings.ToLower(h["content-security-policy"]), "frame-ancestors")
		},
		description: "Neither X-Frame-Options nor CSP frame-ancestors directive present",
		severity:    "low",
	},
	{
		name: "Referrer-Policy",
		check: func(h map[string]string) bool {
			return h["referrer-policy"] != ""
		},
		description: "Referrer-Policy header absent",
		severity:    "info",
	},
}

// MCPSecurityHeadersExecutor checks MCP endpoints for missing HTTP security
// headers (rule mcp-security-headers-001).
type MCPSecurityHeadersExecutor struct {
	rule attack.RuleContext
}

// NewMCPSecurityHeadersExecutor creates an executor for mcp-security-headers.
func NewMCPSecurityHeadersExecutor(r attack.RuleContext) *MCPSecurityHeadersExecutor {
	return &MCPSecurityHeadersExecutor{rule: r}
}

func (e *MCPSecurityHeadersExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)

	// Send a minimal MCP initialize POST to the most likely endpoint paths
	// to get a real server response with full security headers.
	probePaths := candidatePaths

	var findings []attack.Finding
	checked := false

	for _, path := range probePaths {
		ep := vars.BaseURL + path
		resp, err := client.POST(ctx, ep, nil, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "initialize",
			"params": map[string]interface{}{
				"protocolVersion": "2025-03-26",
				"capabilities":    map[string]interface{}{},
				"clientInfo":      map[string]interface{}{"name": "batesian", "version": "1.0"},
			},
		})
		if err != nil || resp.StatusCode == 0 || resp.StatusCode == 404 {
			continue
		}
		checked = true

		headers := resp.NormalizeHeaders()

		for _, hdr := range requiredMCPHeaders {
			if !hdr.check(headers) {
				findings = append(findings, attack.Finding{
					RuleID:     e.rule.ID,
					RuleName:   e.rule.Name,
					Severity:   hdr.severity,
					Confidence: attack.RiskIndicator,
					Title:      fmt.Sprintf("MCP endpoint missing %s header", hdr.name),
					Description: fmt.Sprintf(
						"%s on %s (HTTP %d). "+
							"Missing security headers weaken browser-facing attack surface defenses.",
						hdr.description, ep, resp.StatusCode),
					Evidence: fmt.Sprintf(
						"POST %s (initialize)\nHTTP %d\nreceived headers: %s",
						ep, resp.StatusCode, mcpFormatHeaders(headers)),
					Remediation: e.rule.Remediation,
					TargetURL:   ep,
				})
			}
		}
		break
	}

	if !checked {
		return nil, nil
	}
	return findings, nil
}

func mcpFormatHeaders(h map[string]string) string {
	relevant := []string{
		"strict-transport-security",
		"x-content-type-options",
		"x-frame-options",
		"content-security-policy",
		"referrer-policy",
		"permissions-policy",
	}
	var sb strings.Builder
	for _, k := range relevant {
		if v, ok := h[k]; ok {
			fmt.Fprintf(&sb, "\n  %s: %s", k, v)
		} else {
			fmt.Fprintf(&sb, "\n  %s: (absent)", k)
		}
	}
	return sb.String()
}
