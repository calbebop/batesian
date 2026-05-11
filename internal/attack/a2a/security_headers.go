package a2a

import (
	"context"
	"fmt"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// securityHeader describes one HTTP security header check.
type securityHeader struct {
	name        string
	check       func(headers map[string]string) bool
	description string
	severity    string
}

// requiredHeaders is the set of security headers checked on A2A endpoints.
var requiredA2AHeaders = []securityHeader{
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

// SecurityHeadersExecutor checks A2A endpoints for missing HTTP security headers
// (rule a2a-security-headers-001).
type SecurityHeadersExecutor struct {
	rule attack.RuleContext
}

// NewSecurityHeadersExecutor creates an executor for a2a-security-headers.
func NewSecurityHeadersExecutor(r attack.RuleContext) *SecurityHeadersExecutor {
	return &SecurityHeadersExecutor{rule: r}
}

func (e *SecurityHeadersExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)

	// Probe paths most likely to return security headers.
	probePaths := []string{
		"/.well-known/agent.json",
		"/.well-known/agent-card.json",
		"/",
	}

	var findings []attack.Finding
	checked := false

	for _, path := range probePaths {
		resp, err := client.GET(ctx, vars.BaseURL+path, nil)
		if err != nil || resp.StatusCode == 0 || resp.StatusCode == 404 {
			continue
		}
		checked = true

		headers := resp.NormalizeHeaders()
		endpoint := vars.BaseURL + path

		for _, hdr := range requiredA2AHeaders {
			if !hdr.check(headers) {
				findings = append(findings, attack.Finding{
					RuleID:     e.rule.ID,
					RuleName:   e.rule.Name,
					Severity:   hdr.severity,
					Confidence: attack.RiskIndicator,
					Title:      fmt.Sprintf("A2A endpoint missing %s header", hdr.name),
					Description: fmt.Sprintf(
						"%s on %s (HTTP %d). %s",
						hdr.description, endpoint, resp.StatusCode,
						"Missing security headers weaken browser-based attack surface defenses."),
					Evidence: fmt.Sprintf(
						"GET %s\nHTTP %d\nreceived headers: %s",
						endpoint, resp.StatusCode, formatHeaders(headers)),
					Remediation: e.rule.Remediation,
					TargetURL:   endpoint,
				})
			}
		}
		break // One successful probe is sufficient.
	}

	if !checked {
		return nil, nil
	}
	return findings, nil
}

// formatHeaders formats a header map as a human-readable string for evidence.
func formatHeaders(h map[string]string) string {
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
